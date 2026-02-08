package utils

import (
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGeneratePrivateKey(t *testing.T) {
	key, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("GeneratePrivateKey returned error: %v", err)
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("expected key size 2048, got %d", key.N.BitLen())
	}
}

func TestGenerateCertificate(t *testing.T) {
	key, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("GeneratePrivateKey returned error: %v", err)
	}

	cert, err := GenerateCertificate(key, "TestOrg", "US", "California", "San Francisco", "123 Main St", "94105", 5)
	if err != nil {
		t.Fatalf("GenerateCertificate returned error: %v", err)
	}

	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "TestOrg" {
		t.Errorf("expected organization 'TestOrg', got %v", cert.Subject.Organization)
	}
	if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != "US" {
		t.Errorf("expected country 'US', got %v", cert.Subject.Country)
	}
	if len(cert.Subject.Province) != 1 || cert.Subject.Province[0] != "California" {
		t.Errorf("expected province 'California', got %v", cert.Subject.Province)
	}
	if len(cert.Subject.Locality) != 1 || cert.Subject.Locality[0] != "San Francisco" {
		t.Errorf("expected locality 'San Francisco', got %v", cert.Subject.Locality)
	}
	if len(cert.Subject.StreetAddress) != 1 || cert.Subject.StreetAddress[0] != "123 Main St" {
		t.Errorf("expected street address '123 Main St', got %v", cert.Subject.StreetAddress)
	}
	if len(cert.Subject.PostalCode) != 1 || cert.Subject.PostalCode[0] != "94105" {
		t.Errorf("expected postal code '94105', got %v", cert.Subject.PostalCode)
	}

	if !cert.IsCA {
		t.Error("expected certificate to be CA")
	}

	if cert.SerialNumber.Cmp(big.NewInt(1000)) == 0 {
		t.Error("expected serial number to be random, got 1000")
	}

	expectedExpiry := time.Now().AddDate(5, 0, 0)
	diff := cert.NotAfter.Sub(expectedExpiry)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("expected expiry around %v, got %v", expectedExpiry, cert.NotAfter)
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected KeyUsageDigitalSignature to be set")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("expected KeyUsageCertSign to be set")
	}
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	key, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("GeneratePrivateKey returned error: %v", err)
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")

	if err := WriteKeyToPem(key, keyPath); err != nil {
		t.Fatalf("WriteKeyToPem returned error: %v", err)
	}

	loadedKey, err := LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey returned error: %v", err)
	}

	if key.N.Cmp(loadedKey.N) != 0 {
		t.Error("loaded key modulus does not match original")
	}
	if key.D.Cmp(loadedKey.D) != 0 {
		t.Error("loaded key private exponent does not match original")
	}
	if key.E != loadedKey.E {
		t.Error("loaded key public exponent does not match original")
	}
}

func TestCertificateRoundTrip(t *testing.T) {
	key, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("GeneratePrivateKey returned error: %v", err)
	}

	cert, err := GenerateCertificate(key, "RoundTripOrg", "DE", "Bavaria", "Munich", "456 Oak Ave", "80331", 3)
	if err != nil {
		t.Fatalf("GenerateCertificate returned error: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.crt")

	if err := WriteCertificateToPem(cert, certPath); err != nil {
		t.Fatalf("WriteCertificateToPem returned error: %v", err)
	}

	loadedCert, err := LoadCertificate(certPath)
	if err != nil {
		t.Fatalf("LoadCertificate returned error: %v", err)
	}

	if cert.SerialNumber.Cmp(loadedCert.SerialNumber) != 0 {
		t.Error("loaded certificate serial number does not match original")
	}
	if loadedCert.Subject.Organization[0] != "RoundTripOrg" {
		t.Errorf("expected organization 'RoundTripOrg', got %v", loadedCert.Subject.Organization)
	}
	if !loadedCert.IsCA {
		t.Error("expected loaded certificate to be CA")
	}
	if !cert.NotAfter.Equal(loadedCert.NotAfter) {
		t.Error("loaded certificate expiry does not match original")
	}
}

func TestLoadPrivateKey_NotFound(t *testing.T) {
	_, err := LoadPrivateKey("/nonexistent/path/key.pem")
	if err == nil {
		t.Fatal("expected error when loading non-existent private key file")
	}
}

func TestLoadCertificate_NotFound(t *testing.T) {
	_, err := LoadCertificate("/nonexistent/path/cert.pem")
	if err == nil {
		t.Fatal("expected error when loading non-existent certificate file")
	}
}

func TestFetchSPMetadata_File(t *testing.T) {
	xmlContent := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"/>
  </SPSSODescriptor>
</EntityDescriptor>`

	tmpDir := t.TempDir()
	metadataPath := filepath.Join(tmpDir, "metadata.xml")

	if err := os.WriteFile(metadataPath, []byte(xmlContent), 0644); err != nil {
		t.Fatalf("failed to write test metadata file: %v", err)
	}

	data, err := FetchSPMetadata(metadataPath)
	if err != nil {
		t.Fatalf("FetchSPMetadata returned error: %v", err)
	}

	if string(data) != xmlContent {
		t.Errorf("fetched metadata does not match written content.\nexpected: %s\ngot: %s", xmlContent, string(data))
	}
}

func TestFetchSPMetadata_URL(t *testing.T) {
	xmlContent := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"/>
  </SPSSODescriptor>
</EntityDescriptor>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(xmlContent))
	}))
	defer server.Close()

	data, err := FetchSPMetadata(server.URL)
	if err != nil {
		t.Fatalf("FetchSPMetadata returned error: %v", err)
	}

	if string(data) != xmlContent {
		t.Errorf("fetched metadata does not match served content.\nexpected: %s\ngot: %s", xmlContent, string(data))
	}
}
