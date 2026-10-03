package server

import (
	"encoding/xml"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	"github.com/mdeous/plasmid/pkg/utils"
)

// parseMetadata round-trips the exported document, which is how an SP reads it.
func parseMetadata(t *testing.T, p *Plasmid) ([]byte, *saml.EntityDescriptor) {
	t.Helper()
	raw, err := p.Metadata()
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(raw, &ed); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	return raw, &ed
}

// Left to crewjam/saml, validUntil lands 48h out regardless of how long the
// signing certificate lives, so an instance pinned to a year-long certificate
// still publishes metadata an SP considers expired two days in.
func TestMetadataValidUntilTracksCertificate(t *testing.T) {
	env := newTestEnv(t)

	_, ed := parseMetadata(t, env.plasmid)

	want := env.plasmid.cert.NotAfter
	if diff := ed.ValidUntil.Sub(want); diff > time.Second || diff < -time.Second {
		t.Errorf("validUntil = %v, want the certificate NotAfter %v (diff %v)", ed.ValidUntil, want, diff)
	}

	// The whole point is that this follows the certificate rather than the
	// library's 48h, so it has to be well clear of 48h.
	if remaining := time.Until(ed.ValidUntil); remaining < 20*24*time.Hour {
		t.Errorf("validUntil %v is only %v out, expected to track the 30-day test certificate", ed.ValidUntil, remaining)
	}
}

// cacheDuration answers a different question from validUntil and is left at the
// library's 48h on purpose, so an SP still re-fetches after a certificate swap.
func TestMetadataCacheDurationUnchanged(t *testing.T) {
	env := newTestEnv(t)

	raw, _ := parseMetadata(t, env.plasmid)

	if !strings.Contains(string(raw), `cacheDuration="PT48H"`) {
		t.Errorf("expected cacheDuration=\"PT48H\" to be left alone, got:\n%s", firstLine(string(raw)))
	}
}

func TestMetadataValidDaysOverride(t *testing.T) {
	// Shorter than the fixture certificate, so the override is distinguishable
	// from the certificate-tracking default.
	const overrideDays = 7
	env := newTestEnv(t, func(o *Options) { o.MetadataValidDays = overrideDays })

	_, ed := parseMetadata(t, env.plasmid)

	// Computed in UTC like the production path: AddDate on a local time can
	// cross a DST boundary and land an hour off exactly n*24h.
	want := saml.TimeNow().AddDate(0, 0, overrideDays)
	if diff := ed.ValidUntil.Sub(want); diff > time.Minute || diff < -time.Minute {
		t.Errorf("validUntil = %v, want ~%v (diff %v)", ed.ValidUntil, want, diff)
	}
	// The override has to win over the certificate, which outlives it.
	if !ed.ValidUntil.Before(env.plasmid.cert.NotAfter) {
		t.Errorf("validUntil %v did not override the certificate NotAfter %v", ed.ValidUntil, env.plasmid.cert.NotAfter)
	}
}

// saml.RelaxedTime formats unconditionally, so a validUntil left at the zero
// time is emitted as 0001-01-01 rather than omitted.
func TestMetadataValidUntilNeverZero(t *testing.T) {
	for name, tweak := range map[string]func(*Options){
		"default":  func(*Options) {},
		"override": func(o *Options) { o.MetadataValidDays = 7 },
	} {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t, tweak)
			raw, ed := parseMetadata(t, env.plasmid)
			if ed.ValidUntil.IsZero() {
				t.Error("validUntil is the zero time")
			}
			if strings.Contains(string(raw), "0001-01-01") {
				t.Errorf("metadata carries a zero timestamp:\n%s", firstLine(string(raw)))
			}
		})
	}
}

// The operator-facing endpoint has to agree with the exported file.
func TestMetadataEndpointCarriesCertificateValidity(t *testing.T) {
	env := newTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/metadata", nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metadata = %d, want 200", rec.Code)
	}
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(rec.Body.Bytes(), &ed); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if diff := ed.ValidUntil.Sub(env.plasmid.cert.NotAfter); diff > time.Second || diff < -time.Second {
		t.Errorf("endpoint validUntil = %v, want the certificate NotAfter %v", ed.ValidUntil, env.plasmid.cert.NotAfter)
	}
}

// A certificate that does not match the key makes every assertion fail
// verification at the SP with nothing naming the cause, so New refuses it.
// Built directly rather than through newTestEnv, which fatals on a New error.
func TestNewRejectsMismatchedKeyPair(t *testing.T) {
	key, err := utils.GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert, err := utils.GenerateCertificate(key, "Test IDP", "US", "CA", "LA", "", "", 30)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	otherKey, err := utils.GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}

	baseUrl, _ := url.Parse("https://idp.example.com")
	opts := Options{
		BaseUrl:     baseUrl,
		Key:         otherKey,
		Certificate: cert,
		Store:       &samlidp.MemoryStore{},
		Logger:      slog.Default(),
	}

	if _, err := New(opts); err == nil {
		t.Fatal("expected New to reject a certificate that does not match the key")
	} else if !strings.Contains(err.Error(), "public half") {
		t.Errorf("error %q does not explain the key/certificate mismatch", err)
	}

	// The matched pair must still be accepted, so the guard is not just
	// refusing everything.
	opts.Key = key
	if _, err := New(opts); err != nil {
		t.Errorf("New rejected a matched pair: %v", err)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
