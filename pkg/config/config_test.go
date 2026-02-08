package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func resetViper() {
	viper.Reset()
}

func TestInit_DefaultValues(t *testing.T) {
	resetViper()
	Init()

	for key, expected := range DefaultValues {
		got := viper.Get(key)
		if got == nil {
			t.Errorf("expected default for %q, got nil", key)
			continue
		}
		switch v := expected.(type) {
		case int:
			if gotInt := viper.GetInt(key); gotInt != v {
				t.Errorf("key %q: expected %d, got %d", key, v, gotInt)
			}
		case string:
			if gotStr := viper.GetString(key); gotStr != v {
				t.Errorf("key %q: expected %q, got %q", key, v, gotStr)
			}
		case []string:
			gotSlice := viper.GetStringSlice(key)
			if len(gotSlice) != len(v) {
				t.Errorf("key %q: expected slice len %d, got %d", key, len(v), len(gotSlice))
				continue
			}
			for i := range v {
				if gotSlice[i] != v[i] {
					t.Errorf("key %q[%d]: expected %q, got %q", key, i, v[i], gotSlice[i])
				}
			}
		}
	}
}

func TestLoadFile_ValidYAML(t *testing.T) {
	resetViper()
	Init()

	content := []byte("host: 10.0.0.1\nport: 9090\nbase_url: http://10.0.0.1:9090\n")
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	err := LoadFile(tmpFile)
	if err != nil {
		t.Fatalf("LoadFile returned unexpected error: %v", err)
	}

	if got := viper.GetString(Host); got != "10.0.0.1" {
		t.Errorf("expected host %q, got %q", "10.0.0.1", got)
	}
	if got := viper.GetInt(Port); got != 9090 {
		t.Errorf("expected port %d, got %d", 9090, got)
	}
	if got := viper.GetString(BaseUrl); got != "http://10.0.0.1:9090" {
		t.Errorf("expected base_url %q, got %q", "http://10.0.0.1:9090", got)
	}

	// non-overridden values should still have defaults
	if got := viper.GetString(CertCaOrg); got != "Example Org" {
		t.Errorf("expected cert.ca_org default %q, got %q", "Example Org", got)
	}
}

func TestLoadFile_NotFound(t *testing.T) {
	resetViper()
	Init()

	err := LoadFile("/nonexistent/path/missing.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestEnvOverride(t *testing.T) {
	resetViper()
	t.Setenv("IDP_HOST", "192.168.1.100")
	Init()

	got := viper.GetString(Host)
	if got != "192.168.1.100" {
		t.Errorf("expected host from env %q, got %q", "192.168.1.100", got)
	}
}
