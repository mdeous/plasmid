package web

import (
	"fmt"
	"net/http"

	"github.com/spf13/viper"
)

type configEntry struct {
	Key   string
	Value string
}

func (h *WebHandler) handleSettings(w http.ResponseWriter, r *http.Request) {
	settings := viper.AllSettings()
	var configEntries []configEntry
	for k, v := range settings {
		if sub, ok := v.(map[string]any); ok {
			for sk, sv := range sub {
				configEntries = append(configEntries, configEntry{
					Key:   k + "." + sk,
					Value: formatValue(sv),
				})
			}
		} else {
			configEntries = append(configEntries, configEntry{
				Key:   k,
				Value: formatValue(v),
			})
		}
	}

	h.renderPage(w, "settings", map[string]any{
		"Active":   "settings",
		"BaseURL":  h.baseURL,
		"Host":     viper.GetString("host"),
		"Port":     viper.GetString("port"),
		"CertInfo": h.certInfo(),
		"Config":   configEntries,
	})
}

func formatValue(v any) string {
	switch val := v.(type) {
	case []any:
		result := ""
		for i, item := range val {
			if i > 0 {
				result += ", "
			}
			result += formatValue(item)
		}
		return result
	default:
		return fmt.Sprintf("%v", val)
	}
}
