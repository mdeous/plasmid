package web

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/spf13/viper"
)

type configEntry struct {
	Key       string
	Value     string
	Sensitive bool
}

type configGroup struct {
	Title   string
	Entries []configEntry
}

var sensitiveConfigKeys = map[string]bool{
	"user.password": true,
}

var configGroupOrder = []struct {
	Title  string
	Prefix string
}{
	{"Server", "server"},
	{"User", "user"},
	{"Service Provider", "sp"},
	{"Certificate", "cert"},
}

var serverTopLevelKeys = map[string]bool{
	"host":     true,
	"port":     true,
	"base_url": true,
}

func (h *WebHandler) handleSettings(w http.ResponseWriter, r *http.Request) {
	settings := viper.AllSettings()
	var flat []configEntry
	for k, v := range settings {
		if sub, ok := v.(map[string]any); ok {
			for sk, sv := range sub {
				key := k + "." + sk
				flat = append(flat, configEntry{
					Key:       key,
					Value:     formatValue(sv),
					Sensitive: sensitiveConfigKeys[key],
				})
			}
		} else {
			flat = append(flat, configEntry{
				Key:       k,
				Value:     formatValue(v),
				Sensitive: sensitiveConfigKeys[k],
			})
		}
	}

	groups := groupConfig(flat)

	h.renderPage(w, "settings", map[string]any{
		"Active":       "settings",
		"BaseURL":      h.baseURL,
		"Host":         viper.GetString("host"),
		"Port":         viper.GetString("port"),
		"CertInfo":     h.certInfo(),
		"ConfigGroups": groups,
	})
}

func groupConfig(flat []configEntry) []configGroup {
	buckets := make(map[string][]configEntry)
	other := []configEntry{}

	for _, e := range flat {
		placed := false
		if serverTopLevelKeys[e.Key] {
			buckets["Server"] = append(buckets["Server"], e)
			placed = true
		} else {
			for _, g := range configGroupOrder {
				if strings.HasPrefix(e.Key, g.Prefix+".") {
					buckets[g.Title] = append(buckets[g.Title], e)
					placed = true
					break
				}
			}
		}
		if !placed {
			other = append(other, e)
		}
	}

	groups := make([]configGroup, 0, len(configGroupOrder)+1)
	for _, g := range configGroupOrder {
		entries := buckets[g.Title]
		if len(entries) == 0 {
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
		groups = append(groups, configGroup{Title: g.Title, Entries: entries})
	}
	if len(other) > 0 {
		sort.Slice(other, func(i, j int) bool { return other[i].Key < other[j].Key })
		groups = append(groups, configGroup{Title: "Other", Entries: other})
	}
	return groups
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
