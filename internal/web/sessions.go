package web

import (
	"net/http"
	"time"

	"github.com/crewjam/saml"
)

type sessionView struct {
	ID         string
	ShortID    string
	UserName   string
	NameID     string
	CreateTime string
	ExpireTime string
	Expired    bool
}

func (h *WebHandler) loadSessions() []sessionView {
	ids := h.listKeys("/sessions/")
	sessions := make([]sessionView, 0, len(ids))
	now := time.Now()
	for _, id := range ids {
		var s saml.Session
		if err := h.store.Get("/sessions/"+id, &s); err != nil {
			// Fall back to bare ID if we can't decode — session may have been
			// written by a different crewjam/saml version.
			sessions = append(sessions, sessionView{ID: id, ShortID: shortID(id)})
			continue
		}
		view := sessionView{
			ID:       id,
			ShortID:  shortID(id),
			UserName: s.UserName,
			NameID:   s.NameID,
		}
		if !s.CreateTime.IsZero() {
			view.CreateTime = s.CreateTime.Format("2006-01-02 15:04:05")
		}
		if !s.ExpireTime.IsZero() {
			view.ExpireTime = s.ExpireTime.Format("2006-01-02 15:04:05")
			view.Expired = s.ExpireTime.Before(now)
		}
		sessions = append(sessions, view)
	}
	return sessions
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}

func (h *WebHandler) handleSessions(w http.ResponseWriter, r *http.Request) {
	h.renderPage(w, "sessions", map[string]any{
		"Active":   "sessions",
		"Sessions": h.loadSessions(),
	})
}

func (h *WebHandler) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	sessions := h.loadSessions()
	if len(sessions) == 0 {
		w.Write([]byte(`<tr class="empty-state-row"><td colspan="6">No active sessions. They appear here after a successful SAML login.</td></tr>`))
		return
	}
	for _, s := range sessions {
		h.renderPartial(w, "session_row", s)
	}
}

func (h *WebHandler) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.Delete("/sessions/" + id); err != nil {
		h.logger.Error("failed to delete session", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
