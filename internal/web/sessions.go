package web

import "net/http"

type sessionView struct {
	ID string
}

func (h *WebHandler) loadSessions() []sessionView {
	ids := h.listKeys("/sessions/")
	sessions := make([]sessionView, 0, len(ids))
	for _, id := range ids {
		sessions = append(sessions, sessionView{ID: id})
	}
	return sessions
}

func (h *WebHandler) handleSessions(w http.ResponseWriter, r *http.Request) {
	h.renderPage(w, "sessions", map[string]any{
		"Active":   "sessions",
		"Sessions": h.loadSessions(),
	})
}

func (h *WebHandler) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	sessions := h.loadSessions()
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
