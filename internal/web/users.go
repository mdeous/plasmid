package web

import (
	"net/http"
	"strings"

	"github.com/crewjam/saml/samlidp"
	"golang.org/x/crypto/bcrypt"
)

type userView struct {
	Name      string
	Password  string
	Email     string
	GivenName string
	Surname   string
	Groups    []string
}

func (h *WebHandler) loadUsers() []userView {
	names := h.listKeys("/users/")
	users := make([]userView, 0, len(names))
	for _, name := range names {
		var u samlidp.User
		if err := h.store.Get("/users/"+name, &u); err != nil {
			h.logger.Error("failed to load user", "name", name, "error", err)
			continue
		}
		var password string
		if u.PlaintextPassword != nil {
			password = *u.PlaintextPassword
		}
		users = append(users, userView{
			Name:      u.Name,
			Password:  password,
			Email:     u.Email,
			GivenName: u.GivenName,
			Surname:   u.Surname,
			Groups:    u.Groups,
		})
	}
	return users
}

func (h *WebHandler) handleUsers(w http.ResponseWriter, r *http.Request) {
	h.renderPage(w, "users", map[string]any{
		"Active": "users",
		"Users":  h.loadUsers(),
	})
}

func (h *WebHandler) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("failed to hash password", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var groups []string
	if g := strings.TrimSpace(r.FormValue("groups")); g != "" {
		for _, part := range strings.Split(g, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				groups = append(groups, trimmed)
			}
		}
	}

	user := samlidp.User{
		Name:              username,
		PlaintextPassword: &password,
		HashedPassword:    hashedPassword,
		Email:             strings.TrimSpace(r.FormValue("email")),
		GivenName:         strings.TrimSpace(r.FormValue("given_name")),
		Surname:           strings.TrimSpace(r.FormValue("surname")),
		Groups:            groups,
	}
	if err := h.store.Put("/users/"+username, &user); err != nil {
		h.logger.Error("failed to create user", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderPartial(w, "user_row", userView{
		Name:      user.Name,
		Password:  password,
		Email:     user.Email,
		GivenName: user.GivenName,
		Surname:   user.Surname,
		Groups:    user.Groups,
	})
}

func (h *WebHandler) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.store.Delete("/users/" + name); err != nil {
		h.logger.Error("failed to delete user", "name", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
