package client

import (
	"encoding/json"
	"fmt"
	"github.com/crewjam/saml"
	"net/http"
)

type sessionIds struct {
	Sessions []string `json:"sessions"`
}

func (p *PlasmidClient) SessionGet(sessionId string) (*saml.Session, error) {
	_, body, err := p.request(http.MethodGet, "/sessions/"+sessionId, nil, 200)
	if err != nil {
		return nil, fmt.Errorf("unable to get information about session '%s': %v", sessionId, err)
	}
	var session saml.Session
	err = json.Unmarshal(body, &session)
	if err != nil {
		return nil, fmt.Errorf("unable to deserialize session '%s': %v", sessionId, err)
	}
	return &session, nil
}

func (p *PlasmidClient) SessionList() ([]string, error) {
	ids := &sessionIds{}
	err := p.resourceIds("sessions", ids)
	if err != nil {
		return nil, err
	}
	return ids.Sessions, nil
}

func (p *PlasmidClient) SessionDel(sessionId string) error {
	// get list of sessionNames
	ids := &sessionIds{}
	err := p.resourceIds("sessions", ids)
	if err != nil {
		return err
	}

	// check if session exists
	sessionExists := false
	for _, existingName := range ids.Sessions {
		if existingName == sessionId {
			sessionExists = true
			break
		}
	}
	if !sessionExists {
		return fmt.Errorf("session not found: %s", sessionId)
	}

	// delete session
	_, _, err = p.request(http.MethodDelete, "/sessions/"+sessionId, nil, http.StatusNoContent)
	if err != nil {
		return err
	}
	return nil
}
