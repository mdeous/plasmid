package client

import (
	"fmt"
	idp "github.com/crewjam/saml/samlidp"
	"net/http"
)

type shortcutIds struct {
	Shortcuts []string `json:"shortcuts"`
}

func (p *PlasmidClient) ShortcutAdd(shortcut *idp.Shortcut) error {
	err := p.resourceAdd("shortcuts", shortcut.Name, shortcut)
	if err != nil {
		return err
	}
	return nil
}

func (p *PlasmidClient) ShortcutList() ([]string, error) {
	ids := &shortcutIds{}
	err := p.resourceIds("shortcuts", ids)
	if err != nil {
		return nil, err
	}
	return ids.Shortcuts, nil
}

func (p *PlasmidClient) ShortcutDel(shortcutName string) error {
	// get list of shortcutNames
	ids := &shortcutIds{}
	err := p.resourceIds("shortcuts", ids)
	if err != nil {
		return err
	}

	// check if shortcut exists
	shortcutExists := false
	for _, existingName := range ids.Shortcuts {
		if existingName == shortcutName {
			shortcutExists = true
			break
		}
	}
	if !shortcutExists {
		return fmt.Errorf("shortcut not found: %s", shortcutName)
	}

	// delete shortcut
	_, _, err = p.request(http.MethodDelete, "/shortcuts/"+shortcutName, nil, http.StatusNoContent)
	if err != nil {
		return err
	}
	return nil
}
