package client

import (
	"encoding/json"
	"fmt"
	idp "github.com/crewjam/saml/samlidp"
	"net/http"
)

type userIds struct {
	Users []string `json:"users"`
}

type UserList struct {
	Users []*idp.User
}

func (p *PlasmidClient) UserGet(username string) (*idp.User, error) {
	_, body, err := p.request(http.MethodGet, "/users/"+username, nil, 200)
	if err != nil {
		return nil, fmt.Errorf("unable to get information about user '%s': %v", username, err)
	}
	var user idp.User
	err = json.Unmarshal(body, &user)
	if err != nil {
		return nil, fmt.Errorf("unable to deserialize user '%s': %v", username, err)
	}
	return &user, nil
}

func (p *PlasmidClient) UserAdd(user *idp.User) error {
	err := p.resourceAdd("users", user.Name, user)
	if err != nil {
		return err
	}
	return nil
}

func (p *PlasmidClient) UserList() ([]string, error) {
	// fetch existing usernames
	ids := &userIds{}
	err := p.resourceIds("users", ids)
	if err != nil {
		return nil, err
	}
	return ids.Users, nil
}

func (p *PlasmidClient) UserDel(username string) error {
	// get list of usernames
	ids := &userIds{}
	err := p.resourceIds("users", ids)
	if err != nil {
		return err
	}

	// check if user exists
	userExists := false
	for _, existingName := range ids.Users {
		if existingName == username {
			userExists = true
			break
		}
	}
	if !userExists {
		return fmt.Errorf("user not found: %s", username)
	}

	// delete user
	_, _, err = p.request(http.MethodDelete, "/users/"+username, nil, http.StatusNoContent)
	if err != nil {
		return err
	}
	return nil
}
