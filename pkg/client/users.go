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

func (p *PlasmidClient) UserAdd(user *idp.User) error {
	err := p.resourceAdd("users", user.Name, user)
	if err != nil {
		return err
	}
	return nil
}

func (p *PlasmidClient) UserList() (*UserList, error) {
	ids := &userIds{}
	err := p.resourceIds("users", ids)
	if err != nil {
		return nil, err
	}
	// build users list
	ulist := &UserList{}
	for _, username := range ids.Users {
		// get detailed user info
		_, resp, err := p.request(http.MethodGet, "/users/"+username, nil, http.StatusOK)
		if err != nil {
			return nil, fmt.Errorf("failed to get details for user %s: %v", username, err)
		}
		// add user info to results
		var user idp.User
		err = json.Unmarshal(resp, &user)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize user %s info: %v", username, err)
		}
		ulist.Users = append(ulist.Users, &user)
	}
	return ulist, nil
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
