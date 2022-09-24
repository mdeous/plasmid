package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	idp "github.com/crewjam/saml/samlidp"
	"net/http"
)

type UserList struct {
	Users []*idp.User
}

func (p *PlasmidClient) UserAdd(user *idp.User) error {
	userData, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("unable to deserialize user: %v", err)
	}
	_, _, err = p.request(http.MethodPut, "/users/"+user.Name, bytes.NewReader(userData), http.StatusNoContent)
	if err != nil {
		return err
	}
	return nil
}

func (p *PlasmidClient) UserList() (*UserList, error) {
	// get list of user names
	_, resp, err := p.request(http.MethodGet, "/users/", nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	// serialize received JSON
	var users struct {
		Users []string `json:"users"`
	}
	err = json.Unmarshal(resp, &users)
	if err != nil {
		return nil, fmt.Errorf("unable to deserialize users list: %v", err)
	}
	// build users list
	ulist := &UserList{}
	for _, username := range users.Users {
		// get detailed user info
		_, resp, err = p.request(http.MethodGet, "/users/"+username, nil, http.StatusOK)
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
