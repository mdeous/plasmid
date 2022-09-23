package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	idp "github.com/crewjam/saml/samlidp"
	"io"
	"net/http"
	"net/url"
	"path"
)

type PlasmidClient struct {
	BaseUrl *url.URL
}

func (p *PlasmidClient) request(method string, apiPath string, body io.Reader) (int, []byte, error) {
	// build target URL
	u := p.BaseUrl
	u.Path = path.Join(u.Path, apiPath)
	// build request
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return 0, nil, fmt.Errorf("unable to build %s request to %s: %v", method, apiPath, err)
	}
	// send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("error while sending %s request to %s: %v", method, apiPath, err)
	}
	// read response
	defer func() {
		_ = resp.Body.Close()
	}()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("error while reading response from %s: %v", apiPath, err)
	}
	return resp.StatusCode, data, nil
}

func (p *PlasmidClient) UserAdd(user *idp.User) error {
	userData, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("unable to deserialize user: %v", err)
	}
	status, resp, err := p.request(http.MethodPut, "/users/"+user.Name, bytes.NewReader(userData))
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d\n%s", status, resp)
	}
	return nil
}

func New(baseUrl string) (*PlasmidClient, error) {
	u, err := url.Parse(baseUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid url '%s': %v", baseUrl, err.Error())
	}
	p := &PlasmidClient{
		BaseUrl: u,
	}
	return p, nil
}
