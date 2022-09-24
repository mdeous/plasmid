package client

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

type PlasmidClient struct {
	BaseUrl *url.URL
}

func (p *PlasmidClient) request(method string, apiPath string, body io.Reader, expectedStatus int) (int, []byte, error) {
	// build target URL
	u, _ := url.Parse(p.BaseUrl.String())
	u.Path = path.Join(u.Path, apiPath)
	if strings.HasSuffix(apiPath, "/") {
		u.Path += "/"
	}
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
	// check status code
	if expectedStatus > 0 && resp.StatusCode != expectedStatus {
		return 0, nil, fmt.Errorf("unexpected status code: %d\n%s", resp.StatusCode, data)
	}
	return resp.StatusCode, data, nil
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
