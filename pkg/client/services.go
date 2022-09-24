package client

import (
	"fmt"
	idp "github.com/crewjam/saml/samlidp"
	"io"
	"net/http"
)

type serviceIds struct {
	Services []string `json:"services"`
}

type ServiceList struct {
	Services []*idp.Service
}

func (p *PlasmidClient) ServiceAdd(service string, metaUrl string) error {
	samlResp, err := http.Get(metaUrl)
	if err != nil {
		return err
	}
	if samlResp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(samlResp.Body)
		return fmt.Errorf("error while fetching service provider metadata: %d: %s", samlResp.StatusCode, data)
	}
	_, _, err = p.request(http.MethodPut, "/services/"+service, samlResp.Body, http.StatusNoContent)
	if err != nil {
		return err
	}
	return nil
}

func (p *PlasmidClient) ServiceList() ([]string, error) {
	ids := &serviceIds{}
	err := p.resourceIds("services", ids)
	if err != nil {
		return nil, err
	}
	return ids.Services, nil
}

func (p *PlasmidClient) ServiceDel(serviceName string) error {
	// get list of serviceNames
	ids := &serviceIds{}
	err := p.resourceIds("services", ids)
	if err != nil {
		return err
	}
	// check if service exists
	serviceExists := false
	for _, existingName := range ids.Services {
		if existingName == serviceName {
			serviceExists = true
			break
		}
	}
	if !serviceExists {
		return fmt.Errorf("service not found: %s", serviceName)
	}
	// delete service
	_, _, err = p.request(http.MethodDelete, "/services/"+serviceName, nil, http.StatusNoContent)
	if err != nil {
		return err
	}
	return nil
}
