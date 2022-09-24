package client

import (
	"bytes"
	"fmt"
	idp "github.com/crewjam/saml/samlidp"
	"net/http"
)

type serviceIds struct {
	Services []string `json:"services"`
}

type ServiceList struct {
	Services []*idp.Service
}

func (p *PlasmidClient) ServiceAdd(service string, meta []byte) error {
	_, _, err := p.request(http.MethodPut, "/services/"+service, bytes.NewReader(meta), http.StatusNoContent)
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
