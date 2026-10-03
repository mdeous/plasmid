package client

import (
	"bytes"
	"fmt"
	"net/http"
	"slices"

	"github.com/mdeous/plasmid/pkg/utils"
)

type serviceIds struct {
	Services []string `json:"services"`
}

// ServiceAdd registers every service provider the metadata describes and
// returns the names it created. Fetching and parsing go through pkg/utils so
// this agrees with the dashboard and with `serve --sp-metadata` about what a
// document contains and what the services end up called.
func (p *PlasmidClient) ServiceAdd(service string, metaUrl string) ([]string, error) {
	data, err := utils.FetchSPMetadata(metaUrl)
	if err != nil {
		return nil, err
	}
	services, err := utils.ParseSPServices(service, data)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(services))
	for _, svc := range services {
		_, _, err = p.request(http.MethodPut, "/services/"+svc.Name, bytes.NewReader(svc.XML), http.StatusNoContent)
		if err != nil {
			return names, err
		}
		names = append(names, svc.Name)
	}
	return names, nil
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
	if !slices.Contains(ids.Services, serviceName) {
		return fmt.Errorf("service not found: %s", serviceName)
	}

	// delete service
	_, _, err = p.request(http.MethodDelete, "/services/"+serviceName, nil, http.StatusNoContent)
	if err != nil {
		return err
	}
	return nil
}
