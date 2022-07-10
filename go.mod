module github.com/mdeous/plasmid

go 1.18

require (
	github.com/creasty/defaults v1.6.0
	github.com/crewjam/saml v0.4.8
	github.com/crewjam/saml/samlidp v0.0.0-20220625143334-5e0ffd290abf
	goji.io v2.0.2+incompatible
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
	gopkg.in/yaml.v3 v3.0.0
)

require (
	github.com/beevik/etree v1.1.0 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/russellhaering/goxmldsig v1.1.1 // indirect
	github.com/stretchr/testify v1.7.1 // indirect
	github.com/zenazn/goji v1.0.1 // indirect
)

replace github.com/crewjam/saml v0.0.0-00010101000000-000000000000 => github.com/crewjam/saml v0.4.8
