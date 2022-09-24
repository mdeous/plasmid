# plasmid

Basic SAML identity provider.

> **Warning**
> This application is strictly meant for testing, no authentication is (nor will be) implemented on the
> administration endpoints exposed by the API. It MUST NOT be used as a production SAML IdP.

---
Table of contents:

* [Introduction](#introduction)
  * [Installation](#installation)
    * [From source](#from-source)
    * [Pre-built binaries](#pre-built-binaries)
  * [Configuration](#configuration)
  * [Usage](#usage)
    * [Running the IdP](#running-the-idp)
    * [Interacting with a running instance](#interacting-with-a-running-instance)
    * [Commands completion](#commands-completion)
  * [License](#license)
---

## Introduction

Plasmid is a basic SAML identity provider based on [`crewjam/saml`](https://github.com/crewjam/saml) 
SAML IdP implementation, it is meant to be used as an easy way to test SAML service providers without 
requiring a complicated setup. It can be configured via a YAML file, or using environment variables, 
and has default values for most settings, allowing to customize only what's needed.

## Installation

### From source

Simply clone the project and run `go build` to build it:

```bash
git clone github.com/mdeous/plasmid
cd plasmid
go build .
./plasmid -h
```

### Pre-built binaries

TODO

## Configuration

Plasmid takes its configuration either from a YAML file named `plasmid.yaml` and located in the current
directory, or from environment variables. Some values can also be set from the command-line. Environment
variables take precedence over the configuration file, and command line arguments take precedence over
environment variables.

All the configuration entry names can be translated from their path in the YAML file to the environment 
variable name by replacing `.` with `_`, converting it to upper case, and prepending `IDP_` to it. 
For example the environment variable for the YAML entry `user.username` is `IDP_USER_USERNAME`.

An example YAML file with all the available configurable values is provided in `plasmid.example.yaml`
at the root of the project.

## Usage

### Running the IdP

To start the IdP with the bare minimum settings, simply run `plasmid serve`. The application will 
generate a certificate and a private key, and will create a default `admin:Password123` user. By default,
the application is served on [`http://127.0.0.1:8000`](http://127.0.0.1:8000).

The certificates can also be generated separately using the `plasmid gencert` command. The generated certificate
and private key are saved in PEM format, and can then be imported into other testing tools like 
[`SAMLRaider`](https://github.com/portswigger/saml-raider).

It is sometimes needed to make the IdP accessible from the internet, this can be achieved using `ngrok` by setting
the `base_url` configuration variable to the `ngrok` tunnel URL.

### Interacting with a running instance

Multiple functions to interact in various ways with a running Plasmid instance are available under the
`plasmid client` command. It allows to:

* create/list/delete user accounts
* create/list/delete service providers
* create/list/delete login links for IdP initiated login
* start an IdP initiated login flow with a service provider

Refer to the commands help for more details.

### Commands completion

Plasmid command-line arguments parsing is baseed on [`cobra`](https://github.com/spf13/cobra), and therefore
provides completion for most shells through the `plasmid completion` command. Refer
to the appropriate sub-command help for instructions on setting up completion in your shell.

## License

This project is licensed under the MIT license. See the LICENSE file.