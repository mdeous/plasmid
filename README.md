# plasmid

[![Build](https://github.com/mdeous/plasmid/actions/workflows/build.yml/badge.svg)](https://github.com/mdeous/plasmid/actions/workflows/build.yml)

Basic SAML identity provider for testing service providers.

> **Warning**
>
> This application is strictly meant for testing, no authentication is (nor will be) implemented on the
> administration endpoints exposed by the API. It MUST NOT be used as a production SAML IdP.

---
* [Introduction](#introduction)
* [Installation](#installation)
  * [From Source](#from-source)
  * [Pre-built Binaries](#pre-built-binaries)
* [Configuration](#configuration)
* [Usage](#usage)
  * [Example](#example)
  * [Docker](#docker)
  * [Starting the Identity Provider](#starting-the-identity-provider)
  * [Interacting With a Running Instance](#interacting-with-a-running-instance)
  * [API Endpoints](#api-endpoints)
* [Known Limitations](#known-limitations)
* [License](#license)
---

## Introduction

Plasmid is a SAML identity provider (IdP) based on the implementation from [`crewjam/saml`](https://github.com/crewjam/saml), 
it is meant to be used as an easy way to test SAML service providers (SP) without requiring a complicated setup. 
It can be configured via a YAML file or using environment variables, and has default values for most settings, 
allowing to quickly get it working with minimal configuration.

## Installation

### From Source

Simply clone the project and run `go build` to build it:

```bash
git clone github.com/mdeous/plasmid
cd plasmid
go build .
./plasmid -h
```

### Pre-built Binaries

TODO

## Configuration

Plasmid takes its configuration either from a YAML file named `plasmid.yaml` and located in the current
directory, or from environment variables. Some values can also be set from the command-line. Environment
variables take precedence over the configuration file, and command line arguments take precedence over
environment variables.

All the configuration entry names can be translated from their path in the YAML file to the environment 
variable name by replacing `.` with `_`, converting it to upper case, and prepending `IDP_` to it. 
For example the environment variable for the YAML entry `user.username` is `IDP_USER_USERNAME`.

An example YAML file with all the configurable values is provided in 
[`plasmid.example.yaml`](https://github.com/mdeous/plasmid/blob/69bc87be8ab5da2af2adb2af94efa692b7fae3b2/plasmid.example.yml)
at the root of the project folder.

## Usage

### Example

If you don't care about all the reading and just want to copy paste stuff and get started, this section
is for you. This example demonstrates how to setup a test environment using [`ngrok`](https://ngrok.com/)
`plasmid`, and [`SAMLRaider`](https://github.com/portswigger/saml-raider).

* In a terminal, start a ngrok tunnel and copy the tunnel URL:

```bash 
ngrok http 8000
```

* In another terminal, generate the IdP certificate and private key, and start the server:

```bash
./plasmid gencert
./plasmid serve -u <ngrok-url>
```

* Using the generated `metadata.xml` file, register the identity provider on the service provider
  you want to test
* In [`SAMLRaider`](https://github.com/portswigger/saml-raider), import the certificate and private key
* You can begin testing the service provider and login using `admin:Password123`

### Docker

TODO

### Starting the Identity Provider

To start the IdP with the bare minimum settings, simply run `plasmid serve`. The application will 
generate a certificate and a private key, and will create a default `admin:Password123` user. By default,
the application is served on [`http://127.0.0.1:8000`](http://127.0.0.1:8000).

The certificates can also be generated separately using the `plasmid gencert` command. The generated certificate
and private key are saved in PEM format, and can then be imported into other testing tools like 
[`SAMLRaider`](https://github.com/portswigger/saml-raider).

It is sometimes needed to make the IdP accessible from the internet, this can be achieved using `ngrok` by setting
the `base_url` configuration variable to the `ngrok` tunnel URL.

### Interacting With a Running Instance

Multiple functions to interact in various ways with a running Plasmid instance are provided under the
`plasmid client` command. The available commands are:

```
Interact with a running Plasmid instance

Usage:
  plasmid client [command]

Aliases:
  client, c

Available Commands:
  login        Start an idp initiated login flow (opens a browser)
  login-add    Create a new idp initiated login link
  login-del    Delete an idp initiated login link
  login-list   List links for idp initiated login
  session-del  Delete an active user session
  session-get  Get details about an active user session
  session-list List active user sessions
  sp-add       Register a new service provider
  sp-del       Delete a service provider
  sp-list      List service providers
  user-add     Create a new user account
  user-del     Delete an user account
  user-list    List user accounts

Flags:
  -h, --help         help for client
      --url string   plasmid instance url (default "http://127.0.0.1:8000")

Use "plasmid client [command] --help" for more information about a command.
```

Refer to each commands help for more details on their usage.

### API Endpoints

The underlying IdP implementation exposes a number of API endpoints, this section merely exists 
as an inventory of those endpoints. Most of those can be easily queried using the 
[integrated client](#interacting-with-a-running-instance) via the `plasmid client` command.

For more information, please refer to the code for their handlers in [`crewjam/saml`](https://github.com/crewjam/saml), 
which are listed [here](https://github.com/crewjam/saml/blob/5e0ffd290abf0be7dfd4f8279e03a963071544eb/samlidp/samlidp.go#L83-L121).

#### SSO

| **Method**   | **Path**    | **Description**                    |
|--------------|-------------|------------------------------------|
| `GET`        | `/metadata` | get the identity provider metadata |
| `GET`/`POST` | `/sso`      | generate SAML assertions           |

#### Service providers

| **Method**   | **Path**         | **Description**                  |
|--------------|------------------|----------------------------------|
| `GET`        | `/services/`     | list service providers           |
| `GET`        | `/services/<id>` | get service provider metadata    |
| `PUT`/`POST` | `/services/<id>` | add or update a service provider |
| `DELETE`     | `/services/<id>` | delete a service provider        |

#### Users

| **Method** | **Path**            | **Description**                    |
|------------|---------------------|------------------------------------|
| `GET`      | `/users/`           | list user accounts                 |
| `GET`      | `/users/<username>` | get information on an user account |
| `PUT`      | `/users/<username>` | add or update an user account      |
| `DELETE`   | `/users/<username>` | delete an user account             |

#### Sessions

| **Method** | **Path**         | **Description**                      |
|------------|------------------|--------------------------------------|
| `GET`      | `/sessions/`     | list active sessions                 |
| `GET`      | `/sessions/<id>` | get information on an active session |
| `DELETE`   | `/sessions/<id>` | delete a session                     |

#### Identity provider initiated flow

| **Method**   | **Path**                           | **Description**            |
|--------------|------------------------------------|----------------------------|
| `GET`/`POST` | `/login`                           | login handler              |
| `GET`        | `/login/<link-name>`               | begin flow                 |
| `GET`        | `/login/<link-name>/<relay-state>` | begin flow with RelayState |

#### Identity provider initiated flow links management

| **Method** | **Path**                 | **Description**                                      |
|------------|--------------------------|------------------------------------------------------|
| `GET`      | `/shortcuts/`            | list login links                                     |
| `GET`      | `/shortcuts/<link-name>` | get information on a login link                      |
| `PUT`      | `/shortcuts/<link-name>` | create or update a login link for a service provider |
| `DELETE`   | `/shortcuts/<link-name>` | delete a login link                                  |

## Known Limitations

* Does not support signed SAML requests
* Does not support encrypted SAML requests
* IdP initiated flow currently only works with existing session, but login form is broken (hopefully fixed soon)
* the `client sssion-get` and `client session-del` commands sometimes fail (hopefully fixed soon)

## License

This project is licensed under the MIT license. See the LICENSE file for more information.
