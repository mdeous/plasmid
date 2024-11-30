# plasmid

[![Build](https://github.com/mdeous/plasmid/actions/workflows/build.yml/badge.svg)](https://github.com/mdeous/plasmid/actions/workflows/build.yml)
[![Docker Image](https://github.com/mdeous/plasmid/actions/workflows/docker.yml/badge.svg)](https://github.com/mdeous/plasmid/actions/workflows/docker.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/mdeous/plasmid)](https://goreportcard.com/report/github.com/mdeous/plasmid)
[![Latest Release](https://img.shields.io/github/v/release/mdeous/plasmid)](https://github.com/mdeous/plasmid/releases/latest)
[![License](https://img.shields.io/github/license/mdeous/plasmid)](https://github.com/mdeous/plasmid/blob/main/LICENSE)


Basic SAML identity provider for testing service providers.

> **Warning**
>
> This application is strictly meant for testing SAML service providers, no authentication is (nor will be) implemented 
> on the administration API endpoints it exposes. It MUST NOT be used as a production SAML IdP.

---
* [Introduction](#introduction)
* [Installation](#installation)
  * [From Source](#from-source)
  * [Pre-built Binaries](#pre-built-binaries)
* [Configuration](#configuration)
* [Usage](#usage)
  * [Example (SP-initiated)](#sp-initiated-flow)
  * [Example (IdP-initiated)](#idp-initiated-flow)
  * [Docker](#docker)
  * [Interacting With a Running Instance](#interacting-with-a-running-instance)
  * [API Endpoints](#api-endpoints)
* [Known Limitations](#known-limitations)
* [License](#license)
---

## Introduction

Plasmid is a SAML identity provider (IdP) based on the implementation from [`crewjam/saml`](https://github.com/crewjam/saml), 
it is meant to run with minimal configuration and provide an easy way to test SAML service provider (SP) implementations.

## Installation

### From Source

Simply clone the project and use the provided `Makefile` to build it:

```bash
git clone github.com/mdeous/plasmid
cd plasmid
make
./plasmid -h
```

### Pre-built Binaries

Download the latest release for your plaform from the [releases](https://github.com/mdeous/plasmid/releases/latest)
page. You can also live on the edge by using the [nightly](https://github.com/mdeous/plasmid/releases/tag/nightly)
release, which always contains the latest changes from the `main` branch.

## Configuration

Plasmid can be started without any configuration, it will then automatically generate a certificate and 
private key and create a user in the idp (credentials: `admin:Password123`).

The default configuration can be overridden either with a YAML file named `plasmid.yaml` and located in 
the current directory, or from environment variables. Some values can also be set from the command-line. 
Environment variables take precedence over the configuration file, and command line arguments take precedence 
over environment variables.

All the configuration entry names can be translated from their path in the YAML file to the environment 
variable name by replacing `.` with `_`, converting it to upper case, and prepending `IDP_` to it. 
For example the environment variable for the YAML entry `user.username` is `IDP_USER_USERNAME`.

An example YAML file with all the configurable options and their default values is provided in 
[`plasmid.example.yaml`](https://github.com/mdeous/plasmid/blob/69bc87be8ab5da2af2adb2af94efa692b7fae3b2/plasmid.example.yml)
at the root of the project folder.

## Usage

### SP-initiated Flow

This example demonstrates how to setup a test environment using [`ngrok`](https://ngrok.com/)
`plasmid` and [`SAMLRaider`](https://github.com/portswigger/saml-raider).

* In a terminal, start a ngrok tunnel and copy the tunnel URL:

```bash 
ngrok http 8000
```

* In another terminal, generate the IdP certificate and private key, and start the server:

```bash
./plasmid serve -u <ngrok-url>
```

* Using the generated `idp-metadata.xml` file (or the `<base-url>/metadata` URL), register the plasmid 
  instance on the service provider you want to test
* In [`SAMLRaider`](https://github.com/portswigger/saml-raider), import the certificate and private key
* You can begin testing the service provider and login using `admin:Password123`

### IdP-initiated Flow

* Follow the steps described in the [SP-initiated example](#sp-initiated-flow) above, including logging 
  into the service provider using the SP-initiated flow in order to create a session in plasmid (this is
  needed as a workaround to a bug with sp-initiated flows in the underlying SAML library)
* Create a new link in plasmid for the service provider using the `client` command:

```bash
./plasmid client login-add -n "<link-name>" -e "<sp-entity-id>"
```

* Start the IdP-initiated flow:

```bash
./plasmid client login "<login-name>"
```

* A new browser window should open and the login flow should start

### Docker

To run plasmid with Docker, simply start the image and pass any needed arguments to it.
Optionally, you can mount a configuration file to the container's `/plasmid/plasmid.yaml`
path, or use environment variables.

```bash
docker run ghcr.io/mdeous/plasmid:latest serve
```

### Interacting With a Running Instance

The `plasmid client` command provides a number of subcommands that can be used to interact with
a plasmid instance:

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

Each subcommand can also be called using shorthand commands (e.g. `sg` instead of `session-get`), 
please refer to the help of each of those to know more about their usage and the available shorthands.

#### Common Operations

* Adding a new user to the IdP:

```bash
./plasmid client user-add -u "<username>" -e "<email>" -p "<password>"
```

* Deleting an active user session:

```bash
# list active sessions ids
./plasmid client session-list
# delete the session
./plasmid client session-del "<session-id>"
```

* Adding a new SP to the IdP:

```bash
./plasmid client sp-add -m "<metadata_url_or_file>" -s "<service-name>"
```

* Creating a new IdP-initiated login link:

```bash
./plasmid client login-add -n "<link-name>" -e "<sp-entity-id>"
```

### API Endpoints

The underlying IdP implementation exposes a number of API endpoints, this section merely exists 
as an inventory of those endpoints. Most of those can be easily queried using the 
[integrated client](#interacting-with-a-running-instance) via the `plasmid client` command.

For more information, please refer to the code of their handlers in [`crewjam/saml`](https://github.com/crewjam/saml), 
which are listed [here](https://github.com/crewjam/saml/blob/main/samlidp/samlidp.go#L86-L125).

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
* IdP initiated flow currently does not properly redirect to the SP after login

## License

This project is licensed under the MIT license. See the LICENSE file for more information.
