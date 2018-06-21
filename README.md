# letsencrypt-proxy

## Overview

### Server

### Client

## Server

### Configuration

### API

#### authorize
__Authorize a new certificate endpoint:__  Uses the admin credentials to
create a token for adding a new client/endpoint.

#### register
__Register a new endpoint:__  Consumes an authorization token (generated
by _authorize_) to add a new endpoint for certificate management.

#### renew
__Renew an endpoint:__  Uses an existing (and valid) certificate for an
endpoint to get a new certificate for that endpoint.

#### revoke
__Revoke an endpoint:__  Uses the admin credentials to revoke an endpoints
authorization to obtain certificates

## Client

### Configuration
