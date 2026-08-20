# ski

`ski` will provide a service for issuing short-lived, signed SSH certificates and
loading them into a user's existing `ssh-agent`. It is currently a project
foundation; the certificate-issuing protocol has not been implemented yet.

## Installation

Install [uv](https://docs.astral.sh/uv/) and Python 3.12 or later, then clone the
repository and install the project:

```console
uv sync
```

Run the command from the managed environment:

```console
uv run ski --help
```

## Configuration files

Before it starts, `ski` loads the first existing configuration file in this
order and stops searching:

1. `./.env`
2. `$HOME/.ski.env`
3. `/etc/ski/env`

Values already exported in the shell take precedence over values in that file.

## Intended operation

Once the server and client protocol are implemented, an operator will run a
certificate-authority-backed SSH service and users will request a short-lived
certificate for an existing public key. The client will add the resulting
certificate identity to the local `ssh-agent`; it will not upload a private key.

Do not commit private keys, CA keys, issued certificates, or agent sockets.

## Development

The standard local checks are:

```console
uv run ruff format
uv run ruff check --fix
uv run ty check
uv run pytest
```
