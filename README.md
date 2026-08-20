# ski

`ski` provides a test issuer for short-lived, signed SSH certificates and loads
them into a user's existing `ssh-agent`. The first implementation is deliberately
harmless: it uses an in-memory disposable CA which no production host trusts.

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

## Dummy tracer operation

Start a local test issuer on the unprivileged tracer port:

```console
uv run ski serve --bind 127.0.0.1 --port 2222
```

In another terminal, make sure a local `ssh-agent` is running, then request the
dummy identity with agent forwarding:

```console
ssh -A -p 2222 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  test-user@127.0.0.1
```

The issuer reports a `test-` key identifier and closes the session. Check the
local agent with `ssh-add -l`; the identity is constrained to one hour and is
removed automatically by the agent. This certificate is not accepted by any
production host.

## Intended operation

The production service will use a protected CA and authenticated users to issue
short-lived certificates. The issuer will generate the temporary identity in
memory and add it through the user's explicitly forwarded agent connection; it
will not write the private key to a file or return it in the session transcript.

Do not commit private keys, CA keys, issued certificates, or agent sockets.

## Development

The standard local checks are:

```console
uv run ruff format
uv run ruff check --fix
uv run ty check
uv run pytest
```
