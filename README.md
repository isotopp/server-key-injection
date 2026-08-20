# ski

> [!WARNING]
> **Incomplete test server — do not deploy.** The current implementation is an
> unauthenticated tracer only. It uses an in-memory disposable CA, has no
> persistent state or identity store, and no production host trusts the
> certificates it issues.

`ski` will issue short-lived, signed SSH certificates and load them into a
user's existing `ssh-agent`. The currently implemented tracer proves the
end-to-end agent-forwarding path only.

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

## How to smoke test the implementation

Run these commands from the project root. First, start a dedicated, empty
agent in Terminal 1. Do not clear identities from an agent you normally use.

```console
eval "$(ssh-agent -s)"
ssh-add -l || true
```

In Terminal 2, start the local test issuer on the unprivileged tracer port:

```console
uv run ski serve --bind 127.0.0.1 --port 2222
```

It reports its bound address and remains in the foreground. Back in Terminal 1,
request a dummy identity with agent forwarding:

```console
ssh -A -tt -p 2222 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  test-user@127.0.0.1
```

The issuer reports `Key loaded: test-...` and closes the session. Verify the
local agent:

```console
ssh-add -l
```

The agent displays an `ED25519` key identity and an `ED25519-CERT` identity
with the same `test-...` comment. They are the private key and its matching
signed user certificate; together they are one usable credential. The agent
removes them after one hour. This certificate is not accepted by any production
host.

To test that forwarding is required, repeat the SSH command with
`-o ForwardAgent=no`. It must report `Agent forwarding is required.` and add no
identity. Stop the server with Ctrl-C, then terminate the dedicated agent:

```console
eval "$(ssh-agent -k)"
```

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
