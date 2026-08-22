# ski-authorize

The host-side OpenSSH certificate principal helper is installed independently
from the issuer. It reads a protected local policy, parses the offered
Ed25519 user certificate, and returns one permitted group principal or denies
the request without contacting the issuer.

The repository's target-host deployment guide is
[`docs/TARGET-HOST.md`](../../docs/TARGET-HOST.md). The packaged samples under
`src/ski_authorize/examples/` are deliberately inert until an operator
installs a reviewed CA public key and fills in the allowed groups.
