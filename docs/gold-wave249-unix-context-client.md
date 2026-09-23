# Gold Wave 249: Unix/macOS Context Import client

`neoth context import status`, `plan`, `apply`, `pause`, and `resume` now use
the existing Connector-Control routes on supported Unix hosts, including
macOS. The command discovers the same daemon authority used on Windows and
does not introduce another transport or route family.

The client reads only Connector-Control-owned discovery material: its bounded,
no-follow sidecar, Unix-domain socket endpoint, and token file. Both discovery
files are classified and read through the same nonblocking, no-follow,
capability-relative file descriptor; they must be effective-user regular files
with mode `0600`. Audit-RPC
contributes one narrow proof: its sidecar nonce is accepted only after the
existing `neothd.pid` lock confirms the daemon PID owns that exact nonce. That
nonce derives the expected Connector-Control endpoint nonce; it is never used
as an Audit-RPC bearer or endpoint.

Before connecting, the client recomputes the sidecar endpoint from canonical
home, the derived endpoint nonce, and the persisted runtime nonce. It requires
the private runtime directories and socket to be owned by the effective user,
not symlinks, and private (owner-only directories with no group/other permissions and a `0600` socket). It records
their stable Unix identities, connects only to that exact socket, checks the
kernel peer UID (`SO_PEERCRED` on Linux/Android and `getpeereid` on macOS/BSD),
then validates the path identities again. Platforms without a kernel peer UID
API fail closed.

Requests retain the existing five-second connection deadline and size bounds.
Responses have a bounded envelope and require one well-formed HTTP response
with a single bounded `Content-Length`; duplicate lengths, transfer encoding,
truncation, trailing bytes, malformed headers, and non-200 replies fail.

There is no TCP fallback, configuration fallback, Audit-RPC endpoint reuse, or
cross-authority bearer reuse. This wave adds no erase, GUI, or Buddy scope and
does not close CC-04. Linux and macOS hosted execution remains pending while
the local BSOD hold prohibits compiler, test, fixture, and runtime work.

The Unix-only focused cases are named
`unix_client_discovery_rejects_wrong_cc_nonce_pid_lock_nonce_and_runtime_nonce_before_connect`,
`unix_client_discovery_rejects_group_readable_and_symlinked_tokens_before_connect`,
`unix_private_discovery_reader_rejects_mode_symlink_and_oversize_on_the_opened_fd`,
`unix_client_endpoint_identity_detects_a_replaced_socket_leaf`, and
`unix_client_fixture_home_is_canonical_under_the_inherited_temp_environment`.
The first two intentionally bind no listener, so they prove discovery refusal
before an accepted response. The identity case proves the before/after inode
comparison used by the client; it does not claim a scheduler-controlled socket
replacement during a live connect. The pre/post path snapshots detect persistent
replacement, but do not claim to close a same-UID ABA swap that disappears
between observations. The reader case covers no-follow opening, private mode,
and the size cap on the descriptor actually read. The test suite uses the
shared environment lock and canonical temp-home helper, including macOS `/var`
to `/private/var` normalization. No test claims a real different-UID peer or
hosted macOS execution until those environments are run.
