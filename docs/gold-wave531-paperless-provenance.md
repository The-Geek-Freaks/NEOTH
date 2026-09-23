# W531 Paperless OCI acquisition and W534/W536 hosted follow-up

The manual main-only paperless-provenance workflow acquires candidate OCI
metadata for Paperless v3.2.1, Valkey9-alpine and Postgres18. It retrieves each
index and its exact linux/amd64 and linux/arm64 child manifest, verifies the
Docker-Content-Digest against response bytes and the child's size/digest/media
against the parent, and retains all nine raw manifests for independent review.
Fixed registry/repository/token endpoints, no redirects, twelve requests,
15-second socket timeouts, bounded bytes and a10-minute hosted job limit apply.
Tokens stay out of output and artifacts; config/layers are descriptors only.
No container, image or layer is pulled or launched, and artifact_verified
remains false. Tag selectors are acquisition inputs; they are not release pins.

Root rechecked the upstream signed v3.2.1 tag object
f800dfe8ab5349c5607044e6fdb5fda0edfb5d82 resolving to commit
7575d6078227ebdb4cf443f263d53ebc7575aa37 (GitHub verified=true/reason=valid).
The immutable compose bytes match SHA256
85206b8ae6cd74db70998de6479b4c1f7b50c077772a1af2c026c9ecb35b689c.
That compose still uses latest for Paperless and tags for its dependencies;
the workflow explicitly selects the Paperless release version. The release's
source-archive checksum is distinct from every OCI digest and is not runtime
artifact evidence. Acquisition and seven focused stdlib tests are hosted-only.

W534 imports artifact10779562985 from preflight35927363922 atd2f4bce7 after
checking both artifact hashes, source HEAD and both full before/after Gitblob
pairs. It contains formatting only for cli/chat.rs and gui_chat_runtime.rs.
W536 forwards W525's fixed-label/frame-count diagnostic through the existing
feature-gated bridge capture into the strict W480 GUI provider-count assertion.
This also makes the diagnostic method used in the GUI support compilation.
No assertion is weakened and no arbitrary error, prompt or secret is emitted.

Independent static review approved W531 and W536; the Root review repaired one
fake HTTP-header fixture key before publication. Core/GUI atd2f4 remain separate
pending runtime evidence. P1-18/P2-20/P2-26a remain open. Inventory759sources,
1198native+Win25Linux33mac32, Group903, GUI148Linux144macOS. Road1324 total,
1044checked/278open/2partial,280raw/279pre-tag; WS-LF37done/81open.
No local compiler, formatter, code parser, test, browser, GUI or runtime ran.

W537/W538 follow-up: Hosted35928271580 passed all seven acquisition contract
tests, then failed during its first registry acquisition with a redacted HTTPS
failure. The immutable upstream ci-docker.yml uses semver {{version}} tags, so
the Paperless OCI selector is corrected to3.2.1; the source release remains
v3.2.1. HTTP errors now expose only numeric status and bounded request ordinal,
with an eighth test proving URL/reason content stays out. No registry receipts
have yet been accepted. Core35927364092 passed slim production Clippy, then
found one remaining stale Credentials path in the CLI's test fixture; its type
now uses config::credentials::Credentials. GUI formatting artifact10779923485
from35928270572 was imported with source/hash/before-after Gitblob checks.
These narrow repairs await fresh hosted execution; all counts remain unchanged.
