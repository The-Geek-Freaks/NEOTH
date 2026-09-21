# W143 — observed retained-registry test scope repair

Full CI 35583943094 on 8f130708 reported E0425 in channel-adapters job
106282931940. The local-shadow registry assertion used registry_a outside
the cloud-request block that defined it.

The cloud-request block now returns that same owned, parsed registry string.
Its request mutex guard is dropped before the local-shadow request lock is
acquired. All cloud and local assertions remain unchanged; no production path
changes. Root reviewed the exact source hunk against the complete hosted log.

Admission uses an exact published-source copy so W138 working changes remain
separate. Source SHA-256:
`ABFBA03E90A52E230ED6464B50B2D6C0D02910CEBA255EFB77F32702AB412DD9`.

Preflight 35583921353 and Code Quality 35583920718 passed on preceding
8f130708. They do not establish test compilation. Fresh hosted compilation
and behavioral execution are required. No local toolchain, parser, tests,
fixtures, product or GUI ran. Road counts and checkboxes remain unchanged.
