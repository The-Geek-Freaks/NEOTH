# W144 — portable preview fixture ownership

Windows preview 35575775478 built the native CLI, compatibility binaries,
migration/relay tools and GUI at source 85658d48. Portable lifecycle acceptance
then failed while installing the corrupt-repair manifest because the private
home directory was not owned by the current Windows TokenUser.

The fixture had created NEOTH_HOME with an ordinary inherited directory ACL.
It now establishes current-TokenUser ownership and a protected inheritable
FullControl DACL before writing test data, and reads back owner/protection.
The production private-write ownership checks remain unchanged and are still
exercised by the actual explicit corrupt-repair command.

The patch is confined to packaging/tests/Test-PortablePreview.ps1. Root reviewed
its source against the complete observed log and the existing Windows private
write contract. No local parser, fixture, test, compiler or product ran.
Hosted parser and portable lifecycle acceptance must confirm the correction.
Successful earlier CLI/GUI compilation is historical evidence for that source;
it is not current-head acceptance, release readiness or a Road checkbox closure.
