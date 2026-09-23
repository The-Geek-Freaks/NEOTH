# GOLD-W258: Unix socket identity fixture

The Unix client already records the socket leaf's `(device, inode)` before
connecting and compares it with the post-connect path identity. The focused
case `unix_client_endpoint_identity_detects_a_replaced_socket_leaf` exercises
that identity-change observation.

The prior fixture bound a socket, dropped its listener, unlinked the leaf, and
bound a replacement. On filesystems that reuse an inode immediately, both
independent path observations can legitimately report the same `(device,
inode)`. That was a fixture lifecycle ambiguity, not evidence that the
production comparison accepted a changed identity.

The fixture now retains the original listener after unlinking its pathname and
retains the replacement listener through the assertion. Both socket objects are
live at the same time, so the replacement must have a distinct live inode. The
test therefore deterministically verifies detection of a persistent replaced
leaf. It does not claim a stronger defense against a same-EUID ABA replacement
that disappears between the client's two path observations.
