# W154 - explicit TokenUser ownership for private Windows creation

The hosted portable preview35590348875 built CLI and GUI from
e2de082a2c6cf0c77b3e510862c789089b0e6ca7, then failed the corrupt code-map
repair acceptance. Its recorded failure was `private directory is not owned
by the current user` while installing `code_map.db.corrupt-repair-pending`.
The fixture had already verified its parent home's owner and protected DACL.
The subsequent failure came from the product's newly created file-handle check.

The private Windows creation code built a protected TokenUser DACL but left
the security descriptor owner unspecified. The product then required exactly
the TokenUser owner on readback. The correction assigns that same live SID
with SetSecurityDescriptorOwner before NtCreateFile, CreateFileW and
CreateDirectoryW. The SID and descriptor remain live until those synchronous
calls return. Failure to set the owner aborts before creating the object.

Existing exact-owner/DACL readback, no-follow/reparse checks, create-new
semantics, retained-parent identity, access/sharing masks and durable writes
remain in place. No permission or durability guard is disabled.

Required Windows test identities:

- `wal::win_native::tests::fresh_private_file_and_directory_bind_owner_to_token_user`
- `wal::win_native::tests::relative_private_child_delete_uses_the_pinned_parent_capability`
- `wal::win_native::tests::owner_policy_rejects_a_valid_foreign_sid`

The first test creates a file and directory through the actual private
creation APIs and verifies the resulting handle/path owner and protected DACL.
The existing retained-parent test covers the relative child creation/deletion
path; foreign-owner rejection remains a separate negative control.
All three are Windows-only requirements, not universal Linux/macOS identities.

The final-source Windows native suite and a fresh portable preview lifecycle
must prove the actual repair. The earlier successful compiler steps do not
prove this changed source or package. No local executable validation ran.

Hosted evidence: complete preview log SHA-256
BCA240CEFBE1132EC2233DFE400D6A26EFCD0AC368CB232E866E1F8171119BDE;
original uploaded artifact
`neoth-portable-acceptance-e2de082a2c6cf0c77b3e510862c789089b0e6ca7-1`.
