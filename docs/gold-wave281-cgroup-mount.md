# W281: cgroup namespace-root mount flags

Hosted GUI fixture run `35813667946` at source
`8f16d779dee6941bb8f56bdeb31a35e6cd3837ec` proved that the production
`neothd-gui` helper was manager-owned and reached
`remount_linux_cgroup_at_namespace_root`. W153 then failed at its initial
cgroup2 mount with:

```text
mount read-only cgroup namespace root: Device or resource busy (os error 16)
```

The cgroup-v2 documentation describes creating a namespace-private hierarchy
view from a non-init cgroup namespace with `mount -t cgroup2 none
$MOUNT_POINT`. `mount(2)` documents `MS_BIND | MS_REMOUNT` as the operation
that changes per-mount flags, including `MS_RDONLY`, without changing the
shared filesystem superblock.

The helper therefore performs two fail-closed operations after mount propagation
has become private and before user runtime hiding, PID-guardian fork, provider
launch, or READY:

1. Mount `cgroup2` at `/sys/fs/cgroup` with `MS_NOSUID|MS_NODEV|MS_NOEXEC`.
   It deliberately omits `MS_RDONLY`, retaining the existing shared cgroup2
   superblock read-write.
2. Reconfigure that namespace-private VFS mount with
   `MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC`.

Each syscall names its exact failed stage in the existing containment namespace
error channel. The existing mandatory post-operation checks still require the
cgroup namespace root to be `/`, the mount to be read-only, and cgroup2 to have
`nsdelegate`; no check, service property, or provider boundary is weakened.

References: [Linux cgroup v2 namespace delegation](https://docs.kernel.org/admin-guide/cgroup-v2.html#namespace-delegation), [mount(2), bind mounts and bind-remount](https://man7.org/linux/man-pages/man2/mount.2.html).