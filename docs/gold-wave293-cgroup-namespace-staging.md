# W293: stage a fresh cgroup namespace root without unmounting a locked mount

Hosted GUI125 at source `6dae3f9e06e9d389f6d69a51721b071985fbdff6`
executed all 125 required fixtures. It passed 123 and failed W153 and W164.
The W153 receipt records the concrete containment failure:

```text
unmount inherited cgroup mount: Invalid argument (os error 22)
```

The helper creates `CLONE_NEWUSER`, `CLONE_NEWCGROUP`, and `CLONE_NEWNS`
together. `mount_namespaces(7)` documents that mounts copied from a more
privileged user namespace are locked together in the new less-privileged mount
namespace and may not be individually unmounted. `MS_PRIVATE` stops
propagation; it does not unlock such a mount. The former direct fresh-cgroup2
attempt had already failed with `EBUSY`, so skipping the unmount and mounting
directly at `/sys/fs/cgroup` would not be a safe repair.

The replacement uses only the already-private mount namespace and never
unmounts or remounts the inherited cgroup2 mount:

1. Mount a `mode=0700`, `nosuid,nodev,noexec` tmpfs on `/tmp` in the private
   namespace. The staging directory therefore never reaches the host
   filesystem.
2. Create `/tmp/neoth-cgroup-namespace-stage` there and mount fresh cgroup2
   read-write with `nosuid,nodev,noexec`. Because this mount is created after
   `CLONE_NEWCGROUP`, its mount root represents the new namespace root.
3. Bind that staged mount over `/sys/fs/cgroup`, then bind-remount the public
   clone readonly with `nosuid,nodev,noexec`. This stacks a new mount over the
   inherited locked mount instead of modifying it.
4. Unmount the writable staging clone, remove its directory, and unmount the
   private tmpfs. Any stage or cleanup error fails containment before provider
   launch.

No `nsdelegate` option is added to the fresh cgroup2 mount. cgroup v2 documents
that it is a system-wide option controlled from the initial namespace. The
existing strict post-construction checks remain the acceptance authority: the
cgroup path must be `/`; every visible cgroup2 mount point must be the public
`/sys/fs/cgroup` path; and the top public mount must have root `/`, be
readonly, and retain `nsdelegate`. The covered inherited mount may remain in
mountinfo at that same path, but it cannot provide an alternate reachable
mountpoint. A leaked staging cgroup mount consequently fails before READY.

The focused source regression pins the full staging order and exact fresh,
bind, and readonly mount flags. The existing hostile Linux provider fixture
also attempts to unmount and readonly-remount the public cgroup mount; both
must be rejected with `EPERM`. The provider child also reasserts
no-new-privileges and clears its ambient, effective, permitted, and inheritable
capability sets immediately before exec, regardless of its mapped UID. It also
locks `SECBIT_NOROOT`, so a mapped UID 0 cannot regain capabilities through the
root exec transition. The
fixture probes a nested user-plus-mount namespace only in a forked child:
either an isolated success or `EPERM` is acceptable, but the protected parent
mountinfo must remain byte-identical. Hosted acceptance must run the parent
fixtures `linux_manager_stop_reaps_setsid_and_double_fork_tree` and
`linux_gui_crash_kills_complete_manager_unit`; their provider entry fixture
alone returns early when not selected. W153/W164 remain the callback-flow
coverage, while those two parents prove the staged containment and cleanup
path. No local Rust execution was performed under the BSOD hold.

References: [mount_namespaces(7)](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html), [cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html), [cgroup v2 delegation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).
