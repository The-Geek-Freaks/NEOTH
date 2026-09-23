# W286: replace the inherited cgroup namespace mount

The W281 two-step repair showed that the first fresh cgroup2 mount still failed
with `EBUSY` in Hosted GUI125. The GUI125 receipt is preserved in
`work/gold-20260906/wave281-cgroup-mount/gui125-b7ca/ADMISSION.json` and proves
125 ordered fixture executions, with W153 failing at `mount cgroup namespace
root` before the readonly bind-remount.

`cgroup_namespaces(7)` explains why bind-remounting the inherited cgroup mount
is not safe: a mount copied from the parent mount namespace retains the parent
cgroup namespace root and can expose ancestor cgroups. Its documented repair
sequence is to make mount propagation private, unmount the inherited cgroupfs
mount, and mount cgroupfs again from within the new cgroup namespace. The
remounted filesystem then reports `/` as its mount root. `mount(2)` also lists
stacking a mount on an existing mount point in the same mount namespace with
the same source and target as an EBUSY condition. That is consistent with the
observed error; the receipt alone does not identify the exact kernel branch.

After `make_linux_mounts_private()` succeeds, the helper now performs exactly
these fail-closed operations before it hides the user runtime, forks the PID
namespace guardian, starts any provider, or sends READY:

1. `umount2("/sys/fs/cgroup", 0)` removes the inherited cgroupfs mount.
   The normal zero flags intentionally reject a busy mount; no lazy detach is
   allowed.
2. A fresh cgroup2 mount at that path creates the current cgroup namespace
   root. It uses `MS_NOSUID|MS_NODEV|MS_NOEXEC` and keeps the shared cgroup2
   superblock read-write.
3. `MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC` restricts only
   that newly mounted namespace-private VFS mount.

Every operation reports a distinct namespace-containment stage error. The
existing mandatory post-operation checks remain the authority for acceptance:
the cgroup path must be `/`, and the exact `/sys/fs/cgroup` mount must have root
`/`, be read-only, and retain `nsdelegate`. They prevent treating a successful
syscall sequence as evidence of safe ancestor isolation.

References: [cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html), [mount(2)](https://man7.org/linux/man-pages/man2/mount.2.html).

Independent source review confirmed the ordering and fail-closed gates; the
syscall block now documents its pointer lifetime and null-pointer preconditions.
The design-system lint taxonomy and GUI audit checklist have no visual rows
applicable to this containment-only Rust change: Slint, tokens, copy and layout
are unchanged. Actual W153/W164 hosted acceptance remains required.
