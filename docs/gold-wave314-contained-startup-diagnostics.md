# Wave 314: contained-startup diagnostic capture

The hosted r12 parent-death fixture previously reduced every pre-READY service exit to `load=loaded, active=inactive, sub=dead`. The separate product helper emitted no captured stderr, so that result did not identify whether frame/cgroup validation, PIDFD binding, namespace entry, guardian readiness, or the manager transaction had ended the service.

The supervisor now includes systemd's terminal `Result`, `ExecMainCode`, `ExecMainStatus`, and `StatusText` fields whenever a loaded unit becomes inactive or failed before READY. They are optional diagnostics: a target manager that omits one receives the explicit `<unavailable>` value, while the pre-existing ownership and containment authority fields remain strict. The focused fixture covers both their parse and preservation and a legacy snapshot that omits all four.

The actual product helper publishes only static, advisory `STATUS=` milestones after the combined launch-frame/cgroup-binding/parent-PID-identity checkpoint, request namespace entry, and guardian readiness. It then sends the existing `READY=1` only in its original position. The milestones contain no request payload, path, PID, environment value, token, or provider output; send failures are ignored so they cannot change containment, launch ordering, cleanup, retry behavior, or fail-closed readiness.

No local Rust, Cargo, GUI, or runtime validation ran under the BSOD hold. A hosted rerun of r12 must provide the next decision boundary.
