# W377: browser archive fixture borrow repair

Hosted Rust test-target type checking found `E0505` in `zip_fixture`: the ZIP writer retained the mutable borrow of the fixture byte vector through its destructor, even after successful finalization.

The writer and its cursor now live in a nested scope. `finish()` remains required and checked before that scope ends; the vector is returned only after both values have dropped. The fixture still creates the exact ZIP bytes used by the managed-browser archive validation cases, without cloning or changing their assertions.

Local validation was intentionally not run under the workstation BSOD hold. The next GitHub-hosted Core gate must validate this repair.
