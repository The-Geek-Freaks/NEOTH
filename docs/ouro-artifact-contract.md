# Ouro artifact-integrity contract

`local_ouro` treats the Hugging Face cache as transport storage, never as a
readiness signal. The runtime cache contains exactly `tokenizer.json`,
`config.json`, and `model.safetensors` under the directory derived from the
configured Hugging Face repository.

Before a cache hit, `providers::ouro::artifacts` rejects a missing file, an
unterminated model-download lifecycle, an installation marker, invalid JSON,
an unreadable tokenizer, an invalid Ouro configuration, and malformed or
truncated safetensors. The safetensors check verifies header shape, contiguous
tensor byte ranges, and the declared final length; an existing filename alone
is not enough. `tokenizer.json` and `config.json` are streamed through a
32 MiB cap before either parser receives bytes.
Safetensors headers are bounded to 16 MiB, 256 metadata entries, 10,000
tensors, and rank 32 per tensor before their bookkeeping can grow further.

Before loading, the provider takes the shared model-cache lock and constructs
an `OuroLoadReceipt`. It binds:

- configured Ouro repository;
- the SHA-256 and byte length of each of the three runtime files;
- selected quantisation mode (`none` or `q8`);
- configured accelerator choice and the Candle-resolved device location.

After validation, canonical download paths are moved without copying into a
content-addressed, read-only generation directory. An active-generation pointer
is published last. The private promotion journal and pointer are atomically
written then synchronised with their parent directory; journal removal is also
durable. After an interruption, the provider recovers only the one complete,
read-only generation whose content hash matches its directory name. Incomplete
or multiple orphan generations are explicit errors and do not trigger an
implicit redownload. The Candle loader receives a retained-file/mmap backend, not a
path-based `VarBuilder`: tokenizer and config are parsed from retained handles,
and tensors are read from the same retained safetensors mmap. On Windows the
lease permits only reader sharing, so the OS excludes write, replacement, and
delete while inference uses it. On Unix, the generation's read-only ownership
contract and NEOTH advisory shared lock prevent NEOTH writers; a hostile process
with permission to override filesystem mode is outside this local cache
integrity boundary. The Unix advisory lock is not presented as a defense
against such a writer.
Every named generation artifact is checked as a regular non-link file before
validation, promotion, digesting, and lease opening. Unix opens use
`O_NOFOLLOW`; Windows opens the reparse point itself and reject its handle,
so an orphan generation cannot redirect validation or a retained mmap outside
the model cache.

The lease bytes are checked against the receipt before and after model
construction. Any change rejects the load. On later calls, a newly validated
receipt must equal the one stored alongside the loaded model. A changed
artifact, repository, quantisation mode, or resolved accelerator clears the
in-memory model and forces a new load. Consequently Q8 cannot reuse a native
model and cannot silently dispatch to the native forward path.

`runtime_cache_status` is the bounded structural status API for the CLI and
future GUI. `neoth ouro status` reports its `ready` value only after the cache
passes the non-hashing validation above, otherwise `not_ready` with the bounded
causal error. It deliberately does not hash multi-gigabyte weights; the full
digest receipt is made by the real load path. `neoth ouro fetch`
reports success only after its download lifecycle has completed and the normal
non-pending runtime validation passes.
