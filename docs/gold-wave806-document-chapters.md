# ADOPT31-B3 large-text chapter review

`neoth skills --from-doc` remains the provider-free, defanged whole-review
path for bounded PDF and Office/book inputs. It does not slice binary
containers.

For a plain UTF-8 `.txt`, `.md`, or `.markdown` source larger than 200 KiB,
first discover the available zero-based indexes:

```text
neoth skills --list-doc-chapters /absolute/source.md
```

The read-only table and JSON receipt provide each index, start/end byte range,
truncation flag, source byte count, and source SHA-256. Select exactly one
reported index for review:

```text
neoth skills --from-doc-chapter /absolute/source.md --chapter-index N
```

The source is opened through the retained no-follow capability used by the
document-review boundary. The fixed-chunk scanner retains only a bounded line
prefix and never constructs a whole-file text buffer. It reads exactly the
admitted source length, keeps every cut at a UTF-8 scalar boundary, and refuses
early EOF or growth. Discovery refuses more than 4,096 ranges, so dense headings cannot retain an unbounded range list. Before discovery and after the selected range is read, the
held source is checked for the same regular-file identity, byte length, and
whole-source SHA-256. A change refuses the receipt.

The review JSON contains metadata only for the chapter: index, range, source
byte count, and source SHA-256. `SelectedTextChapter` is deliberately not
serializable; raw selected text never enters JSON. The sole review text is the
sanitized and defanged `rendered_review`. This path never installs or activates
a skill, writes skill state, or dispatches a provider.

`--chapter-index` is mandatory for `--from-doc-chapter`; `--from-doc`,
`--list-doc-chapters`, selection, and all mutation modes are mutually exclusive.
