# W170 — portable diff-impact acceptance schema handling

The Windows preview at source 6003175f completed native CLI, migration, relay
and GUI builds and passed portable lifecycle acceptance. Run 35635024193 then
failed in Test-PortableDiffImpact.ps1:292: strict PowerShell property access
attempted to read an omitted symbol from a valid file-fallback ImpactSeed.

ImpactSeed.symbol is optional and excluded from JSON when absent. The helper
now checks the property exists before comparing its exact value. It still
requires exactly one src/lib.rs changed_symbol seed, an impacted caller_symbol,
fresh matching generations, exact caller coverage and one resolved TestedBy
observation with framework_and_conventional_path provenance. The production
Rust schema and producer are unchanged.

The source repair and CRLF normalization receipts are retained under
work/gold-20260906/wave170-preview-impact. CRLF matches the existing explicit
PowerShell checkout rule in .gitattributes. No local parser, test, fixture or
product execution ran. A fresh GitHub Windows preview must establish whether
the repaired helper and the full portable behavior pass. The prior lifecycle
success is evidence only for its older source, not for the current release.
