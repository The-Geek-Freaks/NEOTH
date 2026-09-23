# W395 - BGE-M3 functional acceptance

GOLD-LF-P2-24 is accepted against all 25 required identities from the W387
selection: 16 native/CLI/Buddy cases, seven GUI cases and two official-model
cases. Root checked every individual PASS terminal in the already admitted
source-bound artifacts. The exact records are in
docs/verification/gold-wave395-p224-acceptance.json.

- Group780e5 run35857339883 on e5bdf2ab supplies the 16 native cases.
- GUI135216 run35856964423 on21612331 supplies all seven GUI cases;
  its complete135/135 receipt has18 source and five input bindings.
- BGE216 run35856967745 on21612331 supplies the two official-model cases,
  nine source bindings and the real product CLI acquisition of the pinned
  official revision5617a9f61b028005a4858fdac845db406aefb181.

The accepted behavior includes explicit model selection, refusal of unknown
or incompatible routes, exact artifact/readiness binding, denied acquisition,
failed-load handling, normalization and GUI/CLI/Buddy lifecycle parity.
Qwen remains the default; selecting BGE does not create silent fallback.

Relevant source remains unchanged through1182864f except two reviewed,
unrelated deltas: providers/mod.rs changes the direct-chat retry request;
GUI main.rs changes macOS response-feedback and citation test fixtures.
Neither changes BGE routing, artifact/readiness semantics or W218 callbacks.
Independent W395 review and Root's exact-terminal recheck agree.

Group780's two unrelated failures and28 unstarted tests remain recorded.
This scoped functional acceptance does not claim full-CI, platform package,
or release acceptance. Model acquisition and execution ran only on GitHub;
no local executable validation or model download occurred.

Road1324=1028checked/294open/2partial;296raw/295pre-tag blockers.
WS-LF118=21done/97open.
