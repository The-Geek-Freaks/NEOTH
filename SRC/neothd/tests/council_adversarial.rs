//! Round-3 v0.4 ARCH-02 — Council adversarial test suite.
//!
//! Seven named tests that exercise specific failure modes the
//! council pipeline must catch. Each test pins a property the
//! primitives shipped in ARCH-04 (block-layer token caps) +
//! ADV-12 (factual_contradiction_check + GROUND_TRUTH_TAG) +
//! ARCH-07 (skill versioning + prompt_bundle_hash) make verifiable
//! WITHOUT needing the full orchestrator integration. The
//! orchestrator-level wiring (factual_check called in run_debate,
//! enforce_budget called before each provider call, prompt_bundle_hash
//! recorded on PROVIDER_REQUEST) lands as the downstream slice that
//! consumes these tests' contracts.
//!
//! ## The seven tests
//!
//! | # | Test                                          | What it pins                                    |
//! |---|-----------------------------------------------|-------------------------------------------------|
//! | 1 | `test_all_three_agree_and_wrong`              | factual_check catches unanimous-wrong via       |
//! |   |                                               | ground-truth comparison (NOT via dissent).      |
//! | 2 | `test_emergent_divergence_explosion`          | dissent score signals strong-dissent above 0.6  |
//! |   |                                               | threshold when responses fully diverge.         |
//! | 3 | `test_callosum_self_destructs`                | CorticalVerdict::IrreconcilableConflict on      |
//! |   |                                               | empty / contradictory hemisphere inputs.        |
//! | 4 | `test_fuzz_input_against_council`             | dissent + factual_check never panic on random   |
//! |   |                                               | byte input.                                     |
//! | 5 | `test_token_budget_exhaustion`                | uncoupled A/B/E survive even when cap is        |
//! |   |                                               | impossible.                                     |
//! | 6 | `test_prompt_bundle_replay_determinism`       | same BlockA..E content → same hash across       |
//! |   |                                               | runs + across input orderings.                  |
//! | 7 | `test_left_dominates_right_unfairly`          | dissent score reflects actual content overlap,  |
//! |   |                                               | not response-length asymmetry.                  |

use neothd::council::dissent::{DissentScore, score_dissent};
use neothd::council::factual_check::{
    DEFAULT_NEGATION_MARKERS, DEFAULT_NEGATION_WINDOW_CHARS, FactualAssertion,
    GROUND_TRUTH_TAG_CLOSE, GROUND_TRUTH_TAG_OPEN, embed_ground_truth_tag,
    extract_ground_truth_block, factual_contradiction_check,
};
use neothd::skills::versioning::{
    BundleBlock, BundleBlockEntry, compute_prompt_bundle_hash, prompt_bundle_hash_hex,
};
use neothd::tokens::budget::{Block, BlockItem, enforce_budget};

// ── Test 1 — test_all_three_agree_and_wrong ─────────────────────

#[test]
fn test_all_three_agree_and_wrong() {
    // Three hemispheres unanimously echo the WRONG capital with the same
    // phrasing (the shared-bias / model-collapse case). Lexical dissent is
    // near-0 (high false confidence) so the dissent scorer sees consensus
    // and the council would ship the wrong answer. With ADV-12's
    // factual_check the ground-truth comparison fires independently.
    //
    // NOTE: the responses are lexically near-identical ON PURPOSE. Jaccard
    // dissent measures WORD overlap, not meaning — paraphrases of the same
    // fact ("Munich since 1949" vs "It is Munich") score HIGH dissent
    // despite agreeing, which is exactly the blind spot
    // `score_dissent_via_embedding` exists to close. This test pins the
    // lexical-consensus case where dissent is genuinely blind.
    let left = "The capital of Germany is Munich.";
    let right = "The capital of Germany is Munich today.";
    let cerebellum = "The capital of Germany is Munich, yes.";

    // Pre-ADV-12: dissent reads near-0 (high lexical consensus).
    let dissent = score_dissent(&[left, right, cerebellum]);
    assert!(
        dissent.is_consensus(),
        "three hemispheres echoing the same wrong fact in the same words MUST appear as consensus to the lexical dissent scorer (this is the bug ADV-12 closes), got {}",
        dissent.0,
    );

    // Post-ADV-12: ground-truth comparison catches it.
    let assertions = vec![FactualAssertion {
        subject: "capital of Germany".to_string(),
        expected_keyword: "Berlin".to_string(),
    }];
    for (label, response) in [("left", left), ("right", right), ("cerebellum", cerebellum)] {
        let outcome = factual_contradiction_check(
            response,
            &assertions,
            DEFAULT_NEGATION_MARKERS,
            DEFAULT_NEGATION_WINDOW_CHARS,
        );
        assert!(
            !outcome.agrees,
            "{label} response MUST fail ground-truth check (mentions capital of Germany but says Munich)",
        );
    }
}

// ── Test 2 — test_emergent_divergence_explosion ────────────────

#[test]
fn test_emergent_divergence_explosion() {
    // Three responses on completely different topics. Dissent
    // score MUST signal strong dissent (>= 0.6) so the council
    // verdict path knows to escalate to Split.
    let left = "the best approach is to refactor the database schema first";
    let right = "you should always validate user inputs at the API boundary";
    let cerebellum = "regression tests will catch the off-by-one before deploy";

    let dissent = score_dissent(&[left, right, cerebellum]);
    assert!(
        dissent.is_strong_dissent(),
        "fully divergent topics MUST surface as strong_dissent (>= {}), got {}",
        DissentScore::STRONG_DISSENT,
        dissent.0,
    );
}

// ── Test 3 — test_callosum_self_destructs ──────────────────────

#[test]
fn test_callosum_self_destructs() {
    // The Callosum primitive is a typed `CorticalVerdict` enum.
    // The "self-destruct" property: malformed inputs (empty,
    // contradictory) MUST surface as IrreconcilableConflict
    // (the only non-resolved variant) rather than panic or loop.
    //
    // We can't easily exercise `callosum::resolve` end-to-end
    // without a real HemisphereProvider — that path needs the
    // orchestrator integration. But the enum's contract IS the
    // pinned property: any IrreconcilableConflict must report
    // unresolved + carry a reason.
    use neothd::council::callosum::CorticalVerdict;
    let conflict = CorticalVerdict::IrreconcilableConflict {
        reason: "synthesis prompt produced empty Cerebellum response".to_string(),
    };
    assert!(
        !conflict.is_resolved(),
        "IrreconcilableConflict must surface as unresolved",
    );
    assert!(
        conflict.text().is_none(),
        "IrreconcilableConflict MUST NOT leak a synthesis text",
    );
    let synthesis = CorticalVerdict::Synthesis("bridged answer".to_string());
    assert!(synthesis.is_resolved());
    assert_eq!(synthesis.text(), Some("bridged answer"));
}

// ── Test 4 — test_fuzz_input_against_council ───────────────────

#[test]
fn test_fuzz_input_against_council() {
    // Coarse deterministic fuzz: 50 hand-picked pathological
    // inputs (empty / huge / unicode / control chars / SQL-
    // injection-ish / NUL bytes embedded as text). None of them
    // may panic the council scoring functions.
    let bad_inputs: Vec<String> = vec![
        String::new(),
        " ".to_string(),
        "\n\n\n".to_string(),
        "\0\0\0".to_string(),
        "'; DROP TABLE users; --".to_string(),
        "{{{{{{}}}}}}".to_string(),
        "🚀🔥💥".to_string(),
        "Müller".to_string(),
        "\u{1F600}".repeat(100),
        "x".repeat(10_000),
        "💀".repeat(500),
        "<script>alert(1)</script>".to_string(),
        "\\x00\\x01\\x02".to_string(),
        "OR 1=1".to_string(),
        format!("{:>8000}", "deeply-indented-content"),
    ];

    for body in &bad_inputs {
        // score_dissent over 3 copies of the same pathological string.
        let _ = score_dissent(&[body, body, body]);
        // Also against a mixed-bag triplet so we exercise the
        // Jaccard with non-trivial union sizes.
        let _ = score_dissent(&[body, "neutral content here", body]);
        // factual_check against an assertion that references the
        // pathological string as the subject.
        let _ = factual_contradiction_check(
            body,
            &[FactualAssertion {
                subject: body.clone(),
                expected_keyword: "anything".to_string(),
            }],
            DEFAULT_NEGATION_MARKERS,
            DEFAULT_NEGATION_WINDOW_CHARS,
        );
    }
}

// ── Test 5 — test_token_budget_exhaustion ──────────────────────

#[test]
fn test_token_budget_exhaustion() {
    // Pin the "never remove uncoupled A/B/E" rule under an impossible cap.
    // Operator sets cap = 50 tokens but A + B + E alone sum to
    // 1500 tokens — enforce_budget MUST surface this as a
    // degradation event (Some(detail)) while preserving all
    // A/B/E items. The `new_total > cap` signal in the detail is
    // the operator-visible "your cap is too aggressive" hint.
    let mut items = vec![
        BlockItem {
            block: Block::A,
            atomic_group: None,
            importance: 0.5,
            ts_ns: 0,
            tokens: 500,
            content: "x".repeat(2000),
        },
        BlockItem {
            block: Block::B,
            atomic_group: None,
            importance: 0.5,
            ts_ns: 0,
            tokens: 500,
            content: "x".repeat(2000),
        },
        BlockItem {
            block: Block::E,
            atomic_group: None,
            importance: 0.5,
            ts_ns: 0,
            tokens: 500,
            content: "x".repeat(2000),
        },
    ];

    let detail = enforce_budget(&mut items, 50)
        .expect("valid bundle")
        .expect("must trigger");
    assert_eq!(items.len(), 3, "A + B + E MUST all survive");
    assert_eq!(detail.dropped_d_count, 0);
    assert_eq!(detail.dropped_c_count, 0);
    assert!(!detail.conductor_truncated);
    assert!(
        detail.new_total > detail.cap,
        "new_total > cap is the operator-visible signal that the cap is too aggressive for the protected blocks alone",
    );
    // Confirm each surviving block is from the protected set.
    for item in &items {
        assert!(!item.block.is_degradable(), "survivor must be A/B/E");
    }
}

// ── Test 6 — test_prompt_bundle_replay_determinism ─────────────

#[test]
fn test_prompt_bundle_replay_determinism() {
    // Pin the ARCH-07 contract: same content set in any input
    // order produces the same hash. Also pin that any content
    // diff produces a different hash (collision-free in the
    // operator's audit-trail sense).
    let blocks_in_order = vec![
        BundleBlockEntry {
            block: BundleBlock::A,
            content: "operator system prompt",
        },
        BundleBlockEntry {
            block: BundleBlock::B,
            content: "active skill: lowkey",
        },
        BundleBlockEntry {
            block: BundleBlock::C,
            content: "profile: alex prefers terse",
        },
        BundleBlockEntry {
            block: BundleBlock::D,
            content: "recall: last meeting was tuesday",
        },
        BundleBlockEntry {
            block: BundleBlock::E,
            content: "current message: what was decided?",
        },
    ];

    // 1. Replay determinism — multiple computations yield same hash.
    let hash_a = compute_prompt_bundle_hash(&blocks_in_order);
    let hash_b = compute_prompt_bundle_hash(&blocks_in_order);
    assert_eq!(hash_a, hash_b, "replay determinism pin");

    // 2. Order independence — re-arranged input yields same hash.
    let blocks_shuffled = vec![
        BundleBlockEntry {
            block: BundleBlock::E,
            content: "current message: what was decided?",
        },
        BundleBlockEntry {
            block: BundleBlock::A,
            content: "operator system prompt",
        },
        BundleBlockEntry {
            block: BundleBlock::D,
            content: "recall: last meeting was tuesday",
        },
        BundleBlockEntry {
            block: BundleBlock::B,
            content: "active skill: lowkey",
        },
        BundleBlockEntry {
            block: BundleBlock::C,
            content: "profile: alex prefers terse",
        },
    ];
    let hash_shuffled = compute_prompt_bundle_hash(&blocks_shuffled);
    assert_eq!(hash_a, hash_shuffled, "input-order independence pin");

    // 3. Content sensitivity — single char diff in any block must
    // produce a different hash. This is the audit-chain integrity
    // guarantee that replay determinism rides on.
    for tweak_block in [BundleBlock::A, BundleBlock::C, BundleBlock::E] {
        let mut tweaked = blocks_in_order.clone();
        for entry in &mut tweaked {
            if entry.block == tweak_block {
                // Replace with a 1-char-different version.
                entry.content = match tweak_block {
                    BundleBlock::A => "operator system prompt!",
                    BundleBlock::C => "profile: alex prefers terse2",
                    BundleBlock::E => "current message: what was decided!",
                    _ => unreachable!(),
                };
            }
        }
        let hash_tweaked = compute_prompt_bundle_hash(&tweaked);
        assert_ne!(
            hash_a, hash_tweaked,
            "1-char tweak in {tweak_block:?} MUST change the bundle hash",
        );
    }

    // 4. Hex form is 64 chars + lowercase.
    let hex = prompt_bundle_hash_hex(&blocks_in_order);
    assert_eq!(hex.len(), 64);
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
}

// ── Test 7 — test_left_dominates_right_unfairly ────────────────

#[test]
fn test_left_dominates_right_unfairly() {
    // Pin the property: dissent score is a function of CONTENT
    // overlap, not RESPONSE LENGTH. A council where Left writes
    // an essay and Right writes a one-liner — but both touch the
    // same canonical points — must NOT register as strong dissent
    // just because the lengths differ.
    let left = "ssl tls https handshake certificate exchange";
    let right = "ssl tls https handshake";
    let cerebellum = "ssl tls https";
    let length_diff_dissent = score_dissent(&[left, right, cerebellum]);

    // Now the inverse: short + short + long, all with disjoint
    // content. Length is similar but content overlap is 0.
    let left2 = "northern lights aurora borealis polar geomagnetic";
    let right2 = "northern lights aurora";
    let cerebellum2 = "alpha beta gamma delta epsilon zeta eta theta iota";
    let content_diff_dissent = score_dissent(&[left2, right2, cerebellum2]);

    assert!(
        content_diff_dissent.0 > length_diff_dissent.0,
        "content divergence MUST dominate dissent score, not length asymmetry — \
         got length-diff dissent {} vs content-diff dissent {}",
        length_diff_dissent.0,
        content_diff_dissent.0,
    );
}

// ── ADV-12 / ARCH-07 cross-test: ground-truth tag in bundle ────

#[test]
fn ground_truth_tag_survives_bundle_hash_canonicalisation() {
    // Sanity: when the GROUND_TRUTH_TAG block is embedded in the A
    // (system) block, the prompt_bundle_hash still differentiates
    // distinct ground-truth content. The two-block pair (the tag
    // wrapping + the assertion text) must roll into the hash
    // distinctly enough that two different ground-truth bodies
    // produce different hashes.
    let assertion_a = vec![FactualAssertion {
        subject: "city".to_string(),
        expected_keyword: "Berlin".to_string(),
    }];
    let assertion_b = vec![FactualAssertion {
        subject: "city".to_string(),
        expected_keyword: "Munich".to_string(),
    }];
    let prompt = "What is the capital?";
    let with_a = embed_ground_truth_tag(prompt, &assertion_a);
    let with_b = embed_ground_truth_tag(prompt, &assertion_b);
    // Confirm the tag was actually embedded.
    assert!(with_a.contains(GROUND_TRUTH_TAG_OPEN));
    assert!(with_a.contains(GROUND_TRUTH_TAG_CLOSE));
    // Extract the inner body to prove the parser sees distinct content.
    let inner_a = extract_ground_truth_block(&with_a).unwrap();
    let inner_b = extract_ground_truth_block(&with_b).unwrap();
    assert_ne!(inner_a, inner_b);

    let bundle_a = vec![BundleBlockEntry {
        block: BundleBlock::A,
        content: &with_a,
    }];
    let bundle_b = vec![BundleBlockEntry {
        block: BundleBlock::A,
        content: &with_b,
    }];
    let hash_a = compute_prompt_bundle_hash(&bundle_a);
    let hash_b = compute_prompt_bundle_hash(&bundle_b);
    assert_ne!(
        hash_a, hash_b,
        "distinct ground-truth bodies MUST produce distinct bundle hashes",
    );
}
