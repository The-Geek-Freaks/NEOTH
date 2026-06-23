#!/usr/bin/env python3
"""convert_ecapa.py — Convert SpeechBrain ECAPA-TDNN checkpoint to safetensors.

Usage
-----
    python scripts/convert_ecapa.py \
        --ckpt ~/.cache/huggingface/hub/models--speechbrain--spkrec-ecapa-voxceleb/\
snapshots/<hash>/embedding_model.ckpt \
        --out  ~/.neoth/models/speechbrain-spkrec-ecapa-voxceleb/model.safetensors

The script remaps SpeechBrain's PyTorch `.ckpt` parameter names to the flat
slash-separated paths that `VarBuilder::pp("...")` in the Rust ECAPA module
resolves.  Only the `embedding_model` weights are included; `classifier`,
`mean_var_norm_emb`, and `label_encoder` are not needed for inference.

Key-mapping summary (SpeechBrain .ckpt → safetensors path)
-----------------------------------------------------------
embedding_model.blocks.0.conv.weight          → blocks_0.weight
embedding_model.blocks.0.conv.bias            → blocks_0.bias
embedding_model.blocks.0.norm.weight          → blocks_0_bn.weight
embedding_model.blocks.0.norm.bias            → blocks_0_bn.bias
embedding_model.blocks.0.norm.running_mean    → blocks_0_bn.running_mean
embedding_model.blocks.0.norm.running_var     → blocks_0_bn.running_var

For SERes2NetBlocks (N = 1, 2, 3):
embedding_model.blocks.N.tdnn1.conv.weight    → blocks_N.tdnn1.weight
embedding_model.blocks.N.tdnn1.conv.bias      → blocks_N.tdnn1.bias
embedding_model.blocks.N.tdnn1.norm.weight    → blocks_N.tdnn1_bn.weight
embedding_model.blocks.N.tdnn1.norm.bias      → blocks_N.tdnn1_bn.bias
embedding_model.blocks.N.tdnn1.norm.running_mean → blocks_N.tdnn1_bn.running_mean
embedding_model.blocks.N.tdnn1.norm.running_var  → blocks_N.tdnn1_bn.running_var

embedding_model.blocks.N.res2net_block.blocks.J.conv.weight  → blocks_N.res2net.blocks_J.weight
embedding_model.blocks.N.res2net_block.blocks.J.conv.bias    → blocks_N.res2net.blocks_J.bias
embedding_model.blocks.N.res2net_block.blocks.J.norm.weight  → blocks_N.res2net.blocks_J_bn.weight
embedding_model.blocks.N.res2net_block.blocks.J.norm.bias    → blocks_N.res2net.blocks_J_bn.bias
embedding_model.blocks.N.res2net_block.blocks.J.norm.running_mean
  → blocks_N.res2net.blocks_J_bn.running_mean
embedding_model.blocks.N.res2net_block.blocks.J.norm.running_var
  → blocks_N.res2net.blocks_J_bn.running_var

embedding_model.blocks.N.tdnn2.conv.weight    → blocks_N.tdnn2.weight
embedding_model.blocks.N.tdnn2.conv.bias      → blocks_N.tdnn2.bias
embedding_model.blocks.N.tdnn2.norm.weight    → blocks_N.tdnn2_bn.weight
... (same pattern)

embedding_model.blocks.N.se_block.conv1.weight → blocks_N.se.conv1.weight
embedding_model.blocks.N.se_block.conv1.bias   → blocks_N.se.conv1.bias
embedding_model.blocks.N.se_block.conv2.weight → blocks_N.se.conv2.weight
embedding_model.blocks.N.se_block.conv2.bias   → blocks_N.se.conv2.bias

MFA:
embedding_model.mfa.conv.weight               → mfa.weight
embedding_model.mfa.conv.bias                 → mfa.bias
embedding_model.mfa.norm.weight               → mfa_bn.weight
embedding_model.mfa.norm.bias                 → mfa_bn.bias
embedding_model.mfa.norm.running_mean         → mfa_bn.running_mean
embedding_model.mfa.norm.running_var          → mfa_bn.running_var

ASP (AttentiveStatisticsPooling):
embedding_model.asp.tdnn.conv.weight          → asp.tdnn.weight
embedding_model.asp.tdnn.conv.bias            → asp.tdnn.bias
embedding_model.asp.tdnn.norm.weight          → asp.tdnn_bn.weight
embedding_model.asp.tdnn.norm.bias            → asp.tdnn_bn.bias
embedding_model.asp.tdnn.norm.running_mean    → asp.tdnn_bn.running_mean
embedding_model.asp.tdnn.norm.running_var     → asp.tdnn_bn.running_var
embedding_model.asp.conv.weight               → asp.conv.weight
embedding_model.asp.conv.bias                 → asp.conv.bias

asp_bn:
embedding_model.asp_bn.norm.weight            → asp_bn.weight
embedding_model.asp_bn.norm.bias              → asp_bn.bias
embedding_model.asp_bn.norm.running_mean      → asp_bn.running_mean
embedding_model.asp_bn.norm.running_var       → asp_bn.running_var

fc (final Conv1d):
embedding_model.fc.weight                     → fc.weight
embedding_model.fc.bias                       → fc.bias

NOTE ON asp_bn: SpeechBrain wraps BatchNorm1d as a skip-transpose module; the
actual PyTorch norm sub-key may be `.norm.weight` or directly `.weight` depending
on the SpeechBrain version. Inspect the checkpoint with `torch.load(...).keys()`
and adjust the mapping below if needed.
"""

import argparse
import sys
import os

def main():
    parser = argparse.ArgumentParser(description="Convert ECAPA-TDNN .ckpt to safetensors")
    parser.add_argument("--ckpt",  required=True,
                        help="Path to embedding_model.ckpt from SpeechBrain")
    parser.add_argument("--out",   required=True,
                        help="Output path for .safetensors file")
    parser.add_argument("--dump-keys", action="store_true",
                        help="Print all original checkpoint keys and exit")
    args = parser.parse_args()

    try:
        import torch
    except ImportError:
        sys.exit("ERROR: torch not installed. Run: pip install torch --index-url https://download.pytorch.org/whl/cpu")

    try:
        from safetensors.torch import save_file
    except ImportError:
        sys.exit("ERROR: safetensors not installed. Run: pip install safetensors")

    print(f"Loading checkpoint: {args.ckpt}")
    state = torch.load(args.ckpt, map_location="cpu")

    # SpeechBrain checkpoints may be plain dicts or wrapped in {"model": ...}.
    if isinstance(state, dict) and "model" in state:
        state = state["model"]

    if args.dump_keys:
        for k in sorted(state.keys()):
            v = state[k]
            print(f"  {k:80s}  {list(v.shape)}")
        return

    # ── Key mapping ──────────────────────────────────────────────────────────

    def _conv_bn(src_prefix, dst_prefix, out):
        """Map a SpeechBrain Conv1d+BatchNorm1d pair."""
        mapping = {
            f"{src_prefix}.conv.weight":        f"{dst_prefix}.weight",
            f"{src_prefix}.conv.bias":          f"{dst_prefix}.bias",
            # BN may live at .norm.* or directly at .weight for some SB versions.
            f"{src_prefix}.norm.weight":        f"{dst_prefix}_bn.weight",
            f"{src_prefix}.norm.bias":          f"{dst_prefix}_bn.bias",
            f"{src_prefix}.norm.running_mean":  f"{dst_prefix}_bn.running_mean",
            f"{src_prefix}.norm.running_var":   f"{dst_prefix}_bn.running_var",
        }
        for src, dst in mapping.items():
            if src in state:
                out[dst] = state[src].float()

    remapped = {}

    # block[0]: TdnnBlock(80 → 1024, k=5).
    prefix = "embedding_model.blocks.0"
    _conv_bn(prefix, "blocks_0", remapped)

    # blocks[1..3]: SERes2NetBlocks.
    for n in range(1, 4):
        sp = f"embedding_model.blocks.{n}"
        dp = f"blocks_{n}"

        # tdnn1
        _conv_bn(f"{sp}.tdnn1", f"{dp}.tdnn1", remapped)
        # Res2Net sub-blocks (7 sub-blocks for scale=8).
        for j in range(7):
            _conv_bn(
                f"{sp}.res2net_block.blocks.{j}",
                f"{dp}.res2net.blocks_{j}",
                remapped,
            )
        # tdnn2
        _conv_bn(f"{sp}.tdnn2", f"{dp}.tdnn2", remapped)
        # SE block (pointwise convs, no BN).
        for key_suffix in ["conv1.weight", "conv1.bias", "conv2.weight", "conv2.bias"]:
            src = f"{sp}.se_block.{key_suffix}"
            dst = f"{dp}.se.{key_suffix}"
            if src in state:
                remapped[dst] = state[src].float()

    # MFA TdnnBlock.
    _conv_bn("embedding_model.mfa", "mfa", remapped)

    # ASP: TdnnBlock + pointwise conv.
    _conv_bn("embedding_model.asp.tdnn", "asp.tdnn", remapped)
    for key_suffix in ["conv.weight", "conv.bias"]:
        src = f"embedding_model.asp.{key_suffix}"
        dst = f"asp.{key_suffix}"
        if src in state:
            remapped[dst] = state[src].float()

    # asp_bn: try .norm.* first (newer SpeechBrain), then direct .* (older).
    for variant in [
        ("embedding_model.asp_bn.norm", "asp_bn"),
        ("embedding_model.asp_bn",      "asp_bn"),
    ]:
        src_p, dst_p = variant
        for sub in ["weight", "bias", "running_mean", "running_var"]:
            src = f"{src_p}.{sub}"
            dst = f"{dst_p}.{sub}"
            if src in state and dst not in remapped:
                remapped[dst] = state[src].float()

    # fc: final Conv1d (may be .w.weight or .weight depending on SB version).
    for src_w in ["embedding_model.fc.weight", "embedding_model.fc.w.weight"]:
        if src_w in state:
            remapped["fc.weight"] = state[src_w].float()
            break
    for src_b in ["embedding_model.fc.bias", "embedding_model.fc.w.bias"]:
        if src_b in state:
            remapped["fc.bias"] = state[src_b].float()
            break

    # ── Validation ───────────────────────────────────────────────────────────

    required_keys = [
        "blocks_0.weight", "blocks_0_bn.weight",
        "blocks_1.tdnn1.weight", "blocks_1.se.conv1.weight",
        "mfa.weight", "mfa_bn.weight",
        "asp.tdnn.weight", "asp.conv.weight",
        "asp_bn.weight",
        "fc.weight",
    ]
    missing = [k for k in required_keys if k not in remapped]
    if missing:
        print(f"WARNING: {len(missing)} expected keys are missing from the remapped output:")
        for k in missing:
            print(f"  {k}")
        print("Run with --dump-keys to inspect original checkpoint key names.")

    unmapped = [k for k in state.keys()
                if k.startswith("embedding_model.") and not k.startswith("embedding_model.fc.")]
    # Don't fail on unmapped keys — they may be extra metadata.

    # ── Save ─────────────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    save_file(remapped, args.out)
    print(f"Saved {len(remapped)} tensors → {args.out}")
    print("Next: verify with 'python -c \"from safetensors import safe_open; "
          f"f=safe_open(\\'{args.out}\\',framework=\\'pt\\'); "
          "print(list(f.keys())[:5])\"'")

if __name__ == "__main__":
    main()
