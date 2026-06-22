#!/usr/bin/env python3
"""Convert SpeechBrain spkrec-xvect-voxceleb embedding_model.ckpt to safetensors.

The Rust XVectorEncoder in src/media/speaker_encoder_xvector.rs loads a single
safetensors file from the NEOTH model cache.  This script maps the SpeechBrain
PyTorch checkpoint key names to the flat paths the VarBuilder expects.

Usage
-----
    # 1. Install dependencies (once):
    pip install torch safetensors huggingface_hub

    # 2. Run (HuggingFace download + convert):
    python scripts/convert_xvector.py

    # Or point at an already-downloaded ckpt:
    python scripts/convert_xvector.py \\
        --ckpt ~/.cache/huggingface/hub/.../embedding_model.ckpt \\
        --out  ~/.neoth/models/speechbrain-spkrec-xvect-voxceleb/model.safetensors

After the script completes, NEOTH's XVectorEncoder::try_load() will find the
file and activate automatically (no config change needed).

Architecture recap (from hyperparams.yaml)
-------------------------------------------
blocks flat list (nn.ModuleList):
  idx 0  Conv1d  in=24,  out=512,  kernel=5, dilation=1
  idx 1  LeakyReLU                                          [no weights]
  idx 2  BatchNorm1d(512)
  idx 3  Conv1d  in=512, out=512,  kernel=3, dilation=2
  idx 4  LeakyReLU                                          [no weights]
  idx 5  BatchNorm1d(512)
  idx 6  Conv1d  in=512, out=512,  kernel=3, dilation=3
  idx 7  LeakyReLU                                          [no weights]
  idx 8  BatchNorm1d(512)
  idx 9  Conv1d  in=512, out=512,  kernel=1, dilation=1
  idx 10 LeakyReLU                                          [no weights]
  idx 11 BatchNorm1d(512)
  idx 12 Conv1d  in=512, out=1500, kernel=1, dilation=1
  idx 13 LeakyReLU                                          [no weights]
  idx 14 BatchNorm1d(1500)
  idx 15 StatisticsPooling                                  [no weights]
  idx 16 Linear(3000 → 512, bias=True)

Key mapping: SpeechBrain ckpt → safetensors (Rust VarBuilder paths)
--------------------------------------------------------------------
SpeechBrain stores parameters under sequential numbering but wraps Conv1d in
a .conv sub-module and BatchNorm1d in a .norm sub-module. The exact keys
depend on the SpeechBrain version; the script prints all source keys so you
can verify the mapping if it fails.

Expected source keys (SpeechBrain ≥ 0.5):
  blocks.0.conv.weight         → blocks_0/weight
  blocks.0.conv.bias           → blocks_0/bias
  blocks.2.norm.weight         → blocks_2/weight
  blocks.2.norm.bias           → blocks_2/bias
  blocks.2.norm.running_mean   → blocks_2/running_mean
  blocks.2.norm.running_var    → blocks_2/running_var
  blocks.2.norm.num_batches_tracked  [skipped — not needed at inference]
  (same pattern for idx 3/5, 6/8, 9/11, 12/14)
  blocks.16.w.weight           → blocks_16/weight
  blocks.16.w.bias             → blocks_16/bias
"""

import argparse
import os
import pathlib
import sys


def default_out_path() -> pathlib.Path:
    home = pathlib.Path.home()
    return (
        home
        / ".neoth"
        / "models"
        / "speechbrain-spkrec-xvect-voxceleb"
        / "model.safetensors"
    )


def download_ckpt() -> pathlib.Path:
    """Download embedding_model.ckpt from HuggingFace Hub and return local path."""
    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        sys.exit("huggingface_hub is not installed: pip install huggingface_hub")

    print("Downloading embedding_model.ckpt from speechbrain/spkrec-xvect-voxceleb …")
    path = hf_hub_download(
        repo_id="speechbrain/spkrec-xvect-voxceleb",
        filename="embedding_model.ckpt",
    )
    print(f"  → {path}")
    return pathlib.Path(path)


def load_state_dict(ckpt_path: pathlib.Path) -> dict:
    try:
        import torch
    except ImportError:
        sys.exit("torch is not installed: pip install torch")

    sd = torch.load(str(ckpt_path), map_location="cpu")
    # SpeechBrain .ckpt files may wrap the state dict.
    if isinstance(sd, dict) and "model" in sd:
        sd = sd["model"]
    elif not isinstance(sd, dict):
        # Try to extract from a SpeechBrain Pretrainer checkpoint.
        if hasattr(sd, "state_dict"):
            sd = sd.state_dict()
        else:
            raise ValueError(f"Unexpected checkpoint format: {type(sd)}")
    return sd


# Key mapping table:
# (source_suffix, target_key)
# source_suffix is matched against the end of each key in the state dict.
KEY_MAP = [
    # ── TDNN block 0 (Conv idx=0, BN idx=2) ──────────────────────────────────
    ("blocks.0.conv.weight",              "blocks_0.weight"),
    ("blocks.0.conv.bias",                "blocks_0.bias"),
    ("blocks.2.norm.weight",              "blocks_2.weight"),
    ("blocks.2.norm.bias",                "blocks_2.bias"),
    ("blocks.2.norm.running_mean",        "blocks_2.running_mean"),
    ("blocks.2.norm.running_var",         "blocks_2.running_var"),
    # ── TDNN block 1 (Conv idx=3, BN idx=5) ──────────────────────────────────
    ("blocks.3.conv.weight",              "blocks_3.weight"),
    ("blocks.3.conv.bias",                "blocks_3.bias"),
    ("blocks.5.norm.weight",              "blocks_5.weight"),
    ("blocks.5.norm.bias",                "blocks_5.bias"),
    ("blocks.5.norm.running_mean",        "blocks_5.running_mean"),
    ("blocks.5.norm.running_var",         "blocks_5.running_var"),
    # ── TDNN block 2 (Conv idx=6, BN idx=8) ──────────────────────────────────
    ("blocks.6.conv.weight",              "blocks_6.weight"),
    ("blocks.6.conv.bias",                "blocks_6.bias"),
    ("blocks.8.norm.weight",              "blocks_8.weight"),
    ("blocks.8.norm.bias",                "blocks_8.bias"),
    ("blocks.8.norm.running_mean",        "blocks_8.running_mean"),
    ("blocks.8.norm.running_var",         "blocks_8.running_var"),
    # ── TDNN block 3 (Conv idx=9, BN idx=11) ─────────────────────────────────
    ("blocks.9.conv.weight",              "blocks_9.weight"),
    ("blocks.9.conv.bias",                "blocks_9.bias"),
    ("blocks.11.norm.weight",             "blocks_11.weight"),
    ("blocks.11.norm.bias",               "blocks_11.bias"),
    ("blocks.11.norm.running_mean",       "blocks_11.running_mean"),
    ("blocks.11.norm.running_var",        "blocks_11.running_var"),
    # ── TDNN block 4 (Conv idx=12, BN idx=14) ────────────────────────────────
    ("blocks.12.conv.weight",             "blocks_12.weight"),
    ("blocks.12.conv.bias",               "blocks_12.bias"),
    ("blocks.14.norm.weight",             "blocks_14.weight"),
    ("blocks.14.norm.bias",               "blocks_14.bias"),
    ("blocks.14.norm.running_mean",       "blocks_14.running_mean"),
    ("blocks.14.norm.running_var",        "blocks_14.running_var"),
    # ── Final linear layer (Linear idx=16) ───────────────────────────────────
    # SpeechBrain Linear stores weights in .w.weight / .w.bias.
    ("blocks.16.w.weight",                "blocks_16.weight"),
    ("blocks.16.w.bias",                  "blocks_16.bias"),
]

# Keys to skip silently (not needed at inference).
SKIP_SUFFIXES = {
    "num_batches_tracked",
}


def build_output_tensors(sd: dict) -> dict:
    """Map state-dict keys to the safetensors output dict."""
    import torch

    # Print all source keys once so the operator can debug mismatches.
    print("\nSource checkpoint keys:")
    for k in sorted(sd.keys()):
        print(f"  {k}")
    print()

    # Build a suffix → target lookup.
    suffix_map = {src: tgt for src, tgt in KEY_MAP}

    output = {}
    unmapped = []

    for src_key, tensor in sd.items():
        # Skip keys we don't need at inference.
        if any(src_key.endswith(s) for s in SKIP_SUFFIXES):
            continue

        # Match by suffix.
        matched = False
        for suffix, target in suffix_map.items():
            if src_key.endswith(suffix):
                output[target] = tensor.float().contiguous()
                matched = True
                break

        if not matched:
            unmapped.append(src_key)

    if unmapped:
        print("WARNING: the following source keys were NOT mapped (check KEY_MAP):")
        for k in unmapped:
            print(f"  {k}")
        print()

    # Validate expected keys are present.
    expected_targets = {tgt for _, tgt in KEY_MAP}
    missing = expected_targets - set(output.keys())
    if missing:
        print("ERROR: the following target keys could not be produced:")
        for k in sorted(missing):
            print(f"  {k}")
        sys.exit(
            "\nConversion failed. Check that KEY_MAP matches the actual ckpt keys above."
        )

    return output


def save_safetensors(tensors: dict, out_path: pathlib.Path) -> None:
    try:
        from safetensors.torch import save_file
    except ImportError:
        sys.exit("safetensors is not installed: pip install safetensors")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    save_file(tensors, str(out_path))
    size_mb = out_path.stat().st_size / 1024 / 1024
    print(f"Saved {len(tensors)} tensors → {out_path}  ({size_mb:.1f} MB)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--ckpt",
        type=pathlib.Path,
        default=None,
        help="Path to embedding_model.ckpt.  If omitted, downloads from HuggingFace.",
    )
    parser.add_argument(
        "--out",
        type=pathlib.Path,
        default=default_out_path(),
        help=f"Output safetensors path (default: {default_out_path()})",
    )
    args = parser.parse_args()

    ckpt_path: pathlib.Path = args.ckpt if args.ckpt is not None else download_ckpt()
    if not ckpt_path.exists():
        sys.exit(f"Checkpoint not found: {ckpt_path}")

    print(f"Loading {ckpt_path} …")
    sd = load_state_dict(ckpt_path)
    print(f"  Loaded {len(sd)} tensors.")

    print("Mapping keys …")
    output = build_output_tensors(sd)
    print(f"  Mapped {len(output)} tensors.")

    save_safetensors(output, args.out)
    print("\nDone.  NEOTH will activate the x-vector encoder on next startup.")


if __name__ == "__main__":
    main()
