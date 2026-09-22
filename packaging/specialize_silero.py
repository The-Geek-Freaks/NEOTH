#!/usr/bin/env python3
"""Hosted-only, fail-closed specialization of the W186 Silero ONNX model.

No branch is manually removed. The only graph mutation binds the production
`sr` input to scalar int64 16000 and fixes the two production input schemas.
ORT_ENABLE_BASIC performs the standard hosted control-flow reduction; a
candidate is written only after CPU ORT proves probability and recurrent-state
parity.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import tempfile
import traceback
from pathlib import Path
from typing import Any

INPUT, STATE, SR = "input", "state", "sr"
INPUT_SHAPE, STATE_SHAPE, SAMPLE_RATE = (1, 576), (2, 1, 128), 16_000
# This gate is deliberately strict during diagnosis. Do not loosen it without a
# hosted recurrent-drift receipt that separates input binding from ORT basic.
PROBABILITY_ATOL = PROBABILITY_RTOL = 1e-6
STATE_ATOL = STATE_RTOL = 1e-6
EXPECTED_ORIGINAL_SHA256 = "7ed98ddbad84ccac4cd0aeb3099049280713df825c610a8ed34543318f1b2c49"
EXPECTED_SOURCE_BLOB_SHA1 = "625ad8909b1abdba2292f3a9a10db6864fd5d561"
NO_TRANSPOSE_OPTIMIZER = ("TransposeOptimizer",)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def shape(value: Any) -> list[int | str | None]:
    return [dim.dim_value if dim.HasField("dim_value") else (dim.dim_param or None) for dim in value.type.tensor_type.shape.dim]


def value_summary(value: Any, onnx: Any) -> dict[str, Any]:
    return {"name": value.name, "elemType": onnx.TensorProto.DataType.Name(value.type.tensor_type.elem_type), "shape": shape(value)}


def graph_io(graph: Any, onnx: Any) -> dict[str, list[dict[str, Any]]]:
    return {"inputs": [value_summary(value, onnx) for value in graph.input], "outputs": [value_summary(value, onnx) for value in graph.output]}


def predicate_provenance(value: str, producers: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Follow the exact local condition producer chain, bounded against cycles."""
    chain: list[dict[str, Any]] = []
    pending, seen = [value], set()
    while pending and len(chain) < 16:
        current = pending.pop(0)
        if current in seen:
            continue
        seen.add(current)
        producer = producers.get(current)
        if producer is None:
            chain.append({"value": current, "kind": "graph-input-or-initializer"})
            continue
        chain.append({"value": current, **producer})
        pending.extend(producer["inputs"])
    if pending:
        chain.append({"kind": "truncated-after-16-values"})
    return chain


def if_nodes(graph: Any, onnx: Any, prefix: str = "") -> list[dict[str, Any]]:
    producers = {
        output: {"node": node.name or f"{node.op_type}@{index}", "opType": node.op_type, "inputs": list(node.input)}
        for index, node in enumerate(graph.node) for output in node.output
    }
    result: list[dict[str, Any]] = []
    for index, node in enumerate(graph.node):
        name = node.name or f"{node.op_type}@{index}"
        for attribute in node.attribute:
            if attribute.type == onnx.AttributeProto.GRAPH:
                result.extend(if_nodes(attribute.g, onnx, f"{prefix}{name}/"))
            elif attribute.type == onnx.AttributeProto.GRAPHS:
                for child_index, child in enumerate(attribute.graphs):
                    result.extend(if_nodes(child, onnx, f"{prefix}{name}/{attribute.name}[{child_index}]/"))
        if node.op_type == "If":
            if not node.input:
                raise ValueError(f"If node {prefix}{name} has no condition input")
            branches = {
                attribute.name: graph_io(attribute.g, onnx)
                for attribute in node.attribute
                if attribute.name in {"then_branch", "else_branch"} and attribute.type == onnx.AttributeProto.GRAPH
            }
            result.append({"path": f"{prefix}{name}", "conditionValue": node.input[0], "conditionProvenance": predicate_provenance(node.input[0], producers), "thenElse": branches})
    return result


def reject_external_data(model: Any, onnx: Any) -> None:
    def walk(graph: Any, path: str) -> None:
        for tensor in graph.initializer:
            if tensor.data_location == onnx.TensorProto.EXTERNAL or tensor.external_data:
                raise ValueError(f"external tensor data is forbidden: {path}{tensor.name}")
        for node in graph.node:
            for attribute in node.attribute:
                if attribute.type == onnx.AttributeProto.GRAPH:
                    walk(attribute.g, f"{path}{node.name or node.op_type}/")
                elif attribute.type == onnx.AttributeProto.GRAPHS:
                    for index, child in enumerate(attribute.graphs):
                        walk(child, f"{path}{node.name or node.op_type}/{attribute.name}[{index}]/")
    walk(model.graph, "")


def canonicalize(value: Any, element_type: int, dimensions: tuple[int, ...]) -> None:
    tensor = value.type.tensor_type
    tensor.elem_type = element_type
    del tensor.shape.dim[:]
    for dimension in dimensions:
        tensor.shape.dim.add().dim_value = dimension


def reject_nonstandard_nodes(model: Any, onnx: Any) -> None:
    def walk(graph: Any, path: str) -> None:
        for node in graph.node:
            if node.domain not in {"", "ai.onnx"}:
                raise ValueError(f"nonstandard/custom-domain node is forbidden: {path}{node.name or node.op_type} ({node.domain})")
            for attribute in node.attribute:
                if attribute.type == onnx.AttributeProto.GRAPH:
                    walk(attribute.g, f"{path}{node.name or node.op_type}/")
                elif attribute.type == onnx.AttributeProto.GRAPHS:
                    for index, child in enumerate(attribute.graphs):
                        walk(child, f"{path}{node.name or node.op_type}/{attribute.name}[{index}]/")
    walk(model.graph, "")


def op_type_counts(model: Any, onnx: Any) -> dict[str, int]:
    """Count every graph and nested control-flow branch for optimizer evidence."""
    counts: dict[str, int] = {}

    def walk(graph: Any) -> None:
        for node in graph.node:
            key = f"{node.domain or 'ai.onnx'}::{node.op_type}"
            counts[key] = counts.get(key, 0) + 1
            for attribute in node.attribute:
                if attribute.type == onnx.AttributeProto.GRAPH:
                    walk(attribute.g)
                elif attribute.type == onnx.AttributeProto.GRAPHS:
                    for child in attribute.graphs:
                        walk(child)

    walk(model.graph)
    return dict(sorted(counts.items()))


def specialize(model: Any, onnx: Any) -> Any:
    from onnx import helper

    graph = model.graph
    inputs = {value.name: value for value in graph.input}
    if set(inputs) != {INPUT, STATE, SR}:
        raise ValueError(f"unexpected original graph inputs: {sorted(inputs)!r}")
    sr = inputs[SR]
    if sr.type.tensor_type.elem_type != onnx.TensorProto.INT64 or shape(sr) != []:
        raise ValueError("sr must be a scalar int64 graph input")
    canonicalize(inputs[INPUT], onnx.TensorProto.FLOAT, INPUT_SHAPE)
    canonicalize(inputs[STATE], onnx.TensorProto.FLOAT, STATE_SHAPE)
    retained_inputs = [inputs[INPUT], inputs[STATE]]
    del graph.input[:]
    graph.input.extend(retained_inputs)
    retained_tensors = [tensor for tensor in graph.initializer if tensor.name != SR]
    del graph.initializer[:]
    graph.initializer.extend(retained_tensors)
    graph.initializer.append(helper.make_tensor(SR, onnx.TensorProto.INT64, [], [SAMPLE_RATE]))
    onnx.checker.check_model(model)
    reject_nonstandard_nodes(model, onnx)
    return model


def optimize_basic(bound_path: Path, optimized_path: Path, ort: Any, disabled_optimizers: tuple[str, ...] = ()) -> None:
    """Use the pinned ORT BASIC pass, optionally excluding exact named L1 transformers."""
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_BASIC
    options.optimized_model_filepath = str(optimized_path)
    session = ort.InferenceSession(str(bound_path), sess_options=options, providers=["CPUExecutionProvider"], disabled_optimizers=set(disabled_optimizers))
    if session.get_providers() != ["CPUExecutionProvider"]:
        raise ValueError("basic specialization requires CPUExecutionProvider as the only provider")
    if not optimized_path.is_file():
        raise ValueError("ORT basic optimization did not emit a serialized ONNX model")


def frames(np: Any) -> dict[str, list[Any]]:
    frame_samples, steps = 512, 256
    index = np.arange(frame_samples * steps, dtype=np.float32)
    speechlike = (0.55 * np.sin(2.0 * math.pi * 180.0 * index / SAMPLE_RATE)).astype(np.float32)
    noise = np.random.default_rng(0x5A17E).uniform(-0.7, 0.7, frame_samples * steps).astype(np.float32)
    clipped = np.where(index.astype(np.int64) % 4 < 2, 1.0, -1.0).astype(np.float32)
    silence = np.zeros(frame_samples * steps, dtype=np.float32)

    def with_carried_context(signal: Any) -> list[Any]:
        context = np.zeros(64, dtype=np.float32)
        windows = []
        for offset in range(0, signal.size, frame_samples):
            frame = signal[offset : offset + frame_samples]
            windows.append(np.concatenate((context, frame)).reshape(INPUT_SHAPE))
            context = frame[-64:].copy()
        return windows

    mixed = np.concatenate((speechlike[: 4 * frame_samples], noise[4 * frame_samples : 8 * frame_samples], clipped[8 * frame_samples : 12 * frame_samples], silence[12 * frame_samples :]))
    return {"silence": with_carried_context(silence), "speechlike": with_carried_context(speechlike), "noise": with_carried_context(noise), "clipped": with_carried_context(clipped), "mixed_recurrent": with_carried_context(mixed)}


def session(path: Path, ort: Any) -> Any:
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_DISABLE_ALL
    result = ort.InferenceSession(str(path), sess_options=options, providers=["CPUExecutionProvider"])
    if result.get_providers() != ["CPUExecutionProvider"]:
        raise ValueError("parity requires CPUExecutionProvider as the only provider")
    return result


def assert_model_contract(original: Any, candidate: Any) -> None:
    original_inputs = {item.name for item in original.get_inputs()}
    if original_inputs != {INPUT, STATE, SR}:
        raise ValueError(f"unexpected original runtime inputs: {sorted(original_inputs)!r}")
    candidate_inputs = {item.name: tuple(item.shape) for item in candidate.get_inputs()}
    if candidate_inputs != {INPUT: INPUT_SHAPE, STATE: STATE_SHAPE}:
        raise ValueError(f"candidate runtime inputs are not canonical: {candidate_inputs!r}")
    if len(original.get_outputs()) != 2 or len(candidate.get_outputs()) != 2:
        raise ValueError("models must expose probability plus recurrent-state outputs")


def parity(original_path: Path, bound_path: Path, candidate_paths: dict[str, Path], np: Any, ort: Any) -> dict[str, Any]:
    original, bound = session(original_path, ort), session(bound_path, ort)
    assert_model_contract(original, bound)
    pairs = {
        "originalVsBound": {"session": bound, "outputs": [{"label": "probability", "atol": PROBABILITY_ATOL, "rtol": PROBABILITY_RTOL}, {"label": "state", "atol": STATE_ATOL, "rtol": STATE_RTOL}]},
    }
    for name, path in candidate_paths.items():
        candidate = session(path, ort)
        assert_model_contract(original, candidate)
        pairs[f"originalVs{name}"] = {"session": candidate, "outputs": [{"label": "probability", "atol": PROBABILITY_ATOL, "rtol": PROBABILITY_RTOL}, {"label": "state", "atol": STATE_ATOL, "rtol": STATE_RTOL}]}
    for pair in pairs.values():
        pair["metrics"] = {output["label"]: {"maxAbsError": 0.0, "maxRelError": 0.0, "overToleranceElements": 0, "worstCase": None} for output in pair["outputs"]}
    comparisons: list[dict[str, Any]] = []
    for scenario, sequence in frames(np).items():
        nonzero = scenario == "mixed_recurrent"
        initial = np.linspace(-0.25, 0.25, int(np.prod(STATE_SHAPE)), dtype=np.float32).reshape(STATE_SHAPE) if nonzero else np.zeros(STATE_SHAPE, dtype=np.float32)
        original_state = initial.copy()
        pair_states = {name: initial.copy() for name in pairs}
        for step, audio in enumerate(sequence):
            source = original.run(None, {INPUT: audio, STATE: original_state, SR: np.asarray(SAMPLE_RATE, dtype=np.int64)})
            for label, outputs in (("original", source),):
                if len(outputs) != 2 or tuple(outputs[0].shape) != (1, 1) or tuple(outputs[1].shape) != STATE_SHAPE:
                    raise ValueError(f"{scenario}[{step}] {label} output shape is invalid")
                if outputs[0].dtype != np.float32 or outputs[1].dtype != np.float32:
                    raise ValueError(f"{scenario}[{step}] {label} output dtype is invalid")
                if not np.isfinite(outputs[0]).all() or not np.isfinite(outputs[1]).all():
                    raise ValueError(f"{scenario}[{step}] {label} returned non-finite output")
                if not ((outputs[0] >= 0.0).all() and (outputs[0] <= 1.0).all()):
                    raise ValueError(f"{scenario}[{step}] {label} probability is outside [0, 1]")
            for pair_name, pair in pairs.items():
                derived = pair["session"].run(None, {INPUT: audio, STATE: pair_states[pair_name]})
                for label, outputs in ((pair_name, derived),):
                    if len(outputs) != 2 or tuple(outputs[0].shape) != (1, 1) or tuple(outputs[1].shape) != STATE_SHAPE:
                        raise ValueError(f"{scenario}[{step}] {label} output shape is invalid")
                    if outputs[0].dtype != np.float32 or outputs[1].dtype != np.float32 or not np.isfinite(outputs[0]).all() or not np.isfinite(outputs[1]).all():
                        raise ValueError(f"{scenario}[{step}] {label} returned invalid output")
                    if not ((outputs[0] >= 0.0).all() and (outputs[0] <= 1.0).all()):
                        raise ValueError(f"{scenario}[{step}] {label} probability is outside [0, 1]")
                for output_index, output in enumerate(pair["outputs"]):
                    before, after = source[output_index], derived[output_index]
                    delta = np.abs(before - after)
                    rel = delta / np.maximum(np.abs(before), 1e-12)
                    metric = pair["metrics"][output["label"]]
                    maximum = float(np.max(delta))
                    metric["maxRelError"] = max(metric["maxRelError"], float(np.max(rel)))
                    # Preserve assert_allclose(before, after): its desired operand is after.
                    tolerance = output["atol"] + output["rtol"] * np.abs(after)
                    metric["overToleranceElements"] += int(np.count_nonzero(delta > tolerance))
                    if maximum > metric["maxAbsError"]:
                        flat_index = int(np.argmax(delta))
                        metric["maxAbsError"] = maximum
                        metric["worstCase"] = {"scenario": scenario, "step": step, "outputIndex": [int(index) for index in np.unravel_index(flat_index, delta.shape)], "before": float(before.flat[flat_index]), "after": float(after.flat[flat_index]), "absError": maximum, "relError": float(rel.flat[flat_index]), "inputContext": audio.reshape(-1)[:64].tolist(), "inputFrameSha256": hashlib.sha256(audio.tobytes()).hexdigest(), "referenceStateInputSha256": hashlib.sha256(original_state.tobytes()).hexdigest(), "comparedStateInputSha256": hashlib.sha256(pair_states[pair_name].tobytes()).hexdigest()}
                pair_states[pair_name] = derived[1]
            comparisons.append({"scenario": scenario, "step": step, "initialState": "nonzero" if nonzero else "zero"})
            original_state = source[1]
    result = {"provider": "CPUExecutionProvider", "intraOpThreads": 1, "interOpThreads": 1, "framesPerScenario": 256, "comparisons": comparisons, "pairs": {name: {"probability": {"rtol": PROBABILITY_RTOL, "atol": PROBABILITY_ATOL, **pair["metrics"]["probability"]}, "state": {"rtol": STATE_RTOL, "atol": STATE_ATOL, **pair["metrics"]["state"]}} for name, pair in pairs.items()}}
    return result


def select_strict_variant(result: dict[str, Any], preference: tuple[str, ...]) -> str | None:
    """Choose deterministically only from fully evaluated, strict-passing variants."""
    binding = result["pairs"]["originalVsBound"]
    if binding["probability"]["overToleranceElements"] or binding["state"]["overToleranceElements"]:
        return None
    for variant in preference:
        pair = result["pairs"][f"originalVs{variant}"]
        if not pair["probability"]["overToleranceElements"] and not pair["state"]["overToleranceElements"]:
            return variant
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-blob-sha", required=True)
    args = parser.parse_args()
    receipt: dict[str, Any] = {"schema": "w186-silero-specialization-receipt/v1", "status": "failed", "sourceRevision": args.source_revision, "sourceBlobSha": args.source_blob_sha, "productionContract": {"input": [1, 576], "state": [2, 1, 128], "sr": {"dtype": "int64", "shape": [], "value": SAMPLE_RATE}}, "packages": {}}
    try:
        import numpy as np
        import onnx
        import onnxruntime as ort

        receipt["packages"] = {distribution.metadata["Name"]: distribution.version for distribution in importlib.metadata.distributions() if distribution.metadata.get("Name")}
        if len(args.source_blob_sha) != 40 or any(character not in "0123456789abcdef" for character in args.source_blob_sha.lower()):
            raise ValueError("source blob SHA must be a 40-character hexadecimal Git object id")
        if args.source_blob_sha.lower() != EXPECTED_SOURCE_BLOB_SHA1:
            raise ValueError("source blob SHA does not match the pinned Silero provenance")
        if not args.input.is_file():
            raise ValueError(f"input model does not exist: {args.input}")
        if args.output.exists():
            raise ValueError(f"refusing to overwrite existing candidate: {args.output}")
        original_sha256 = file_sha256(args.input)
        if original_sha256.lower() != EXPECTED_ORIGINAL_SHA256:
            raise ValueError("input model SHA-256 does not match the pinned Silero artifact")
        receipt["original"] = {"path": str(args.input), "sha256": original_sha256}
        original = onnx.load_model(str(args.input), load_external_data=False)
        reject_external_data(original, onnx)
        reject_nonstandard_nodes(original, onnx)
        receipt["before"] = {"io": graph_io(original.graph, onnx), "ifNodes": if_nodes(original.graph, onnx), "opTypeCounts": op_type_counts(original, onnx)}
        with tempfile.TemporaryDirectory(prefix="w186-silero-") as directory:
            bound = Path(directory) / "bound-16k.onnx"
            onnx.save_model(specialize(original, onnx), str(bound))
            bound_model = onnx.load_model(str(bound), load_external_data=False)
            receipt["bound"] = {"io": graph_io(bound_model.graph, onnx), "ifNodes": if_nodes(bound_model.graph, onnx), "opTypeCounts": op_type_counts(bound_model, onnx)}
            variants = (("BasicDefault", ()), ("BasicNoTranspose", NO_TRANSPOSE_OPTIMIZER))
            candidate_paths: dict[str, Path] = {}
            receipt["optimizerVariants"] = []
            for name, disabled_optimizers in variants:
                candidate_path = Path(directory) / f"{name}.onnx"
                optimize_basic(bound, candidate_path, ort, disabled_optimizers)
                derived = onnx.load_model(str(candidate_path), load_external_data=False)
                onnx.checker.check_model(derived)
                reject_external_data(derived, onnx)
                reject_nonstandard_nodes(derived, onnx)
                after = {"io": graph_io(derived.graph, onnx), "ifNodes": if_nodes(derived.graph, onnx), "opTypeCounts": op_type_counts(derived, onnx)}
                receipt["optimizerVariants"].append({"name": name, "engine": "onnxruntime", "source": "https://github.com/microsoft/onnxruntime/tree/v1.19.2", "graphOptimizationLevel": "ORT_ENABLE_BASIC", "provider": "CPUExecutionProvider", "intraOpThreads": 1, "interOpThreads": 1, "disabledOptimizers": list(disabled_optimizers), "after": after})
                if after["ifNodes"]:
                    raise ValueError(f"{name} left If control flow; candidate is unsafe for tract 0.23.8")
                candidate_paths[name] = candidate_path
            receipt["parity"] = parity(args.input, bound, candidate_paths, np, ort)
            preference = tuple(name for name, _ in variants)
            selected = select_strict_variant(receipt["parity"], preference)
            receipt["candidateSelection"] = {"preference": list(preference), "selected": selected, "reason": "first fully evaluated variant with zero strict-tolerance violations for probability and recurrent state"}
            if selected is None:
                failures = [f"{pair_name}.{label}" for pair_name, pair in receipt["parity"]["pairs"].items() for label, metric in pair.items() if metric["overToleranceElements"]]
                raise AssertionError(f"no specialization variant passed strict parity after complete diagnostic run: {', '.join(failures)}")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            os.replace(candidate_paths[selected], args.output)
        receipt["candidate"] = {"path": str(args.output), "sha256": file_sha256(args.output)}
        receipt["status"] = "passed"
    except BaseException as error:
        receipt["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if receipt["status"] != "passed":
        raise SystemExit(receipt["error"]["message"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
