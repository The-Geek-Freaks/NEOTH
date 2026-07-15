#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("build_release_self_knowledge.py")


def run(
    argv: list[str],
    cwd: Path,
    *,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if env:
        environment.update(env)
    return subprocess.run(
        argv,
        cwd=cwd,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )


class ReleaseSelfKnowledgeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        run(["git", "init", "-q"], self.repo)
        run(["git", "config", "user.email", "test@example.invalid"], self.repo)
        run(["git", "config", "user.name", "NEOTH Test"], self.repo)
        (self.repo / "src").mkdir()
        (self.repo / "src" / "lib.rs").write_text("pub fn neoth() {}\n", encoding="utf-8")
        (self.repo / "src" / "credentials.rs").write_text(
            "pub fn public_credential_policy() {}\n", encoding="utf-8"
        )
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "architecture.md").write_text(
            "# Architecture\n\nNEOTH routes verified work through explicit gates.\n",
            encoding="utf-8",
        )
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts" / "augment_graphify_tracked_code.py").write_text(
            SCRIPT.with_name("augment_graphify_tracked_code.py").read_text(encoding="utf-8"),
            encoding="utf-8",
            newline="\n",
        )
        run(
            [
                "git",
                "add",
                "src/lib.rs",
                "src/credentials.rs",
                "docs/architecture.md",
                "scripts/augment_graphify_tracked_code.py",
            ],
            self.repo,
        )
        run(["git", "commit", "-qm", "fixture"], self.repo)
        self.head = run(["git", "rev-parse", "HEAD"], self.repo).stdout.strip()
        self.fake_site = Path(self.temp.name) / "fake-site"
        fake_graphify = self.fake_site / "graphify"
        fake_graphify.mkdir(parents=True)
        (fake_graphify / "__init__.py").write_text("", encoding="utf-8")
        fake_distribution = self.fake_site / "graphifyy_fixture-0.8.41.dist-info"
        fake_distribution.mkdir()
        (fake_distribution / "METADATA").write_text(
            "Metadata-Version: 2.1\n"
            "Name: graphifyy-fixture\n"
            "Version: 0.8.41\n",
            encoding="utf-8",
        )
        (fake_graphify / "detect.py").write_text(
            """
import json
import os
from enum import Enum
from pathlib import Path

CODE_EXTENSIONS = {'.py', '.rs'}

class FileType(Enum):
    CODE = 'code'

def classify_file(path):
    path = Path(path)
    if path.suffix.lower() in CODE_EXTENSIONS:
        return FileType.CODE
    try:
        if path.read_bytes().startswith(b'#!'):
            return FileType.CODE
    except OSError:
        pass
    return None

def detect(root, *, follow_symlinks, google_workspace):
    root = Path(root).resolve()
    documents = [str(root / 'docs' / 'architecture.md')]
    code = [
        str(root / 'src' / 'lib.rs'),
        str(root / 'scripts' / 'augment_graphify_tracked_code.py'),
    ]
    skipped_sensitive = []
    if not os.environ.get('FAKE_GRAPHIFY_DETECT_OMIT_CODE'):
        code.append(str(root / 'src' / 'credentials.rs'))
    else:
        skipped_sensitive.append(str(root / 'src' / 'credentials.rs'))
    if os.environ.get('FAKE_GRAPHIFY_SKIP_SENSITIVE_DOCUMENT'):
        skipped_sensitive.append(str(root / 'docs' / 'credentials.md'))
    if os.environ.get('FAKE_DETECT_EXTRA_DOCUMENT'):
        documents.append(str(root / 'docs' / 'selected.md'))
    videos = []
    if os.environ.get('FAKE_DETECT_VIDEO'):
        videos.append(str(root / 'media' / 'demo.mp4'))
    return {
        'files': {
            'code': code,
            'document': documents,
            'paper': [],
            'image': [],
            'video': videos,
        },
        'skipped_sensitive': skipped_sensitive,
    }

def save_manifest(files, manifest_path, *, kind, root):
    path = Path(manifest_path)
    manifest = json.loads(path.read_text(encoding='utf-8'))
    for raw in files['code']:
        relative = Path(raw).resolve().relative_to(Path(root).resolve()).as_posix()
        manifest[relative] = {
            'mtime': 1,
            'ast_hash': 'c' * 32,
            'semantic_hash': '',
        }
    path.write_text(json.dumps(manifest), encoding='utf-8')
""".lstrip(),
            encoding="utf-8",
        )
        (fake_graphify / "build.py").write_text(
            """
def _dedupe(items, fields):
    seen = set()
    result = []
    for item in items:
        key = tuple(item.get(field) for field in fields)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result

def dedupe_nodes(nodes):
    return _dedupe(nodes, ('id',))

def dedupe_edges(edges):
    return _dedupe(edges, ('source', 'target', 'type'))
""".lstrip(),
            encoding="utf-8",
        )
        (fake_graphify / "extract.py").write_text(
            """
from pathlib import Path

def _get_extractor(path):
    return object() if Path(path).suffix.lower() in {'.py', '.rs'} else None

def extract(paths, cache_root=None, *, parallel=True, max_workers=None):
    return {
        'nodes': [
            {
                'id': 'augmented_' + path.stem,
                'label': path.stem,
                'source_file': str(path),
            }
            for path in paths
        ],
        'edges': [],
        'input_tokens': 0,
        'output_tokens': 0,
    }
""".lstrip(),
            encoding="utf-8",
        )
        self.fake = Path(self.temp.name) / "fake_graphify.py"
        self.fake.write_text(
            """
import json
import os
import importlib.metadata as metadata
from pathlib import Path
import re
import sys
import unicodedata
if '--version' in sys.argv:
    print(f"graphify {metadata.version('graphifyy-fixture')}")
    raise SystemExit(0)
out = Path.cwd() / 'graphify-out'
out.mkdir(parents=True, exist_ok=True)
args = sys.argv[1:]
with (out / 'pipeline-log.jsonl').open('a', encoding='utf-8') as handle:
    handle.write(json.dumps(args) + '\\n')
skip = os.environ.get('FAKE_GRAPHIFY_SKIP', '')
if args[0] == 'extract':
    semantic = '' if os.environ.get('FAKE_GRAPHIFY_OMIT_SEMANTIC') else 'b' * 32
    source_file = str((Path.cwd() / 'src' / 'lib.rs').resolve())
    file_id = re.sub(
        r'_+',
        '_',
        re.sub(r'[^\\w]+', '_', unicodedata.normalize('NFKC', source_file)),
    ).strip('_').casefold()
    (out / 'graph.json').write_text(json.dumps({
      'nodes': [
        {'id':file_id,'label':'lib.rs','source_file':source_file,'_origin':'ast'},
        {'id':'n2','label':'Runtime'}
      ],
      'edges': [{'source':file_id,'target':'n2','type':'CONTAINS','source_file':source_file}]
    }), encoding='utf-8')
    manifest = {
      'src/lib.rs': {'mtime': 1, 'ast_hash':'a' * 32, 'semantic_hash': ''},
      'scripts/augment_graphify_tracked_code.py': {
        'mtime': 1, 'ast_hash':'d' * 32, 'semantic_hash': ''
      },
      'docs/architecture.md': {'mtime': 1, 'ast_hash':'', 'semantic_hash': semantic}
    }
    if not os.environ.get('FAKE_GRAPHIFY_DETECT_OMIT_CODE'):
        manifest['src/credentials.rs'] = {
          'mtime': 1, 'ast_hash':'c' * 32, 'semantic_hash': ''
        }
    if os.environ.get('FAKE_GRAPHIFY_EXTRA_MANIFEST'):
        manifest['.venv/foreign.md'] = {'mtime': 1, 'ast_hash':'', 'semantic_hash':'e' * 32}
    (out / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
elif args[0] == 'cluster-only':
    if skip == 'cluster-only':
        raise SystemExit(0)
    raw = json.loads((out / 'graph.json').read_text(encoding='utf-8'))
    (out / 'graph.json').write_text(json.dumps({
      'directed': raw.get('directed', False),
      'multigraph': False,
      'nodes': raw['nodes'],
      'links': raw['edges'],
    }), encoding='utf-8')
    (out / 'GRAPH_REPORT.md').write_text('# Graph report\\n\\nNEOTH contains the runtime.\\n', encoding='utf-8')
    (out / '.graphify_analysis.json').write_text(json.dumps({'communities': {'0':[node['id'] for node in raw['nodes']]}}), encoding='utf-8')
    (out / '.graphify_labels.json').write_text(json.dumps({'0':'Runtime'}), encoding='utf-8')
    (out / 'graph.html').write_text('<!doctype html><title>NEOTH graph</title>', encoding='utf-8')
elif args[:1] == ['export']:
    mode = args[1]
    if skip == mode:
        raise SystemExit(0)
    if mode == 'html':
        (out / 'graph.html').write_text('<!doctype html><title>NEOTH graph</title>', encoding='utf-8')
    elif mode == 'wiki':
        (out / 'wiki').mkdir(parents=True, exist_ok=True)
        (out / 'wiki' / 'index.md').write_text('# NEOTH Wiki\\n\\n[[Runtime]]\\n', encoding='utf-8')
    elif mode == 'obsidian':
        (out / 'obsidian').mkdir(parents=True, exist_ok=True)
        (out / 'obsidian' / 'Runtime.md').write_text('# Runtime\\n\\nNEOTH runtime details.\\n', encoding='utf-8')
        (out / 'obsidian' / 'graph.canvas').write_text('{}', encoding='utf-8')
    elif mode == 'svg':
        (out / 'graph.svg').write_text('<svg xmlns="http://www.w3.org/2000/svg"/>', encoding='utf-8')
    elif mode == 'graphml':
        (out / 'graph.graphml').write_text('<graphml/>', encoding='utf-8')
else:
    raise SystemExit(2)
""".strip()
            + "\n",
            encoding="utf-8",
        )
        self.snapshot = Path(self.temp.name) / "self-knowledge"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def build(
        self,
        *,
        check: bool = True,
        env: dict[str, str] | None = None,
        output: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        build_env = {
            "PYTHONPATH": os.pathsep.join(
                part
                for part in (str(self.fake_site), os.environ.get("PYTHONPATH", ""))
                if part
            )
        }
        if env:
            build_env.update(env)
        return run(
            [
                sys.executable,
                str(SCRIPT),
                "build",
                "--repo",
                str(self.repo),
                "--output",
                str(output or self.snapshot),
                "--version",
                "1.0.0",
                "--graphify-bin",
                sys.executable,
                "--graphify-launcher-arg",
                str(self.fake),
                "--graphify-backend",
                "fixture-backend",
                "--graphify-model",
                "fixture-model",
                "--graphify-python-bin",
                sys.executable,
                "--graphify-distribution",
                "graphifyy-fixture",
            ],
            self.repo,
            check=check,
            env=build_env,
        )

    def verify(self, *extra: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return run(
            [
                sys.executable,
                str(SCRIPT),
                "verify",
                "--snapshot",
                str(self.snapshot),
                *extra,
            ],
            self.repo,
            check=check,
        )

    def reseal_payload_file(self, relative_path: str) -> None:
        payload = self.snapshot / relative_path
        manifest_path = self.snapshot / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entry = next(item for item in manifest["files"] if item["path"] == relative_path)
        contents = payload.read_bytes()
        entry["bytes"] = len(contents)
        entry["sha256"] = hashlib.sha256(contents).hexdigest()
        digest = hashlib.sha256()
        for item in sorted(manifest["files"], key=lambda candidate: candidate["path"]):
            digest.update(
                (
                    f"{item['path']}\0{item['sha256']}\0{item['bytes']}\0"
                    f"{item['role']}\n"
                ).encode("utf-8")
            )
        manifest["payload_sha256"] = digest.hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    def test_build_binds_head_source_and_all_required_exports(self) -> None:
        self.build()
        manifest = json.loads((self.snapshot / "manifest.json").read_text(encoding="utf-8"))
        paths = {item["path"] for item in manifest["files"]}
        self.assertEqual(manifest["source_head"], self.head)
        self.assertTrue(
            {
                "graph.json",
                "GRAPH_REPORT.md",
                "graph.html",
                "graph.svg",
                "graph.graphml",
                "graphify-manifest.json",
                "SOURCE_MANIFEST.json",
                "GENERATION_RECEIPT.json",
                "wiki/index.md",
                "obsidian/Runtime.md",
            }.issubset(paths)
        )
        verified = self.verify(
            "--repo",
            str(self.repo),
            "--expected-head",
            self.head,
            "--expected-version",
            "1.0.0",
        )
        self.assertIn("verified", verified.stdout)
        receipt = json.loads(
            (self.snapshot / "GENERATION_RECEIPT.json").read_text(encoding="utf-8")
        )
        self.assertEqual(receipt["graphify_backend"], "fixture-backend")
        self.assertEqual(receipt["graphify_model"], "fixture-model")
        toolchain = receipt["toolchain"]
        self.assertTrue(toolchain["rustc_verbose_version"].startswith("rustc "))
        self.assertTrue(toolchain["cargo_version"].startswith("cargo "))
        rust_release = next(
            line.removeprefix("release: ")
            for line in toolchain["rustc_verbose_version"].splitlines()
            if line.startswith("release: ")
        )
        self.assertEqual(toolchain["cargo_version"].split()[1], rust_release)
        inventory_core = {
            "schema_version": toolchain["schema_version"],
            "python_implementation": toolchain["python_implementation"],
            "python_version": toolchain["python_version"],
            "rustc_verbose_version": toolchain["rustc_verbose_version"],
            "cargo_version": toolchain["cargo_version"],
            "packages": toolchain["packages"],
        }
        self.assertEqual(
            hashlib.sha256(
                json.dumps(inventory_core, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest(),
            toolchain["inventory_sha256"],
        )
        self.assertEqual(
            receipt["graphify_toolchain_sha256"],
            toolchain["inventory_sha256"],
        )
        self.assertEqual(len(receipt["pipeline"]), 7)
        self.assertIn("--no-cluster", receipt["pipeline"][0])
        self.assertEqual(
            receipt["pipeline"][2][-3:],
            ["html", "--graph", "graphify-out/graph.json"],
        )
        graph_text = (self.snapshot / "graph.json").read_text(encoding="utf-8")
        graph = json.loads(graph_text)
        self.assertNotIn(str(self.repo), graph_text)
        anchor = next(node for node in graph["nodes"] if node["label"] == "lib.rs")
        self.assertEqual(anchor["source_file"], "src/lib.rs")
        self.assertEqual(anchor["id"], "src_lib_rs")
        graphify_manifest = json.loads(
            (self.snapshot / "graphify-manifest.json").read_text(encoding="utf-8")
        )
        node_sources = {
            node.get("source_file")
            for node in graph["nodes"]
            if isinstance(node, dict) and node.get("source_file")
        }
        self.assertEqual(set(graphify_manifest), node_sources)

    def test_mismatched_cargo_provenance_fails_closed(self) -> None:
        self.build()
        path = self.snapshot / "GENERATION_RECEIPT.json"
        receipt = json.loads(path.read_text(encoding="utf-8"))
        receipt["toolchain"]["cargo_version"] = (
            "cargo 0.0.0 (ea2d97820 2025-10-10)"
        )
        path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self.reseal_payload_file("GENERATION_RECEIPT.json")
        result = self.verify(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cargo and rustc release versions disagree", result.stderr)

    def test_detector_omitted_tracked_code_is_locally_augmented(self) -> None:
        self.build(env={"FAKE_GRAPHIFY_DETECT_OMIT_CODE": "1"})
        receipt = json.loads(
            (self.snapshot / "GENERATION_RECEIPT.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(receipt["pipeline"]), 8)
        self.assertTrue(
            receipt["pipeline"][1][1]
            .replace("\\", "/")
            .endswith("scripts/augment_graphify_tracked_code.py")
        )
        graphify_manifest = json.loads(
            (self.snapshot / "graphify-manifest.json").read_text(encoding="utf-8")
        )
        self.assertRegex(
            graphify_manifest["src/credentials.rs"]["ast_hash"],
            r"^[0-9a-f]{32}$",
        )
        self.verify()

    def test_sensitive_non_code_omission_fails_closed(self) -> None:
        (self.repo / "docs" / "credentials.md").write_text(
            "# Public credential architecture\n",
            encoding="utf-8",
        )
        run(["git", "add", "docs/credentials.md"], self.repo)
        run(["git", "commit", "-qm", "sensitive document fixture"], self.repo)

        result = self.build(
            check=False,
            env={"FAKE_GRAPHIFY_SKIP_SENSITIVE_DOCUMENT": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "sensitive-looking tracked inputs that the local AST recovery cannot represent",
            result.stderr,
        )

    def test_tampered_payload_fails_closed(self) -> None:
        self.build()
        (self.snapshot / "GRAPH_REPORT.md").write_text("tampered\n", encoding="utf-8")
        result = self.verify(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed integrity", result.stderr)

    def test_wrong_expected_head_fails_closed(self) -> None:
        self.build()
        result = self.verify("--expected-head", "0" * 40, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected", result.stderr)

    def test_dirty_tracked_tree_is_not_bound_to_head(self) -> None:
        (self.repo / "src" / "lib.rs").write_text("pub fn changed() {}\n", encoding="utf-8")
        result = self.build(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tracked, untracked, or ignored", result.stderr)

    def test_untracked_input_is_not_silently_graphed(self) -> None:
        (self.repo / "untracked.md").write_text("unbound input\n", encoding="utf-8")
        result = self.build(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tracked, untracked, or ignored", result.stderr)

    def test_ignored_input_is_not_silently_graphed(self) -> None:
        (self.repo / ".git" / "info" / "exclude").write_text(".venv/\n", encoding="utf-8")
        (self.repo / ".venv").mkdir()
        (self.repo / ".venv" / "foreign.md").write_text("ignored input\n", encoding="utf-8")
        result = self.build(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tracked, untracked, or ignored", result.stderr)

    def test_graphify_manifest_cannot_name_untracked_inputs(self) -> None:
        result = self.build(check=False, env={"FAKE_GRAPHIFY_EXTRA_MANIFEST": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the tracked release source tree", result.stderr)

    def test_detector_exclusions_do_not_make_the_release_impossible(self) -> None:
        (self.repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
        # Keep path casing consistent with the fixture's existing `src/`
        # directory; Windows cannot represent sibling `src` and `SRC` trees.
        dist = self.repo / "src" / "dist"
        dist.mkdir(parents=True)
        (dist / "README.md").write_text("generated distribution notes\n", encoding="utf-8")
        run(["git", "add", "pnpm-lock.yaml", "src/dist/README.md"], self.repo)
        run(["git", "commit", "-qm", "tracked detector exclusions"], self.repo)

        self.build()
        source = json.loads(
            (self.snapshot / "SOURCE_MANIFEST.json").read_text(encoding="utf-8")
        )
        source_paths = {entry["path"] for entry in source["files"]}
        graphify_manifest = json.loads(
            (self.snapshot / "graphify-manifest.json").read_text(encoding="utf-8")
        )
        self.assertIn("pnpm-lock.yaml", source_paths)
        self.assertIn("src/dist/README.md", source_paths)
        self.assertNotIn("pnpm-lock.yaml", graphify_manifest)
        self.assertNotIn("src/dist/README.md", graphify_manifest)

    def test_every_detector_selected_input_must_reach_the_manifest(self) -> None:
        (self.repo / "docs" / "selected.md").write_text(
            "# Selected\n\nThis input must be semantically extracted.\n",
            encoding="utf-8",
        )
        run(["git", "add", "docs/selected.md"], self.repo)
        run(["git", "commit", "-qm", "selected input"], self.repo)
        result = self.build(
            check=False,
            env={"FAKE_DETECT_EXTRA_DOCUMENT": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pinned detector selection", result.stderr)

    def test_detector_classified_code_without_ast_extractor_fails_closed(self) -> None:
        tool = self.repo / "bin" / "neoth-tool"
        tool.parent.mkdir()
        tool.write_text("#!/bin/sh\necho neoth\n", encoding="utf-8")
        run(["git", "add", "bin/neoth-tool"], self.repo)
        run(["git", "commit", "-qm", "extensionless tool"], self.repo)

        result = self.build(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no pinned AST extractor", result.stderr)

    def test_untranscribed_detector_video_fails_closed(self) -> None:
        media = self.repo / "media" / "demo.mp4"
        media.parent.mkdir()
        media.write_bytes(b"not-a-real-video")
        run(["git", "add", "media/demo.mp4"], self.repo)
        run(["git", "commit", "-qm", "media fixture"], self.repo)

        result = self.build(check=False, env={"FAKE_DETECT_VIDEO": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no transcript phase", result.stderr)

    def test_missing_required_export_fails_closed(self) -> None:
        result = self.build(check=False, env={"FAKE_GRAPHIFY_SKIP": "svg"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("svg", result.stderr)

    def test_partial_semantic_extraction_fails_closed(self) -> None:
        result = self.build(
            check=False,
            env={"FAKE_GRAPHIFY_OMIT_SEMANTIC": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("semantic extraction", result.stderr)

    def test_output_below_graphify_or_git_metadata_is_rejected(self) -> None:
        graphify_result = self.build(
            check=False,
            output=self.repo / "graphify-out" / "nested" / "snapshot",
        )
        self.assertNotEqual(graphify_result.returncode, 0)
        self.assertIn("unsafe snapshot output", graphify_result.stderr)
        git_result = self.build(
            check=False,
            output=self.repo / ".git" / "objects" / "snapshot",
        )
        self.assertNotEqual(git_result.returncode, 0)
        self.assertIn(".git", git_result.stderr)

    def test_snapshot_root_symlink_is_rejected(self) -> None:
        self.build()
        linked = Path(self.temp.name) / "linked-self-knowledge"
        try:
            linked.symlink_to(self.snapshot, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"directory symlinks unavailable: {error}")
        result = self.verify("--snapshot", str(linked), check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink/junction", result.stderr)

    def test_unknown_manifest_field_fails_closed(self) -> None:
        self.build()
        path = self.snapshot / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["surprise"] = True
        path.write_text(json.dumps(manifest), encoding="utf-8")
        result = self.verify(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("closed schema", result.stderr)


if __name__ == "__main__":
    unittest.main()
