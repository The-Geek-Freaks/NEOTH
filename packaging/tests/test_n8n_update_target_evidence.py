import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).parents[1] / "n8n_update_target_evidence.py"
SPEC = importlib.util.spec_from_file_location("n8n_update_target_evidence", MODULE_PATH)
assert SPEC and SPEC.loader
TARGET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TARGET)


def raw_index(children=None):
    children = children or TARGET.EXPECTED_CHILDREN
    return json.dumps({
        "schemaVersion": 2,
        "mediaType": TARGET.OCI_INDEX_MEDIA_TYPE,
        "manifests": [
            {"mediaType": TARGET.OCI_MANIFEST_MEDIA_TYPE, "digest": digest, "platform": {"os": os_name, "architecture": architecture}}
            for (os_name, architecture), digest in children.items()
        ],
    }, sort_keys=True).encode()


class N8nUpdateTargetEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.original_digest = TARGET.DIGEST

    def tearDown(self):
        TARGET.DIGEST = self.original_digest

    def expect_index_rejection(self, body, header, reason):
        TARGET.DIGEST = "sha256:" + hashlib.sha256(body).hexdigest()
        with self.assertRaisesRegex(TARGET.VerificationError, reason):
            TARGET.validate_index(body, header)

    def test_index_rejects_wrong_digest_before_parsing(self):
        body = raw_index()
        self.expect_index_rejection(body, "sha256:" + "0" * 64, "index_header_digest_mismatch")

    def test_index_rejects_wrong_platform_and_shape(self):
        wrong_platform = raw_index({("linux", "amd64"): TARGET.EXPECTED_CHILDREN[("linux", "amd64")], ("linux", "s390x"): TARGET.EXPECTED_CHILDREN[("linux", "arm64")]})
        self.expect_index_rejection(wrong_platform, "sha256:" + hashlib.sha256(wrong_platform).hexdigest(), "index_platform_children_mismatch")
        malformed = b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":{}}'
        self.expect_index_rejection(malformed, "sha256:" + hashlib.sha256(malformed).hexdigest(), "index_manifest_count_invalid")

    def test_release_rejects_mutable_ref(self):
        release = json.dumps({"tag_name": "n8n@2.40.7", "draft": False, "prerelease": False, "target_commitish": "stable"}).encode()
        ref = json.dumps({"ref": "refs/tags/n8n@2.40.7", "object": {"type": "commit", "sha": TARGET.SOURCE_COMMIT}}).encode()
        with self.assertRaisesRegex(TARGET.VerificationError, "release_source_ref_invalid"):
            TARGET.validate_release(release, ref)
