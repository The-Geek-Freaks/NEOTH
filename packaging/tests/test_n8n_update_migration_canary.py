import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import n8n_update_migration_canary as canary


class GateBoundaryTests(unittest.TestCase):
    labels = {"io.neoth.w1601": "owned", "io.neoth.w1601.run": "10", "io.neoth.w1601.attempt": "2"}

    def setUp(self):
        self.environment = patch.dict(os.environ, {"GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "2"})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()

    def archive(self, entries):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "fixture.tar"
        with tarfile.open(path, "w") as value:
            for name, body, mode in entries:
                item = tarfile.TarInfo(name)
                item.mode = mode
                if body is None:
                    item.type, item.size = tarfile.DIRTYPE, 0
                    value.addfile(item)
                else:
                    item.size = len(body)
                    value.addfile(item, io.BytesIO(body))
        return directory, path

    def test_archive_normalizes_root_alias_but_rejects_duplicate_alias(self):
        directory, path = self.archive([(".", None, 0o755), ("./node", b"x", 0o600)])
        with directory:
            self.assertIsInstance(canary.safe_archive_manifest(path), str)
        directory, path = self.archive([("node", b"x", 0o600), ("./node", b"x", 0o600)])
        with directory, self.assertRaisesRegex(canary.Failure, "archive_member_unsafe"):
            canary.safe_archive_manifest(path)
        directory, path = self.archive([(".", b"", 0o600)])
        with directory, self.assertRaisesRegex(canary.Failure, "archive_member_unsafe"):
            canary.safe_archive_manifest(path)

    def test_archive_manifest_binds_rename_content_mode_and_ignores_order(self):
        first_dir, first = self.archive([("a", b"one", 0o600), ("b", b"two", 0o644)])
        order_dir, reordered = self.archive([("b", b"two", 0o644), ("a", b"one", 0o600)])
        rename_dir, renamed = self.archive([("c", b"one", 0o600), ("b", b"two", 0o644)])
        content_dir, content = self.archive([("a", b"ONE", 0o600), ("b", b"two", 0o644)])
        mode_dir, mode = self.archive([("a", b"one", 0o640), ("b", b"two", 0o644)])
        with first_dir, order_dir, rename_dir, content_dir, mode_dir:
            baseline = canary.safe_archive_manifest(first)
            self.assertEqual(baseline, canary.safe_archive_manifest(reordered))
            self.assertNotEqual(baseline, canary.safe_archive_manifest(renamed))
            self.assertNotEqual(baseline, canary.safe_archive_manifest(content))
            self.assertNotEqual(baseline, canary.safe_archive_manifest(mode))

    def test_archive_rejects_traversal_and_count_size_caps(self):
        directory, path = self.archive([("../escape", b"x", 0o600)])
        with directory, self.assertRaisesRegex(canary.Failure, "archive_member_unsafe"):
            canary.safe_archive_manifest(path)
        directory, path = self.archive([("one", b"x", 0o600), ("two", b"x", 0o600)])
        with directory, patch.object(canary, "MAX_ARCHIVE_MEMBERS", 1):
            with self.assertRaisesRegex(canary.Failure, "archive_member_count"):
                canary.safe_archive_manifest(path)
        directory, path = self.archive([("one", b"x" * 8, 0o600)])
        with directory, patch.object(canary, "MAX_MEMBER_BYTES", 4):
            with self.assertRaisesRegex(canary.Failure, "archive_member_unsafe"):
                canary.safe_archive_manifest(path)

    def runtime(self, identifier="a" * 64, image="image", volume="w1601_n8n_" + "b" * 16, phase="seed", name="seed"):
        labels = dict(self.labels, **{"io.neoth.w1601.phase": phase})
        config = {"Image": image, "Labels": labels, "Entrypoint": ["node"], "Cmd": ["-e", "setInterval(() => {}, 2147483647)"]}
        return {"Id": identifier, "Name": f"/{name}", "Config": config,
                "HostConfig": {"NetworkMode": "none", "PortBindings": {}, "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}, "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=64m"}},
                "NetworkSettings": {"Ports": {}}, "Mounts": [{"Type": "volume", "Name": volume, "Destination": "/home/node/.n8n", "Source": "/var/lib/docker/volumes/x", "RW": True}, {"Type": "tmpfs", "Destination": "/tmp"}], "State": {"Running": False}}

    def test_post_effect_custody_and_full_runtime_shape(self):
        custody, volume, identifier = canary.Custody(), "w1601_n8n_" + "b" * 16, "a" * 64
        custody.defaults["image"] = (["entry"], ["command"])
        with patch.object(canary, "absent", return_value=True), patch.object(canary, "docker", return_value=b""), patch.object(canary, "inspect", side_effect=canary.Failure("inspect_after_effect")):
            with self.assertRaisesRegex(canary.Failure, "inspect_after_effect"):
                custody.volume(volume)
        self.assertEqual(custody.volumes, [volume])
        with patch.object(canary, "inspect", side_effect=canary.Failure("inspect_after_effect")):
            with self.assertRaisesRegex(canary.Failure, "inspect_after_effect"):
                custody.container(identifier, "image", volume, "seed", "seed")
        self.assertEqual(custody.containers[0][0], identifier)
        good = self.runtime(identifier, "image", volume)
        with patch.object(canary, "inspect", return_value=good):
            custody.validate(identifier, "image", volume, "seed", "seed", running=False)
        for field, value, reason in (("NetworkMode", "bridge", "candidate_container_identity_invalid"), ("PortBindings", {"5678/tcp": []}, "candidate_container_identity_invalid"), ("Tmpfs", {}, "candidate_tmpfs_invalid")):
            broken = self.runtime(identifier, "image", volume)
            broken["HostConfig"][field] = value
            with patch.object(canary, "inspect", return_value=broken), self.assertRaisesRegex(canary.Failure, reason):
                custody.validate(identifier, "image", volume, "seed", "seed")
        broken = self.runtime(identifier, "image", volume); broken["Mounts"][0]["Name"] = "wrong"
        with patch.object(canary, "inspect", return_value=broken), self.assertRaisesRegex(canary.Failure, "candidate_mount_invalid"):
            custody.validate(identifier, "image", volume, "seed", "seed")
        broken = self.runtime(identifier, "image", volume); broken["Config"]["Cmd"] = ["-e", "network()"]
        with patch.object(canary, "inspect", return_value=broken), self.assertRaisesRegex(canary.Failure, "candidate_seed_command_invalid"):
            custody.validate(identifier, "image", volume, "seed", "seed")

    def test_pending_ambiguous_create_reconciles_exact_name_and_refuses_label_swap(self):
        custody, identifier, volume, name = canary.Custody(), "a" * 64, "w1601_n8n_" + "b" * 16, "seed"
        custody.defaults["image"] = (["entry"], ["command"]); custody.pending = [(name, "image", volume, "seed")]
        row = self.runtime(identifier, "image", volume, name=name)
        calls = []
        with patch.object(canary, "absent", side_effect=[False, False, True, True]), patch.object(canary, "inspect", return_value=row), patch.object(canary, "docker", side_effect=lambda *a, **k: calls.append(a) or b""):
            self.assertTrue(custody.cleanup())
        self.assertEqual(calls, [("container", "rm", "-f", identifier)])
        custody = canary.Custody(); custody.containers = [(identifier, "image", volume, "seed", name)]; custody.defaults["image"] = (["entry"], ["command"])
        swapped = self.runtime(identifier, "image", volume, name=name); swapped["Config"]["Labels"]["io.neoth.w1601.run"] = "other"
        with patch.object(canary, "absent", return_value=False), patch.object(canary, "inspect", return_value=swapped), patch.object(canary, "docker") as effect:
            self.assertFalse(custody.cleanup())
        effect.assert_not_called()

    def test_candidate_content_mutation_keeps_id_name_but_changes_proof(self):
        rows = [{"id": "id-one", "name": "Workflow", "active": False, "nodes": [{"a": 1}], "connections": {}, "settings": {}, "nodeGroups": None}]
        changed = [{**rows[0], "nodeGroups": {"group": {"x": 2}}}]
        with patch.object(canary, "COUNT", 1), patch.object(canary, "internal_json", side_effect=[rows, changed]):
            first = canary.candidate_workflows("a" * 64, b"workflow", (("slug", "Workflow"),))
            second = canary.candidate_workflows("a" * 64, b"workflow", (("slug", "Workflow"),))
        self.assertEqual(first[0][:2], second[0][:2]); self.assertNotEqual(first, second)

    def test_hosted_node_transport_rejects_anonymous_workflow_200(self):
        wrapper = r'''const code=process.env.CANARY_TRANSPORT,calls=[];const fs={readFileSync:()=> 'workflow-key'};const http={request:(options,callback)=>{const unauth=!options.headers||!options.headers['X-N8N-API-KEY'];calls.push([options.path,unauth]);const status=options.path==='/healthz'?200:200;const handlers={};const response={statusCode:status,on:(event,handler)=>{handlers[event]=handler;return response},destroy:()=>{}};const request={setTimeout:()=>{},on:()=>request,end:()=>{callback(response);if(handlers.data)handlers.data(Buffer.from('{}'));if(handlers.end)handlers.end()}};return request}};new Function('require',code)(m=>m==='fs'?fs:m==='http'?http:require(m));setTimeout(()=>process.stdout.write(JSON.stringify({code:process.exitCode||0,calls})),0);'''
        result = subprocess.run(["node", "-e", wrapper], env=dict(os.environ, CANARY_TRANSPORT=canary.WORKFLOW_TRANSPORT), capture_output=True, text=True, check=False, timeout=10)
        observed = json.loads(result.stdout)
        self.assertEqual(result.returncode, 23)
        self.assertEqual(observed["code"], 23)
        self.assertEqual(observed["calls"], [["/healthz", True], ["/api/v1/workflows?limit=1", True]])

    def run_credential_export_fixture(self, fixture):
        wrapper = r'''const code=process.env.CANARY_PROOF,fixture=JSON.parse(process.env.CANARY_FIXTURE),files={},removed=[];const fs={readFileSync:x=>x===0?JSON.stringify({id:'cred-1',name:'neoth-restore-decrypt-fixture'}):files[x],mkdtempSync:()=>'/tmp/private',chmodSync:()=>{},lstatSync:p=>({isFile:()=>true,isSymbolicLink:()=>false,size:files[p].length}),unlinkSync:p=>{delete files[p];removed.push('file')},rmdirSync:p=>removed.push('dir'),rmSync:p=>{removed.push('rm')}};const path={join:(a,b)=>a+'/'+b};const child={spawnSync:(cmd,args)=>{const out=args.find(x=>x.startsWith('--output=')).slice(9);files[out]=JSON.stringify(fixture);return {status:0}}};const crypto={createHash:()=>{let x='';const h={update:v=>{x+=v;return h},digest:()=>require('crypto').createHash('sha256').update(x).digest('hex')};return h}};new Function('require',code)(m=>m==='node:fs'?fs:m==='node:path'?path:m==='node:child_process'?child:m==='node:crypto'?crypto:require(m));process.stderr.write(JSON.stringify(removed));'''
        return subprocess.run(["node", "-e", wrapper], env=dict(os.environ, CANARY_PROOF=canary.CREDENTIAL_EXPORT_PROOF, CANARY_FIXTURE=json.dumps(fixture)), capture_output=True, text=True, check=False, timeout=10)

    def test_hosted_node_export_proof_accepts_exact_fixture_and_cleans_private_file(self):
        fixture = [{"id": "cred-1", "name": "neoth-restore-decrypt-fixture", "type": "httpHeaderAuth", "data": {"name": "X-NEOTH-Restore-Fixture", "value": "neoth-restore-dummy"}}]
        result = self.run_credential_export_fixture(fixture)
        self.assertEqual(result.returncode, 0); self.assertEqual(set(json.loads(result.stdout)), {"id_sha256", "proof_sha256"}); self.assertEqual(json.loads(result.stderr), ["file", "dir"])

    def test_hosted_node_export_proof_rejects_list_only_and_mutated_plaintext_type_or_id(self):
        exact = {"id": "cred-1", "name": "neoth-restore-decrypt-fixture", "type": "httpHeaderAuth", "data": {"name": "X-NEOTH-Restore-Fixture", "value": "neoth-restore-dummy"}}
        for mutation in ({"data": {"name": "X-NEOTH-Restore-Fixture", "value": "changed"}}, {"type": "basicAuth"}, {"id": "other"}):
            candidate = dict(exact); candidate.update(mutation)
            self.assertNotEqual(self.run_credential_export_fixture([candidate]).returncode, 0)
        self.assertNotEqual(self.run_credential_export_fixture([]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
