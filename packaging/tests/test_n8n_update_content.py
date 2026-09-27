import json
import os
import subprocess
import unittest
from pathlib import Path


SCRIPT = (Path(__file__).resolve().parents[2] / "SRC" / "neothd" / "src" / "integrations" / "n8n" / "managed_update_verify.js").read_text(encoding="utf-8")


class UpdateContentHelperTests(unittest.TestCase):
    def workflow(self, identifier="workflow-1"):
        return {
            "id": identifier, "name": "workflow", "active": False,
            "nodes": [{"name": "trigger", "type": "n8n-nodes-base.manualTrigger"}],
            "connections": {}, "settings": {}, "nodeGroups": [{"name": "main", "children": ["trigger"]}],
            "staticData": {"global": {"runs": 1}}, "meta": {"instanceId": "stable"},
            "pinData": {"trigger": [{"value": 1}]}, "tags": [{"id": "tag-1", "name": "prod"}],
            "shared": [{"role": "workflow:owner", "workflowId": identifier, "projectId": "project-1", "project": {"id": "project-1", "name": "Personal"}}],
            "versionId": "version-1", "versionCounter": 3, "activeVersionId": "version-1",
            "versionMetadata": {"name": "workflow", "description": "rich export"},
        }

    def credential(self, value="secret"):
        return {"id": "credential-1", "name": "credential", "type": "httpHeaderAuth", "data": {"name": "X-Key", "value": value}, "isManaged": False, "isGlobal": False, "isResolvable": True, "resolvableAllowFallback": False, "resolverId": None, "usageScope": "project"}

    def run_helper(self, workflows, credentials, *, oversize=False, fail_export=False):
        wrapper = r'''
const code=process.env.NEOTH_UPDATE_CONTENT_SCRIPT;
const fixture=JSON.parse(process.env.NEOTH_UPDATE_CONTENT_FIXTURE);
const removed=[]; const files={};
const fs={
  mkdtempSync:()=>'/tmp/private', chmodSync:()=>{},
  lstatSync:p=>({isFile:()=>true,isSymbolicLink:()=>false,size:process.env.NEOTH_UPDATE_CONTENT_OVERSIZE==='1'?67108865:Buffer.byteLength(files[p]||'')}),
  readFileSync:p=>files[p], rmSync:()=>removed.push('rm')
};
const path={join:(a,b)=>a+'/'+b};
const child={spawnSync:(cmd,args)=>{ if(process.env.NEOTH_UPDATE_CONTENT_FAIL==='1') return {status:1}; const out=args.find(v=>v.startsWith('--output=')).slice(9); files[out]=JSON.stringify(args[0]==='export:workflow'?fixture.workflows:fixture.credentials); return {status:0}; }};
new Function('require', code)(m=>m==='node:fs'?fs:m==='node:path'?path:m==='node:child_process'?child:m==='node:crypto'?require('crypto'):require(m));
process.stderr.write(JSON.stringify(removed));
'''
        env = dict(os.environ, NEOTH_UPDATE_CONTENT_SCRIPT=SCRIPT,
                   NEOTH_UPDATE_CONTENT_FIXTURE=json.dumps({"workflows": workflows, "credentials": credentials}),
                   NEOTH_UPDATE_CONTENT_OVERSIZE="1" if oversize else "0",
                   NEOTH_UPDATE_CONTENT_FAIL="1" if fail_export else "0")
        return subprocess.run(["node", "-e", wrapper], env=env, capture_output=True, text=True, check=False, timeout=10)

    def receipt(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stderr), ["rm"])
        return json.loads(result.stdout)

    def test_hosted_helper_canonicalizes_order_but_binds_durable_workflow_and_credential_state(self):
        first = self.receipt(self.run_helper([self.workflow("b"), self.workflow("a")], [self.credential()]))
        reordered = self.receipt(self.run_helper([self.workflow("a"), self.workflow("b")], [self.credential()]))
        self.assertEqual(first, reordered)
        for field, mutation in (("active", True), ("nodeGroups", []), ("staticData", {"global": {"runs": 2}}), ("pinData", {}), ("meta", {"instanceId": "changed"}), ("tags", []), ("shared", [])):
            workflow = self.workflow(); workflow[field] = mutation
            changed = self.receipt(self.run_helper([workflow], [self.credential()]))
            baseline = self.receipt(self.run_helper([self.workflow()], [self.credential()]))
            self.assertNotEqual(changed["content_sha256"], baseline["content_sha256"], field)
        changed = self.receipt(self.run_helper([self.workflow()], [self.credential("changed")]))
        self.assertNotEqual(changed["content_sha256"], self.receipt(self.run_helper([self.workflow()], [self.credential()]))["content_sha256"])
        scoped = self.credential(); scoped["usageScope"] = "instance"
        self.assertNotEqual(self.receipt(self.run_helper([self.workflow()], [scoped]))["content_sha256"], self.receipt(self.run_helper([self.workflow()], [self.credential()]))["content_sha256"])
        volatile = self.workflow(); volatile.update({"createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": "2026-01-01T00:00:00.000Z"})
        migrated = dict(volatile); migrated.update({"createdAt": "2026-01-02T00:00:00.000Z", "updatedAt": "2026-01-02T00:00:00.000Z"})
        self.assertEqual(self.receipt(self.run_helper([volatile], [self.credential()])), self.receipt(self.run_helper([migrated], [self.credential()])))

    def test_hosted_helper_rejects_duplicate_malformed_oversize_and_failed_export_with_cleanup(self):
        duplicate = self.run_helper([self.workflow(), self.workflow()], [self.credential()])
        self.assertEqual(duplicate.returncode, 23); self.assertEqual(json.loads(duplicate.stderr), ["rm"])
        malformed = self.workflow(); del malformed["active"]
        bad = self.run_helper([malformed], [self.credential()])
        self.assertEqual(bad.returncode, 23); self.assertEqual(json.loads(bad.stderr), ["rm"])
        unknown = self.workflow(); unknown["unreviewedStructuralField"] = {"can": "change"}
        changed = self.receipt(self.run_helper([unknown], [self.credential()]))
        baseline = self.receipt(self.run_helper([self.workflow()], [self.credential()]))
        self.assertNotEqual(changed["content_sha256"], baseline["content_sha256"])
        for result in (self.run_helper([self.workflow()], [self.credential()], oversize=True), self.run_helper([self.workflow()], [self.credential()], fail_export=True)):
            self.assertEqual(result.returncode, 23); self.assertEqual(json.loads(result.stderr), ["rm"])


if __name__ == "__main__":
    unittest.main()
