import importlib.util, io, json, sys, tarfile, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
SPEC=importlib.util.spec_from_file_location("managed_update",Path(__file__).parents[1]/"n8n_managed_update_canary.py"); canary=importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name]=canary; SPEC.loader.exec_module(canary)
def receipt():
    d={key:"d"*64 for key in canary.FIELDS}; d.update(schema_version=1,source_archive_bytes=1,host_port=5681,baseline_workflow_count=13,baseline_credential_count=1,migrated_workflow_count=13,migrated_credential_count=1,selector="n8n-2.40.7",version="2.40.7",platform="linux/amd64",update_job_id="job",source_container_id="a"*64,retained_source_container_id="a"*64,new_container_id="b"*64,retained_source_name="neoth-n8n-retired-job",source_volume="old",update_volume="new")
    return {"job_id":"job","state":"ready","operation":"update","target":"n8n-2.40.7","platform":"linux/amd64","receipt":d,"failure_code":None}
def binding(update, identifier):
    lineage={"update_job_id":update["update_job_id"],"update_manifest_sha256":update["update_manifest_sha256"],"admitted_selector":update["selector"],"admitted_version":update["version"],"admitted_platform":update["platform"],"admitted_runtime_image":update["runtime_image"],"admitted_repo_digest":update["repo_digest"],"catalog_evidence_sha256":update["catalog_evidence_sha256"],"index_digest":update["index_digest"],"child_manifest_digest":update["child_manifest_digest"],"config_digest":update["config_digest"],"source_job_id":update["source_job_id"],"source_manifest_sha256":update["source_manifest_sha256"],"source_archive_sha256":update["source_archive_sha256"],"source_archive_bytes":update["source_archive_bytes"],"update_volume_owner_job_id":update["update_job_id"],"source_container_id":update["source_container_id"],"source_image":update["source_image"],"source_volume":update["source_volume"],"baseline_workflow_count":update["baseline_workflow_count"],"baseline_credential_count":update["baseline_credential_count"],"baseline_content_sha256":update["baseline_content_sha256"],"migrated_workflow_count":update["migrated_workflow_count"],"migrated_credential_count":update["migrated_credential_count"],"migrated_content_sha256":update["migrated_content_sha256"],"retained_source_container_id":update["retained_source_container_id"],"retained_source_name":update["retained_source_name"]}
    return {"schema_version":4,"phase":"Ready","job_id":update["update_job_id"],"manifest_sha256":update["update_manifest_sha256"],"container_name":"neoth-n8n","container_id":identifier,"image":update["runtime_image"],"host_port":5681,"volume":update["update_volume"],"retained_reinstall":None,"bootstrap_volume_owner_job_id":None,"lineage":{"update":lineage}}
def repair_view(update, old, new=None):
    prior=binding(update,old); current=None if new is None else binding(update,new)
    return {"schema_version":1,"phase":"completed","repair_job_id":"repair","repair_manifest_sha256":"e"*64,"generation":1,"source_install_job_id":update["update_job_id"],"source_install_manifest_sha256":update["update_manifest_sha256"],"action":"recreated" if new else "healthy","old_container_id":old,"new_container_id":new,"old_binding":prior,"new_binding":current,"old_binding_bytes":list(json.dumps(prior,separators=(",",":"),sort_keys=True).encode()),"new_binding_bytes":None if current is None else list(json.dumps(current,separators=(",",":"),sort_keys=True).encode())}
class Boundaries(unittest.TestCase):
 def test_exact_receipt_rejects_extra_wrong_selector_and_source_alias(self):
  self.assertEqual(canary.validate_update(receipt())["selector"],canary.TARGET)
  for mutate in (lambda x:x["receipt"].update(selector="n8n"),lambda x:x["receipt"].update(update_volume="old"),lambda x:x["receipt"].update(evidence_sha256="not-a-hash"),lambda x:x["receipt"].update(migrated_content_sha256="c"*64),lambda x:x["receipt"].update(extra="x"),lambda x:x.update(job_id="other")):
   v=receipt(); mutate(v)
   with self.assertRaises(canary.Failure): canary.validate_update(v)
 def test_archive_member_manifest_detects_content_mutation(self):
  with tempfile.TemporaryDirectory() as temp:
   first,second=Path(temp)/"a.tar",Path(temp)/"b.tar"
   for path,body in ((first,b"one"),(second,b"two")):
    with tarfile.open(path,"w") as archive:
     item=tarfile.TarInfo("fixture"); item.size=len(body); archive.addfile(item,io.BytesIO(body))
   self.assertNotEqual(canary.migration.safe_archive_manifest(first),canary.migration.safe_archive_manifest(second))
 def test_source_archive_receipt_binds_exact_hash_and_byte_count(self):
  update=canary.validate_update(receipt()); update["source_archive_sha256"]="a"*64; update["source_archive_bytes"]=17
  canary.validate_source_archive_receipt(update,"a"*64,17)
  for digest,size in (("b"*64,17),("a"*64,18)):
   with self.assertRaises(canary.Failure): canary.validate_source_archive_receipt(update,digest,size)
 def test_ready_operation_rejects_operation_state_and_failure_mutation(self):
  good={"job_id":"job","state":"ready","operation":"backup","failure_code":None}
  self.assertEqual(canary.ready_operation(json.dumps(good).encode(),"backup"),"job")
  for key,value in (("state","failed"),("operation","repair"),("failure_code","x")):
   bad=dict(good); bad[key]=value
   with self.assertRaises(canary.Failure): canary.ready_operation(json.dumps(bad).encode(),"backup")
 def test_update_capture_uses_stdin_payload_without_secret_argv(self):
  command=["neoth","--output","json","n8n","update","--target",canary.TARGET,"--platform",canary.PLATFORM,"--api-key-stdin"]
  self.assertEqual(command[-1],"--api-key-stdin")
  self.assertNotIn("secret-value", " ".join(command))
 def test_pre_receipt_cleanup_uses_only_the_known_source_fixture(self):
  source=("install-job","manifest","source-volume","a"*64)
  with patch.object(canary.product,"cleanup_owned_runtime_and_volume",return_value=True) as cleanup, patch.object(canary.migration,"clear_fixture_secrets",return_value=True) as secrets:
   self.assertTrue(canary.cleanup_update_fixture(Path("/unused"),source,None,False))
  cleanup.assert_called_once_with("a"*64,"source-volume","install-job",5681,runtime_already_absent=False)
  secrets.assert_called_once_with("install-job")
 def test_completed_update_cleanup_rejects_wrong_retained_source_before_delete(self):
  view=canary.validate_update(receipt())
  source=("install-job","manifest","old","a"*64)
  wrong={"Id":"a"*64,"Name":"/wrong","State":{"Running":False},"Config":{"Image":"x","Labels":{"io.neoth.managed":"n8n"}},"Mounts":[]}
  with patch.object(canary,"assert_no_update_candidates"), patch.object(canary.product,"exact_absent",return_value=True), patch.object(canary.product,"docker_inspect",return_value=wrong), patch.object(canary,"docker") as docker:
   self.assertFalse(canary.cleanup_update_fixture(Path("/unused"),source,view,False))
  docker.assert_not_called()
 def test_update_runtime_rejects_reinstall_binding_that_loses_update_volume(self):
  view=canary.validate_update(receipt())
  binding={"container_id":"c"*64,"phase":"Ready","container_name":"neoth-n8n","job_id":"reinstall","manifest_sha256":"manifest","volume":"wrong","image":view["runtime_image"]}
  with patch.object(canary.product,"read_json",return_value=binding), patch.object(canary.product,"docker_inspect") as inspect:
   with self.assertRaises(canary.Failure): canary.update_runtime(Path("/unused"),view,"b"*64,"reinstall","manifest")
  inspect.assert_not_called()
 def test_attempted_update_without_receipt_preserves_fixture(self):
  source=("install-job","manifest","source-volume","a"*64)
  with patch.object(canary.product,"cleanup_owned_runtime_and_volume") as cleanup:
   self.assertFalse(canary.cleanup_update_fixture(Path("/unused"),source,None,True))
  cleanup.assert_not_called()
 def test_repair_recreation_binds_raw_old_and_new_update_lineage(self):
  update=canary.validate_update(receipt()); old="b"*64; new="c"*64; view=repair_view(update,old,new)
  canary.validate_update_repair(view,"repair","e"*64,update,"recreated",old,new)
  for mutate in (lambda x:x.update(action="healthy"),lambda x:x.update(old_container_id="a"*64),lambda x:x["new_binding"].update(volume="wrong"),lambda x:x.update(repair_job_id="other")):
   changed=json.loads(json.dumps(view)); mutate(changed)
   with self.assertRaises(canary.Failure): canary.validate_update_repair(changed,"repair","e"*64,update,"recreated",old,new)
 def test_reinstall_rejection_requires_deadline_writer_and_specific_code(self):
  canary.validate_reinstall_rejection(1,False,False,b"n8n_retained_reinstall_already_active")
  for result in ((0,False,False,b"n8n_retained_reinstall_already_active"),(1,True,False,b"n8n_retained_reinstall_already_active"),(1,False,True,b"n8n_retained_reinstall_already_active"),(1,False,False,b"different")):
   with self.assertRaises(canary.Failure): canary.validate_reinstall_rejection(*result)
 def test_repeat_reinstall_uses_its_own_bounded_stdin_process_path(self):
  class Sink(io.BytesIO):
   def close(self): pass
  class Child:
   def __init__(self): self.stdin=Sink(); self.stdout=io.BytesIO(); self.stderr=io.BytesIO(b"n8n_retained_reinstall_already_active"); self.returncode=1
   def wait(self,timeout=None): return self.returncode
   def kill(self): self.returncode=-9
  child=Child()
  with patch.object(canary.subprocess,"Popen",return_value=child) as popen:
   canary.bounded_reinstall_rejection(Path("neoth"),"uninstall",b"key\n",timeout=1)
  self.assertEqual(child.stdin.getvalue(),b"key\n")
  self.assertIn("--api-key-stdin",popen.call_args.args[0])
 def test_lifecycle_key_contract_stays_bytes_and_scoped(self):
  update=canary.validate_update(receipt()); workflow_key=b"workflow-key"; scoped_key=b"scoped-key"
  self.assertEqual(canary.api_key_stdin(workflow_key),b"workflow-key\n")
  for invalid in ("workflow-key",b"",b"workflow\nkey"):
   with self.assertRaises(canary.Failure): canary.api_key_stdin(invalid)
  with patch.object(canary.migration,"candidate_workflows",return_value=(("w","1","digest"),)) as workflows, patch.object(canary.migration,"candidate_credential_listing",return_value=("credential","name")) as credentials, patch.object(canary.migration,"credential_proof",return_value={"proof":"ok"}):
   canary.assert_update_content(update["new_container_id"],workflow_key,scoped_key,[],("credential","name"),{"proof":"ok"},(("w","1","digest"),))
  self.assertEqual(workflows.call_args.args[1],workflow_key)
  self.assertEqual(credentials.call_args.args[1],scoped_key)
 def test_schema3_update_backup_binds_the_update_source_and_archive(self):
  update=canary.validate_update(receipt())
  with tempfile.TemporaryDirectory() as directory:
   home=Path(directory); archive=home/"n8n-backups"/"backup.tar"; archive.parent.mkdir(); archive.write_bytes(b"x")
   value={"schema_version":3,"backup_job_id":"backup","backup_manifest_sha256":"f"*64,"source_install_job_id":update["update_job_id"],"source_job_id":update["update_job_id"],"source_manifest_sha256":update["update_manifest_sha256"],"source_operation":"update","source_pinned_image":update["runtime_image"],"source_container_id":update["new_container_id"],"volume_name":update["update_volume"],"generation":1,"archive_sha256":"a"*64,"archive_bytes":1,"original_running_state":True,"restored_running_state":True}
   value["archive_sha256"]=canary.sha(archive)
   receipt_path=home/"n8n-backup-backup.receipt.json"
   receipt_path.write_text(json.dumps(value),encoding="utf-8")
   self.assertEqual(canary.validate_update_backup(home,"backup","f"*64,update)["archive_bytes"],1)
   value["source_operation"]="install"
   receipt_path.write_text(json.dumps(value),encoding="utf-8")
   with self.assertRaises(canary.Failure): canary.validate_update_backup(home,"backup","f"*64,update)
class JobManifestTests(unittest.TestCase):
 def test_real_observer_projection_returns_validated_manifest(self):
  job="00000000-0000-4000-8000-000000000001"
  row={"job_id":job,"operation":"backup","state":"ready","state_revision":5,"completed_steps":4,"total_steps":4,"manifest_sha256":"a"*64}
  with patch.object(canary.product,"run",return_value=json.dumps([row]).encode()):
   self.assertEqual(canary.job_manifest(Path("/unused"),job,"backup"),"a"*64)
 def test_real_observer_rejects_nonready_foreign_incomplete_or_invalid_row(self):
  job="00000000-0000-4000-8000-000000000001"
  base={"job_id":job,"operation":"backup","state":"ready","state_revision":5,"completed_steps":4,"total_steps":4,"manifest_sha256":"a"*64}
  for change in ({"state":"failed"},{"operation":"repair"},{"job_id":"foreign"},{"completed_steps":3},{"manifest_sha256":"invalid"}):
   row={**base,**change}
   with self.subTest(change=change), patch.object(canary.product,"run",return_value=json.dumps([row]).encode()):
    with self.assertRaises(canary.product.Failure): canary.job_manifest(Path("/unused"),job,"backup")
if __name__=="__main__": unittest.main()
