"""Run-only execution lane for the disposable hosted n8n bootstrap canary."""

from __future__ import annotations

import copy
import hashlib
import json
import secrets
import sys
from pathlib import Path
from typing import Any

EXECUTION_ASSETS = ("morning_brief.json", "daily_summary.json")
FIXTURE_BASE_URL = "http://neoth-mock:9744"
FIXTURE_CHANNEL = "canary-channel"
FIXTURE_RECIPIENT = "canary-recipient"
RECALL_SENTINEL = "NEOTH_CANARY_RECALL_SENTINEL"
COMPLETION_SENTINEL = "NEOTH_CANARY_COMPLETION_SENTINEL"
MOCK_CONFIG_PATH = "/tmp/neoth-execution-mock.json"

# Config travels only on docker-exec stdin, is read once, then unlinked.
MOCK_NODE = r"""
const fs=require('fs'),http=require('http');let p;try{p=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));fs.unlinkSync(process.argv[1]);}catch(_){process.exit(2)}const calls=[],fail=(r,s)=>{r.writeHead(s,{'content-type':'application/json'});r.end(JSON.stringify({ok:false}));};http.createServer((req,res)=>{let b='';req.on('data',c=>{b+=c;if(b.length>16384)req.destroy();});req.on('end',()=>{if(req.url==='/__receipt'&&req.method==='GET'){res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({calls}));}let body;try{body=JSON.parse(b)}catch(_){return fail(res,400)};let row={path:req.url,method:req.method,auth:req.headers.authorization===`Bearer ${p.token}`,limit:body.limit,channel:body.channel,recipient:body.recipient,incognito:body.incognito,promptHasRecall:typeof body.prompt==='string'&&body.prompt.includes(p.recall),textHasCompletion:typeof body.text==='string'&&body.text.includes(p.completion)};calls.push(row);if(!row.auth||req.method!=='POST'||!['/api/recall','/api/provider/call','/api/channel/send'].includes(req.url))return fail(res,403);if(req.url==='/api/recall'){if(typeof body.limit!=='number')return fail(res,422);res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({ok:true,data:{hits:[p.recall]}}));}if(req.url==='/api/provider/call'){if(body.incognito!==true||!row.promptHasRecall)return fail(res,422);res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({ok:true,data:{completion:p.completion}}));}if(body.channel!==p.channel||body.recipient!==p.recipient||!row.textHasCompletion)return fail(res,422);res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({ok:true,data:{queued:true}}));});}).listen(9744,'0.0.0.0');
""".strip()
MOCK_RECEIPT_NODE = "fetch('http://127.0.0.1:9744/__receipt').then(async r=>process.stdout.write(await r.text())).catch(()=>process.exit(2));"


def adapt_workflow(bootstrap: Any, source: dict, credential_id: str, credential_name: str) -> dict:
    value = copy.deepcopy(source)
    if not isinstance(value.get("nodes"), list) or not isinstance(value.get("connections"), dict):
        raise bootstrap.CanaryFailure("execution_template_shape_invalid")
    triggers = configurations = requests = 0
    for node in value["nodes"]:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not isinstance(node.get("name"), str):
            raise bootstrap.CanaryFailure("execution_template_node_invalid")
        if node["id"] == "schedule":
            if node.get("type") != "n8n-nodes-base.scheduleTrigger":
                raise bootstrap.CanaryFailure("execution_template_schedule_missing")
            node["type"] = "n8n-nodes-base.manualTrigger"; node["typeVersion"] = 1; node["parameters"] = {}; triggers += 1
        elif node["id"] == "configuration":
            assignments = node.get("parameters", {}).get("assignments", {}).get("assignments")
            expected = {"neothBaseUrl": FIXTURE_BASE_URL, "channel": FIXTURE_CHANNEL, "recipient": FIXTURE_RECIPIENT}
            if not isinstance(assignments, list):
                raise bootstrap.CanaryFailure("execution_template_configuration_missing")
            found = set()
            for assignment in assignments:
                if not isinstance(assignment, dict) or assignment.get("name") not in expected or assignment.get("type") != "string":
                    raise bootstrap.CanaryFailure("execution_template_configuration_invalid")
                assignment["value"] = expected[assignment["name"]]; found.add(assignment["name"])
            if found != set(expected):
                raise bootstrap.CanaryFailure("execution_template_configuration_invalid")
            configurations += 1
        elif node.get("type") == "n8n-nodes-base.httpRequest":
            parameters = node.get("parameters")
            if not isinstance(parameters, dict) or parameters.get("authentication") != "genericCredentialType" or parameters.get("genericAuthType") != "httpHeaderAuth":
                raise bootstrap.CanaryFailure("execution_template_http_auth_invalid")
            node["credentials"] = {"httpHeaderAuth": {"id": credential_id, "name": credential_name}}; requests += 1
    if (triggers, configurations, requests) != (1, 1, 3):
        raise bootstrap.CanaryFailure("execution_template_shape_invalid")
    value["active"] = False
    return value


def create_credential(bootstrap: Any, port: int, raw_key: str, name: str, token: str) -> str:
    payload = {"name": name, "type": "httpHeaderAuth", "data": {"name": "Authorization", "value": f"Bearer {token}"}}
    try:
        status, response = bootstrap.workflow_request(port, raw_key, "POST", "/api/v1/credentials", payload)
    except Exception as error:
        raise bootstrap.UnknownEffect("credential_create_unknown") from error
    value = response.get("data", response) if isinstance(response, dict) else None
    if status not in (200, 201) or not isinstance(value, dict) or not isinstance(value.get("id"), str) or not value["id"]:
        raise bootstrap.UnknownEffect("credential_create_unknown")
    return value["id"]


def import_execution_copies(bootstrap: Any, repository: Path, port: int, raw_key: str, credential_id: str, credential_name: str, receipt: dict) -> list[str]:
    assets = repository / "SRC" / "neothd" / "assets" / "n8n_workflows"; ids: list[str] = []; hashes: dict[str, str] = {}
    for name in EXECUTION_ASSETS:
        mapped = adapt_workflow(bootstrap, json.loads((assets / name).read_bytes()), credential_id, credential_name)
        payload = bootstrap.workflow_payload_from_value(mapped); hashes[name] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        try:
            status, created = bootstrap.workflow_request(port, raw_key, "POST", "/api/v1/workflows", payload)
        except Exception as error:
            receipt["unknown_effect_stage"] = f"execution_copy_create_{name}"
            raise bootstrap.UnknownEffect("execution_copy_create_unknown") from error
        value = created.get("data", created) if isinstance(created, dict) else None
        if status not in (200, 201) or not isinstance(value, dict) or not isinstance(value.get("id"), str) or not value["id"]:
            receipt["unknown_effect_stage"] = f"execution_copy_create_{name}"
            raise bootstrap.UnknownEffect("execution_copy_create_unknown")
        identifier = value["id"]
        status, observed = bootstrap.workflow_request(port, raw_key, "GET", f"/api/v1/workflows/{bootstrap.quote(identifier, safe='')}")
        observed_value = observed.get("data", observed) if isinstance(observed, dict) else None
        if status != 200 or not isinstance(observed_value, dict) or observed_value.get("id") != identifier or observed_value.get("active") is not False or not bootstrap.workflow_matches_payload(payload, observed_value):
            raise bootstrap.CanaryFailure("execution_copy_read_verification_failed")
        ids.append(identifier)
    receipt["execution_copy_sha256"] = hashes; receipt["execution_copy_ids_sha256"] = hashlib.sha256("\n".join(ids).encode()).hexdigest()
    receipt.setdefault("execution_stages", []).append("execution_copies_created_inactive_verified")
    return ids


def _owned_execution(bootstrap: Any, row: dict, job: str, volume: str, network: str) -> str:
    identifier = bootstrap.owned_container(row, job, "execution", volume); networks = row.get("NetworkSettings", {}).get("Networks", {})
    if not isinstance(networks, dict) or set(networks) != {network} or not bootstrap.bootstrap_ports_are_unpublished(row):
        raise bootstrap.CanaryFailure("execution_network_or_port_mismatch")
    return identifier


def _owned_mock(bootstrap: Any, row: dict, job: str, network: str) -> str:
    identifier = row.get("Id"); labels = row.get("Config", {}).get("Labels", {}); networks = row.get("NetworkSettings", {}).get("Networks", {})
    if not isinstance(identifier, str) or len(identifier) != 64 or row.get("Config", {}).get("Image") != bootstrap.IMAGE:
        raise bootstrap.CanaryFailure("mock_identity_invalid")
    if labels.get("io.neoth.managed") != "n8n" or labels.get("io.neoth.n8n-job") != job or labels.get("io.neoth.canary-kind") != "mock":
        raise bootstrap.CanaryFailure("mock_label_mismatch")
    aliases = networks.get(network, {}).get("Aliases") if isinstance(networks, dict) else None
    if not isinstance(networks, dict) or set(networks) != {network} or not isinstance(aliases, list) or "neoth-mock" not in aliases or not bootstrap.bootstrap_ports_are_unpublished(row):
        raise bootstrap.CanaryFailure("mock_network_or_port_mismatch")
    return identifier


def _mock_calls(bootstrap: Any, mock_id: str) -> list[dict]:
    value = bootstrap.sanitize_json(bootstrap.docker("exec", "-u", "node", mock_id, "node", "-e", MOCK_RECEIPT_NODE)); calls = value.get("calls") if isinstance(value, dict) else None
    if not isinstance(calls, list) or not all(isinstance(row, dict) for row in calls):
        raise bootstrap.CanaryFailure("mock_receipt_invalid")
    return calls


def _assert_mock_receipt(bootstrap: Any, mock_id: str) -> dict:
    calls = _mock_calls(bootstrap, mock_id)
    if len(calls) != 6 or [row.get("path") for row in calls] != ["/api/recall", "/api/provider/call", "/api/channel/send"] * 2:
        raise bootstrap.CanaryFailure("mock_call_sequence_mismatch")
    for index, row in enumerate(calls):
        if row.get("method") != "POST" or row.get("auth") is not True: raise bootstrap.CanaryFailure("mock_auth_or_method_mismatch")
        if index % 3 == 0 and type(row.get("limit")) is not int: raise bootstrap.CanaryFailure("mock_recall_limit_mismatch")
        if index % 3 == 1 and (row.get("incognito") is not True or row.get("promptHasRecall") is not True): raise bootstrap.CanaryFailure("mock_provider_payload_mismatch")
        if index % 3 == 2 and (row.get("channel") != FIXTURE_CHANNEL or row.get("recipient") != FIXTURE_RECIPIENT or row.get("textHasCompletion") is not True): raise bootstrap.CanaryFailure("mock_send_payload_mismatch")
    return {"calls": 6, "routes": {"recall": 2, "provider": 2, "send": 2}}


def _wait_mock_ready(bootstrap: Any, mock_id: str) -> None:
    deadline = bootstrap.time.monotonic() + 10
    while bootstrap.time.monotonic() < deadline:
        try:
            if _mock_calls(bootstrap, mock_id) == []:
                return
        except Exception:
            pass
        bootstrap.time.sleep(0.2)
    raise bootstrap.CanaryFailure("mock_readiness_timeout")


def _run_cli_once(bootstrap: Any, execution_id: str, workflow_id: str, receipt: dict) -> None:
    result = bootstrap.run(("docker", "exec", "-u", "node", execution_id, "n8n", "execute", "--id", workflow_id), timeout=bootstrap.STARTUP_TIMEOUT)
    if result.timed_out or result.overflow or result.code != 0:
        receipt["unknown_effect_stage"] = "n8n_execute_unknown"
        raise bootstrap.UnknownEffect("n8n_execute_unknown")


def _assert_execution_key(bootstrap: Any, observed: dict, receipt: dict) -> None:
    expected_key_hash = receipt.get("encryption_key_sha256")
    observed_key_hash = observed.get("encryptionKeySha256")
    if observed.get("ok") is not True or not isinstance(expected_key_hash, str) or len(expected_key_hash) != 64 or not isinstance(observed_key_hash, str) or observed_key_hash != expected_key_hash:
        raise bootstrap.CanaryFailure("execution_encryption_key_handoff_unproven")


def _cleanup_container(bootstrap: Any, receipt: dict, name: str, expected_id: str | None, verifier: Any, job: str, *args: str) -> bool:
    try:
        row = bootstrap.inspect(expected_id or name); identifier = verifier(bootstrap, row, job, *args)
        if expected_id is not None and identifier != expected_id: raise bootstrap.CanaryFailure("execution_cleanup_id_mismatch")
        bootstrap.docker("rm", "-f", identifier); bootstrap.prove_absent("container", identifier); return True
    except Exception:
        try:
            bootstrap.prove_absent("container", expected_id or name); return True
        except Exception:
            receipt.setdefault("cleanup", []).append("execution_container_retained_identity_unproven"); return False


def _cleanup_execution_resources(bootstrap: Any, receipt: dict, network: str, execution_name: str, execution_id: str | None, mock_name: str, mock_id: str | None, job: str, volume: str) -> bool:
    cleanup_ok = _cleanup_container(bootstrap, receipt, execution_name, execution_id, _owned_execution, job, volume, network)
    cleanup_ok = _cleanup_container(bootstrap, receipt, mock_name, mock_id, _owned_mock, job, network) and cleanup_ok
    try:
        row = bootstrap.inspect(network); labels = row.get("Labels", {})
        if labels.get("io.neoth.managed") != "n8n" or labels.get("io.neoth.n8n-job") != job or labels.get("io.neoth.canary-kind") != "execution-network": raise bootstrap.CanaryFailure("execution_network_cleanup_identity_unproven")
        bootstrap.docker("network", "rm", network); bootstrap.prove_absent("network", network)
    except Exception:
        try:
            bootstrap.prove_absent("network", network)
        except Exception:
            receipt.setdefault("cleanup", []).append("execution_network_retained_identity_unproven"); cleanup_ok = False
    return cleanup_ok


def execute_templates(bootstrap: Any, repository: Path, job: str, volume: str, runtime_id: str, port: int, raw_key: str, receipt: dict) -> None:
    """Use the caller's module identity; never import a second __main__ copy."""
    token = secrets.token_urlsafe(30); credential_name = f"neoth-execution-{secrets.token_hex(8)}"
    credential_id = create_credential(bootstrap, port, raw_key, credential_name, token)
    receipt["execution_credential_id_sha256"] = hashlib.sha256(credential_id.encode()).hexdigest(); receipt["execution_credential_token_sha256"] = hashlib.sha256(token.encode()).hexdigest()
    receipt.setdefault("execution_stages", []).append("dummy_http_header_credential_created")
    ids = import_execution_copies(bootstrap, repository, port, raw_key, credential_id, credential_name, receipt)
    bootstrap.docker("stop", "--time", "15", runtime_id, timeout=bootstrap.STARTUP_TIMEOUT)
    if bootstrap.inspect(runtime_id).get("State", {}).get("Running") is not False: raise bootstrap.CanaryFailure("runtime_not_stopped_before_execution")
    bootstrap.docker("rm", runtime_id); bootstrap.prove_absent("container", runtime_id)
    receipt.setdefault("execution_stages", []).append("runtime_stopped_and_absent_before_execution")
    suffix = secrets.token_hex(8); network = f"neoth-n8n-execution-{suffix}"; mock_name = f"neoth-n8n-mock-{suffix}"; execution_name = f"neoth-n8n-execution-{suffix}"
    mock_id: str | None = None; execution_id: str | None = None
    try:
        try:
            bootstrap.docker("network", "create", "--internal", "--label", "io.neoth.managed=n8n", "--label", f"io.neoth.n8n-job={job}", "--label", "io.neoth.canary-kind=execution-network", network)
        except Exception as error:
            receipt.setdefault("unknown_effect_stage", "execution_network_create_unknown"); raise bootstrap.UnknownEffect("execution_network_create_unknown") from error
        network_row = bootstrap.inspect(network)
        if network_row.get("Driver") != "bridge" or network_row.get("Internal") is not True or network_row.get("Labels", {}).get("io.neoth.n8n-job") != job: raise bootstrap.CanaryFailure("execution_network_identity_mismatch")
        try:
            bootstrap.docker("run", "-d", "--entrypoint", "sh", "--name", mock_name, "--network", network, "--network-alias", "neoth-mock", "--label", "io.neoth.managed=n8n", "--label", f"io.neoth.n8n-job={job}", "--label", "io.neoth.canary-kind=mock", bootstrap.IMAGE, "-c", "while :; do sleep 3600; done")
        except Exception as error:
            receipt.setdefault("unknown_effect_stage", "mock_container_create_unknown"); raise bootstrap.UnknownEffect("mock_container_create_unknown") from error
        mock_id = _owned_mock(bootstrap, bootstrap.inspect(mock_name), job, network)
        bootstrap.docker("exec", "-i", "-u", "node", mock_id, "sh", "-c", f"umask 077; cat > {MOCK_CONFIG_PATH}", payload=json.dumps({"token": token, "recall": RECALL_SENTINEL, "completion": COMPLETION_SENTINEL, "channel": FIXTURE_CHANNEL, "recipient": FIXTURE_RECIPIENT}).encode())
        bootstrap.docker("exec", "-d", "-u", "node", mock_id, "node", "-e", MOCK_NODE, MOCK_CONFIG_PATH)
        _wait_mock_ready(bootstrap, mock_id)
        try:
            bootstrap.docker("run", "-d", "--entrypoint", "sh", "--name", execution_name, "--network", network, "--label", "io.neoth.managed=n8n", "--label", f"io.neoth.n8n-job={job}", "--label", "io.neoth.canary-kind=execution", "-v", f"{volume}:/home/node/.n8n", bootstrap.IMAGE, "-c", "while :; do sleep 3600; done")
        except Exception as error:
            receipt.setdefault("unknown_effect_stage", "execution_container_create_unknown"); raise bootstrap.UnknownEffect("execution_container_create_unknown") from error
        execution_id = _owned_execution(bootstrap, bootstrap.inspect(execution_name), job, volume, network)
        key = bootstrap.sanitize_json(bootstrap.docker("exec", "-u", "node", execution_id, "node", "-e", bootstrap.CONFIG_KEY_NODE))
        _assert_execution_key(bootstrap, key, receipt)
        receipt.setdefault("execution_stages", []).append("internal_mock_and_execution_container_bound")
        for identifier in ids:
            _run_cli_once(bootstrap, execution_id, identifier, receipt)
        receipt["execution_mock"] = _assert_mock_receipt(bootstrap, mock_id); receipt.setdefault("execution_stages", []).append("two_cli_executions_and_mock_assertions_passed")
    finally:
        original_failure = sys.exc_info()[0] is not None
        cleanup_ok = _cleanup_execution_resources(bootstrap, receipt, network, execution_name, execution_id, mock_name, mock_id, job, volume)
        if not cleanup_ok and not original_failure: raise bootstrap.CanaryFailure("execution_cleanup_unproven")
