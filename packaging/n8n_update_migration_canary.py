#!/usr/bin/env python3
"""Hosted-only, networkless n8n 2.40.5 -> 2.40.7 migration feasibility gate."""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tarfile, threading, time
from pathlib import Path, PurePosixPath
import n8n_product_bootstrap_canary as product
import n8n_update_target_preflight_canary as target

TARGET, PLATFORM, COUNT = "n8n-2.40.7", "linux/amd64", 13
ID, VOLUME = re.compile(r"[0-9a-f]{64}"), re.compile(r"w1601_n8n_[0-9a-f]{16}")
MAX_ARCHIVE_BYTES, MAX_ARCHIVE_MEMBERS, MAX_MEMBER_BYTES = 128 * 1024 * 1024, 20_000, 64 * 1024 * 1024
class Failure(RuntimeError): pass

def raw(argv, payload=None, timeout=180): return product.run_with_payload(argv, payload, timeout) if payload is not None else product.run(argv, timeout)
def docker(*args, payload=None, timeout=180): return raw(["docker", *args], payload, timeout)
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""): digest.update(chunk)
    return digest.hexdigest()
def inspect(identifier):
    value = json.loads(docker("inspect", identifier))
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict): raise Failure("inspect_invalid")
    return value[0]
def absent(kind, identifier): return product.exact_absent(kind, identifier)
def write_receipt(path, value):
    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(canonical(value) + b"\n")
def candidate_name(kind):
    return "w1601_n8n_" + hashlib.sha256(f"{os.environ['GITHUB_RUN_ID']}:{os.environ['GITHUB_RUN_ATTEMPT']}:{kind}".encode()).hexdigest()[:16]

def guard(home, receipt):
    root, run, attempt = os.environ.get("RUNNER_TEMP", ""), os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REF") != "refs/heads/main" or not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")) or not re.fullmatch(r"[1-9][0-9]*", run) or not re.fullmatch(r"[1-9][0-9]*", attempt) or not root): raise Failure("hosted_guard_failed")
    task = Path(root).resolve() / f"w1601-n8n-{run}-{attempt}"
    if sys.platform != "linux" or os.environ.get("DOCKER_HOST") != "unix:///var/run/docker.sock" or os.environ.get("DOCKER_CONTEXT"):
        raise Failure("managed_engine_mismatch")
    if home.is_symlink() or not home.is_dir() or any(home.iterdir()) or home.resolve() != task / "neoth-home" or receipt.resolve() != task / "receipt" / "receipt.json" or os.environ.get("NEOTH_HOME") != str(home.resolve()): raise Failure("hosted_path_guard_failed")
    for variable, directory in (("XDG_CONFIG_HOME", "xdg-config"), ("XDG_DATA_HOME", "xdg-data"), ("XDG_RUNTIME_DIR", "xdg-runtime")):
        value = Path(os.environ.get(variable, ""))
        if value.is_symlink() or not value.is_dir() or value.resolve() != task / directory:
            raise Failure("private_keyring_path_invalid")
    if not docker("version", "--format", "{{.Server.Version}}", timeout=20).strip(): raise Failure("docker_engine_unavailable")

def safe_archive_manifest(archive):
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE_BYTES: raise Failure("archive_size_invalid")
    rows, names, count, total_bytes = [], set(), 0, 0
    try:
        with tarfile.open(archive, "r:") as tar:
            # Streaming prevents unbounded getmembers allocation before the member cap.
            while member := tar.next():
                count += 1
                if count > MAX_ARCHIVE_MEMBERS: raise Failure("archive_member_count")
                path = PurePosixPath(member.name)
                # Docker's tar uses ./ and a root directory entry. Normalize
                # those aliases before duplicate detection, never before .. checks.
                name = path.as_posix()
                if (not member.name or member.name.startswith("/") or "\\" in member.name or ".." in path.parts or name in names or member.issym() or member.islnk() or not (member.isfile() or member.isdir()) or (name == "." and not member.isdir()) or member.size < 0 or member.size > MAX_MEMBER_BYTES): raise Failure("archive_member_unsafe")
                total_bytes += member.size
                if total_bytes > MAX_ARCHIVE_BYTES: raise Failure("archive_total_member_bytes")
                names.add(name); content = "dir"
                if member.isfile():
                    stream = tar.extractfile(member)
                    if stream is None: raise Failure("archive_member_read")
                    item, total = hashlib.sha256(), 0
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        total += len(chunk)
                        if total > member.size: raise Failure("archive_member_read")
                        item.update(chunk)
                    if total != member.size: raise Failure("archive_member_read")
                    content = item.hexdigest()
                rows.append([name, member.type.decode("latin1"), member.size, member.mode, content])
    except (tarfile.TarError, OSError) as error: raise Failure("archive_invalid") from error
    if count == 0: raise Failure("archive_empty")
    digest = hashlib.sha256()
    for row in sorted(rows): digest.update(canonical(row)); digest.update(b"\n")
    return digest.hexdigest()

def ownership_labels(phase=None):
    labels = {"io.neoth.w1601": "owned", "io.neoth.w1601.run": os.environ["GITHUB_RUN_ID"],
              "io.neoth.w1601.attempt": os.environ["GITHUB_RUN_ATTEMPT"]}
    if phase is not None:
        labels["io.neoth.w1601.phase"] = phase
    return labels


class Custody:
    """Record intent before create; reconcile names once and delete only exact owned IDs."""
    def __init__(self):
        self.containers, self.volumes, self.pending, self.defaults = [], [], [], {}

    def volume(self, name):
        if not VOLUME.fullmatch(name) or not absent("volume", name):
            raise Failure("candidate_volume_preexisting")
        self.volumes.append(name)
        argv = ["volume", "create"]
        for key, value in ownership_labels().items():
            argv.extend(["--label", f"{key}={value}"])
        docker(*argv, name)
        self.validate_volume(name)
        return name

    def validate_volume(self, name):
        row = inspect(name)
        if row.get("Name") != name or row.get("Labels") != ownership_labels():
            raise Failure("candidate_volume_identity_invalid")
        return row

    def validate(self, identifier, image, volume, phase, name, running=None):
        row = inspect(identifier)
        config, mounts = row.get("Config", {}), row.get("Mounts", [])
        labels, host, network = config.get("Labels", {}), row.get("HostConfig", {}), row.get("NetworkSettings", {})
        if (row.get("Id") != identifier or row.get("Name") != f"/{name}"
                or config.get("Image") != image or not isinstance(labels, dict)
                or any(labels.get(key) != value for key, value in ownership_labels(phase).items())
                or host.get("NetworkMode") != "none" or host.get("PortBindings") not in (None, {})
                or host.get("RestartPolicy") != {"Name": "no", "MaximumRetryCount": 0}
                or not isinstance(network.get("Ports", {}), dict)
                or any(bindings not in (None, []) for bindings in network.get("Ports", {}).values())
                or not isinstance(mounts, list)):
            raise Failure("candidate_container_identity_invalid")
        volumes = [mount for mount in mounts if mount.get("Type") == "volume"]
        other = [mount for mount in mounts if mount.get("Type") != "volume"]
        if (len(volumes) != 1 or volumes[0].get("Name") != volume
                or volumes[0].get("Destination") != "/home/node/.n8n"
                or not volumes[0].get("Source") or volumes[0].get("RW") is not True
                or any(mount.get("Type") != "tmpfs" or mount.get("Destination") != "/tmp" for mount in other)):
            raise Failure("candidate_mount_invalid")
        tmpfs = host.get("Tmpfs", {})
        if (not isinstance(tmpfs, dict) or set(tmpfs) != {"/tmp"}
                or set(tmpfs["/tmp"].split(",")) != {"rw", "nosuid", "nodev", "noexec", "size=64m"}):
            raise Failure("candidate_tmpfs_invalid")
        if phase == "seed":
            if config.get("Entrypoint") != ["node"] or config.get("Cmd") != ["-e", "setInterval(() => {}, 2147483647)"]:
                raise Failure("candidate_seed_command_invalid")
        elif phase == "target":
            expected = self.defaults.get(image)
            if expected is None or (config.get("Entrypoint"), config.get("Cmd")) != expected:
                raise Failure("candidate_server_command_invalid")
        else:
            raise Failure("candidate_phase_invalid")
        if running is not None and row.get("State", {}).get("Running") is not running:
            raise Failure("candidate_running_state_invalid")
        return row

    def container(self, identifier, image, volume, phase, name):
        if not ID.fullmatch(identifier):
            raise Failure("candidate_create_identity_unknown")
        record = (identifier, image, volume, phase, name)
        if record not in self.containers:
            self.containers.append(record)
        self.validate(*record, running=False)
        return identifier

    def cleanup(self):
        ok = True
        for name, image, volume, phase in self.pending:
            try:
                if not absent("container", name):
                    identifier = inspect(name).get("Id", "")
                    if not ID.fullmatch(identifier):
                        raise Failure("candidate_reconciliation_identity_unknown")
                    record = (identifier, image, volume, phase, name)
                    self.validate(*record)
                    if record not in self.containers:
                        self.containers.append(record)
            except Exception:
                ok = False
        for record in reversed(self.containers):
            identifier = record[0]
            try:
                if not absent("container", identifier):
                    self.validate(*record)
                    docker("container", "rm", "-f", identifier)
                ok = absent("container", identifier) and ok
            except Exception:
                ok = False
        for volume in reversed(self.volumes):
            try:
                if not absent("volume", volume):
                    self.validate_volume(volume)
                    docker("volume", "rm", volume)
                ok = absent("volume", volume) and ok
            except Exception:
                ok = False
        return bool(ok)

def admitted(binary):
    value = product.read_json_bytes(raw([str(binary), "--output", "json", "n8n", "update-target", "verify", "--target", TARGET, "--platform", PLATFORM], timeout=400)); value = target.validate_target(value); target.verify_docker_image(value["runtime_image"], value["config_digest"]); return value
def backup(binary, home, job, boot, volume, source, port):
    row = product.docker_inspect(source)
    product.validate_runtime(row, job, volume, source, port)
    if row.get("State", {}).get("Running") is not False: raise Failure("backup_source_not_stopped")
    backup_id, view = product.validate_backup_product(product.read_json_bytes(raw([str(binary), "--output", "json", "n8n", "backup"])), job, original_running=False); record = product.observe_exact_job(home, backup_id, "backup"); receipt = product.read_backup_completion_receipt(home, backup_id, record["manifest_sha256"], view, job, boot["manifest_sha256"], source, volume, original_running=False); archive = home / "n8n-backups" / f"{backup_id}.tar"
    if sha256(archive) != receipt["archive_sha256"] or archive.stat().st_size != receipt["archive_bytes"]: raise Failure("backup_archive_custody_invalid")
    return archive, receipt
def create_candidate(custody, image, volume, phase, seed):
    name = candidate_name(phase)
    if not absent("container", name):
        raise Failure("candidate_name_preexisting")
    defaults = inspect(image).get("Config", {})
    if not isinstance(defaults.get("Entrypoint"), list):
        raise Failure("candidate_image_command_invalid")
    custody.defaults[image] = (defaults.get("Entrypoint"), defaults.get("Cmd"))
    custody.pending.append((name, image, volume, phase))
    argv = ["create", "--name", name, "--network", "none", "--restart", "no",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m",
            "--mount", f"type=volume,src={volume},dst=/home/node/.n8n"]
    for key, value in ownership_labels(phase).items():
        argv.extend(["--label", f"{key}={value}"])
    argv += ["--entrypoint", "node", image, "-e", "setInterval(() => {}, 2147483647)"] if seed else [image]
    return custody.container(docker(*argv).decode("ascii", "strict").strip(), image, volume, phase, name)


def capture(argv, *, payload=None, input_file=None, timeout=30, limit=16 * 1024):
    """Bound capture and the entire process lifetime, including stdin writes."""
    output, errors, overflow, writer_failed = bytearray(), bytearray(), [False], []
    def drain(stream, destination, cap):
        try:
            while chunk := stream.read(4096):
                available = max(0, cap - len(destination))
                destination.extend(chunk[:available])
                if len(chunk) > available:
                    overflow[0] = True
        except OSError:
            writer_failed.append(True)
    def feed(stream):
        try:
            if payload:
                stream.write(payload)
            stream.close()
        except OSError:
            writer_failed.append(True)
    child = None
    threads = []
    timed_out = False
    try:
        child = subprocess.Popen(argv, stdin=input_file if input_file is not None else subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        threads = [threading.Thread(target=drain, args=(child.stdout, output, limit), daemon=True),
                   threading.Thread(target=drain, args=(child.stderr, errors, 16 * 1024), daemon=True)]
        if input_file is None:
            threads.append(threading.Thread(target=feed, args=(child.stdin,), daemon=True))
        for thread in threads:
            thread.start()
        try:
            child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            child.kill()
            child.wait(timeout=5)
    except OSError as error:
        raise Failure("candidate_command_spawn_failed") from error
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        for thread in threads:
            thread.join(2)
    if timed_out:
        raise Failure("candidate_internal_timeout")
    if child.returncode != 0 or overflow[0] or writer_failed or any(thread.is_alive() for thread in threads):
        raise Failure("candidate_internal_failed")
    return bytes(output)


def copy_archive_to_stopped_seed(archive, seed, expected):
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise Failure("archive_size_invalid")
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if metadata.st_mode & 0o077 or metadata.st_size != expected["archive_bytes"]:
            raise Failure("archive_private_handle_invalid")
        def current_hash():
            source.seek(0)
            digest = hashlib.sha256()
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
            return digest.hexdigest()
        if current_hash() != expected["archive_sha256"]:
            raise Failure("archive_input_drift")
        source.seek(0)
        capture(["docker", "cp", "-", f"{seed}:/home/node/.n8n"], input_file=source, timeout=180)
        if current_hash() != expected["archive_sha256"]:
            raise Failure("archive_input_drift")


def internal_json(container, script, payload, timeout, limit):
    output = capture(["docker", "exec", "-i", container, "node", "-e", script],
                     payload=payload, timeout=timeout, limit=limit)
    try:
        return json.loads(output)
    except (ValueError, UnicodeError) as error:
        raise Failure("candidate_internal_json_invalid") from error

def source_workflows(port, key, templates):
    value = product.observe_imported_workflows(port, key, templates)
    if value.get("count") != COUNT: raise Failure("source_workflow_count_invalid")
    entries = []
    names = dict(templates)
    for slug, identifier, _ in value["entries"]:
        detail = product.workflow_data(product.workflow_api_json(
            port, key, "/api/v1/workflows/" + product.urllib.parse.quote(identifier, safe="")))
        if detail.get("id") != identifier or detail.get("name") != names[slug] or detail.get("active") is not False:
            raise Failure("source_workflow_identity_changed")
        graph = {field: detail.get(field) for field in ("name", "nodes", "connections", "settings", "nodeGroups")}
        if any(graph[field] is None for field in ("name", "nodes", "connections", "settings")):
            raise Failure("source_workflow_graph_invalid")
        entries.append((slug, identifier, hashlib.sha256(canonical(graph)).hexdigest()))
    return tuple(sorted(entries))

# Node provides only bounded internal HTTP transport. Python uses the existing exact canonical JSON formula.
WORKFLOW_TRANSPORT = r'''
const fs = require('fs'), http = require('http');
const key = fs.readFileSync(0, 'utf8').trim();
function request(path, authenticated = true) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: 5678, path,
      headers: authenticated ? { 'X-N8N-API-KEY': key } : {} }, res => {
      const chunks = []; let bytes = 0;
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 1048576) { res.destroy(); reject(Error('size')); }
        else chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => resolve([res.statusCode, Buffer.concat(chunks).toString('utf8')]));
    });
    req.setTimeout(5000, () => req.destroy(Error('timeout')));
    req.on('error', reject); req.end();
  });
}
(async () => {
  if ((await request('/healthz', false))[0] !== 200) throw Error('health');
  if ((await request('/api/v1/workflows?limit=1', false))[0] !== 401) throw Error('negative');
  const list = await request('/api/v1/workflows?limit=100');
  if (list[0] !== 200) throw Error('auth');
  const body = JSON.parse(list[1]), rows = body.data;
  if (!Array.isArray(rows) || rows.length !== 13 || body.nextCursor) throw Error('count');
  const out = [];
  for (const row of rows) {
    if (!row || typeof row.id !== 'string' || row.active !== false) throw Error('row');
    const detail = await request('/api/v1/workflows/' + encodeURIComponent(row.id));
    if (detail[0] !== 200) throw Error('detail');
    const value = JSON.parse(detail[1]);
    const item = value && value.data && typeof value.data === 'object' ? value.data : value;
    if (!item || item.id !== row.id || item.active !== false) throw Error('identity');
    out.push({ id: item.id, name: item.name, active: item.active, nodes: item.nodes,
      connections: item.connections, settings: item.settings, nodeGroups: item.nodeGroups ?? null });
  }
  process.stdout.write(JSON.stringify(out));
})().catch(() => process.exitCode = 23);
'''
CREDENTIAL_EXPORT_PROOF = r'''const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process'),{createHash}=require('node:crypto');let d;try{process.umask(0o077);const e=JSON.parse(fs.readFileSync(0,'utf8'));if(!e||typeof e.id!=='string'||typeof e.name!=='string')throw 0;d=fs.mkdtempSync('/tmp/neoth-migrate-');fs.chmodSync(d,0o700);const p=path.join(d,'credentials.json'),x=spawnSync('n8n',['export:credentials','--all','--decrypted',`--output=${p}`],{stdio:'ignore',timeout:15000,killSignal:'SIGKILL'});if(x.error||x.signal||x.status!==0)throw 0;const s=fs.lstatSync(p);if(!s.isFile()||s.isSymbolicLink()||s.size<2||s.size>33554432)throw 0;const v=JSON.parse(fs.readFileSync(p,'utf8'));if(!Array.isArray(v)||v.length!==1)throw 0;const c=v[0];if(!c||typeof c!=='object'||Array.isArray(c)||c.id!==e.id||c.name!==e.name||c.type!=='httpHeaderAuth'||!c.data||Array.isArray(c.data)||Object.keys(c.data).sort().join(',')!=='name,value'||c.data.name!=='X-NEOTH-Restore-Fixture'||c.data.value!=='neoth-restore-dummy')throw 0;fs.unlinkSync(p);fs.rmdirSync(d);d=undefined;process.stdout.write(JSON.stringify({id_sha256:createHash('sha256').update(c.id).digest('hex'),proof_sha256:createHash('sha256').update(JSON.stringify({name:c.name,type:c.type,data:{name:c.data.name,value:c.data.value}})).digest('hex')}));}catch{process.exitCode=23}finally{if(d)try{fs.rmSync(d,{recursive:true,force:true})}catch{process.exitCode=23}}'''
CREDENTIAL_LIST_TRANSPORT = r'''const fs=require('fs'),http=require('http');const k=fs.readFileSync(0,'utf8').trim(),r=http.request({host:'127.0.0.1',port:5678,path:'/api/v1/credentials?limit=100',headers:{'X-N8N-API-KEY':k}},x=>{let b='',n=0;x.on('data',d=>{n+=d.length;if(n>262144)x.destroy();else b+=d});x.on('end',()=>{try{let v=JSON.parse(b),a=v.data;if(x.statusCode!==200||!Array.isArray(a)||a.length!==1||!a[0]||typeof a[0].id!=='string'||typeof a[0].name!=='string')throw 0;process.stdout.write(JSON.stringify({id:a[0].id,name:a[0].name}))}catch{process.exitCode=23}})});r.setTimeout(5000,()=>r.destroy());r.on('error',()=>process.exitCode=23);r.end();'''
def candidate_workflows(container, key, templates):
    for _ in range(30):
        try:
            rows = internal_json(container, WORKFLOW_TRANSPORT, key, 20, 8 * 1024 * 1024)
        except Failure as error:
            if str(error) != "candidate_internal_failed": raise
            time.sleep(2); continue
        else:
            names, entries = {name: slug for slug, name in templates}, []
            if not isinstance(rows, list) or len(rows) != COUNT: raise Failure("candidate_workflow_shape_invalid")
            for row in rows:
                if not isinstance(row, dict) or set(row) != {"id", "name", "active", "nodes", "connections", "settings", "nodeGroups"} or not isinstance(row["id"], str) or row["name"] not in names or row["active"] is not False or any(row[x] is None for x in ("nodes", "connections", "settings")): raise Failure("candidate_workflow_shape_invalid")
                graph = {field: row[field] for field in ("name", "nodes", "connections", "settings", "nodeGroups")}; entries.append((names[row["name"]], row["id"], hashlib.sha256(canonical(graph)).hexdigest()))
            result = tuple(sorted(entries))
            if len({entry[0] for entry in result}) != COUNT or len({entry[1] for entry in result}) != COUNT: raise Failure("candidate_workflow_duplicate")
            return result
    raise Failure("candidate_readiness_timeout")
def credential_listing(port, key):
    value = product.workflow_api_json(port, key, "/api/v1/credentials?limit=100"); rows = value.get("data")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict): raise Failure("credential_list_count_invalid")
    identifier, name = rows[0].get("id"), rows[0].get("name")
    if not isinstance(identifier, str) or not identifier or not isinstance(name, str) or name != product.RESTORE_CREDENTIAL_NAME: raise Failure("credential_list_identity_invalid")
    return identifier, name
def candidate_credential_listing(container, key):
    try: row = internal_json(container, CREDENTIAL_LIST_TRANSPORT, key, 20, 256 * 1024)
    except Failure as error: raise Failure("candidate_credential_list_failed") from error
    if set(row) != {"id", "name"} or not isinstance(row["id"], str) or not row["id"] or row["name"] != product.RESTORE_CREDENTIAL_NAME: raise Failure("candidate_credential_list_invalid")
    return row["id"], row["name"]
def credential_proof(container, identifier, name):
    result = product.bounded.run(["docker", "exec", "-i", container, "node", "-e", CREDENTIAL_EXPORT_PROOF], payload=canonical({"id": identifier, "name": name}), timeout=30)
    if result.code != 0 or result.timed_out or result.overflow: raise Failure("credential_decryption_export_failed")
    try: proof = json.loads(result.stdout)
    except Exception as error: raise Failure("credential_decryption_export_invalid") from error
    if set(proof) != {"id_sha256", "proof_sha256"} or not all(isinstance(value, str) and ID.fullmatch(value) for value in proof.values()): raise Failure("credential_decryption_export_invalid")
    expected = {"name": name, "type": "httpHeaderAuth", "data": {
        "name": product.RESTORE_CREDENTIAL_HEADER, "value": product.RESTORE_CREDENTIAL_VALUE}}
    expected_digest = hashlib.sha256(json.dumps(expected, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    if proof["id_sha256"] != hashlib.sha256(identifier.encode()).hexdigest() or proof["proof_sha256"] != expected_digest:
        raise Failure("credential_decryption_export_mismatch")
    return proof

def input_provenance():
    names = (
        "packaging/n8n_update_migration_canary.py", "packaging/n8n_bootstrap_canary.py",
        "packaging/n8n_product_bootstrap_canary.py", "packaging/n8n_update_target_preflight_canary.py",
        "packaging/tests/test_n8n_update_migration_canary.py", ".github/workflows/n8n-update-migration.yml",
        "SRC/Cargo.lock", "SRC/neothd/Cargo.toml", "SRC/neothd/src/cli/n8n.rs",
        "SRC/neothd/src/integrations/n8n.rs", "SRC/neothd/src/integrations/n8n/managed_bootstrap.rs",
        "SRC/neothd/src/integrations/n8n/bootstrap_transport.rs", "SRC/neothd/src/integrations/n8n/managed_runtime.rs",
        "SRC/neothd/src/integrations/n8n/managed_backup.rs", "SRC/neothd/src/integrations/n8n/managed_update_target.rs",
        "SRC/neothd/src/integrations/n8n/workflow_import.rs", "SRC/neothd/src/integrations/jobs.rs",
        "SRC/neothd/src/integrations/state.rs", "SRC/neothd/src/installers/n8n_workflows.rs",
        "SRC/neothd/src/installers/n8n_starter_workflows.rs", "SRC/neothd/src/cli/init.rs",
        "SRC/neothd/src/cli/init/io.rs", "SRC/neothd/src/cli/init/steps_provider.rs",
        "SRC/neothd/src/cli/init/types.rs", "SRC/neothd/src/cli/credential.rs",
        "SRC/neothd/src/config/mod.rs", "SRC/neothd/src/config/credentials.rs", "SRC/neothd/src/config/keychain.rs",
    )
    assets = sorted(Path("SRC/neothd/assets/n8n_workflows").glob("*.json"))
    if len(assets) != 3:
        raise Failure("workflow_asset_set_invalid")
    return {name: sha256(Path(name)) for name in names + tuple(asset.as_posix() for asset in assets)}


def source_record(home, port):
    boot = product.read_json(home / "n8n-managed-bootstrap.v2.json")
    runtime = product.read_json(home / "n8n-managed-runtime.v2.json")
    job = boot.get("job_id", "")
    if not isinstance(job, str) or not product.JOB.fullmatch(job):
        raise Failure("source_job_invalid")
    volume, _, identifier = product.validate_custody(boot, runtime, job, port)
    product.validate_runtime(product.docker_inspect(identifier), job, volume, identifier, port)
    return job, boot, volume, identifier


def clear_fixture_secrets(job):
    keys = [f"n8n-bootstrap.{kind}.{job}" for kind in
            ("owner-password", "browser-id", "api-key-label", "captured-api-key")]
    keys.append("n8n_api_key")
    ok = True
    for key in keys:
        try:
            result = product.bounded.run(["secret-tool", "lookup", "neoth-key", key], timeout=10)
            if result.timed_out or result.overflow or result.code not in (0, 1):
                raise Failure("secret_lookup_unproven")
            if result.code == 0:
                raw(["secret-tool", "clear", "neoth-key", key], timeout=10)
            result = product.bounded.run(["secret-tool", "lookup", "neoth-key", key], timeout=10)
            if result.code != 1 or result.timed_out or result.overflow or result.stdout or result.stderr:
                raise Failure("secret_removal_unproven")
        except Exception:
            ok = False
    return ok


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--home", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--port", type=int, default=5681)
    args = parser.parse_args(argv)
    try:
        guard(args.home, args.receipt)
        if not 1 <= args.port <= 65535:
            return 2
    except Exception:
        return 2
    receipt = {"schema": 2, "scenario": "n8n_isolated_migration_feasibility",
               "source_sha": os.environ.get("GITHUB_SHA"), "outcome": "failed", "cleanup_proven": False}
    custody, source, install_attempted = Custody(), None, False
    try:
        receipt["stage"] = "target_admission"
        if not args.binary.is_file() or args.binary.is_symlink():
            raise Failure("binary_invalid")
        receipt["input_sha256"] = input_provenance()
        receipt["binary_sha256"] = sha256(args.binary)
        target_view = admitted(args.binary)
        receipt["stage"] = "source_install"
        install_attempted = True
        installed_job = product.validate_product(product.first_product_install(args.binary, args.home, args.port))
        source = source_record(args.home, args.port)
        job, boot, source_volume, source_id = source
        if job != installed_job:
            raise Failure("source_install_job_mismatch")
        receipt["stage"] = "source_fixture"
        templates = product.workflow_templates(product.read_json_from_command(
            [str(args.binary), "--output", "json", "n8n", "workflows"]))
        product.validate_import_job(product.read_json_bytes(raw(
            [str(args.binary), "--output", "json", "n8n", "import-workflows"])))
        canonical_key = product.canonical_n8n_api_key()
        source_graphs = source_workflows(args.port, canonical_key, templates)
        scoped_key = product.mint_restore_credential_key(job, source_id)
        product.create_restore_fixture_credential(args.port, scoped_key)
        credential_id, credential_name = credential_listing(args.port, scoped_key)
        source_credential = credential_proof(source_id, credential_id, credential_name)
        receipt["stage"] = "stopped_source_backup"
        docker("container", "stop", source_id)
        first_archive, first_backup = backup(args.binary, args.home, job, boot, source_volume, source_id, args.port)
        first_manifest = safe_archive_manifest(first_archive)
        receipt["stage"] = "isolated_copy"
        candidate_volume = custody.volume(candidate_name("candidate"))
        if candidate_volume == source_volume:
            raise Failure("candidate_source_volume_alias")
        image = target_view["runtime_image"]
        seed = create_candidate(custody, image, candidate_volume, "seed", True)
        seed_record = (seed, image, candidate_volume, "seed", candidate_name("seed"))
        custody.validate(*seed_record, running=False)
        copy_archive_to_stopped_seed(first_archive, seed, first_backup)
        custody.validate(*seed_record, running=False)
        docker("container", "rm", seed)
        if not absent("container", seed):
            raise Failure("seed_removal_unproven")
        receipt["stage"] = "target_migration_and_content"
        candidate = create_candidate(custody, image, candidate_volume, "target", False)
        candidate_record = (candidate, image, candidate_volume, "target", candidate_name("target"))
        docker("container", "start", candidate)
        candidate_graphs = candidate_workflows(candidate, canonical_key, templates)
        custody.validate(*candidate_record, running=True)
        candidate_id, candidate_name_value = candidate_credential_listing(candidate, scoped_key)
        if (candidate_id, candidate_name_value) != (credential_id, credential_name):
            raise Failure("candidate_credential_identity_mismatch")
        candidate_credential = credential_proof(candidate, credential_id, credential_name)
        if candidate_graphs != source_graphs or candidate_credential != source_credential:
            raise Failure("candidate_content_mismatch")
        receipt["candidate"] = {"historical_workflow_key_authenticated": True,
            "historical_credential_key_authenticated": True, "unauthenticated_workflows_status": 401,
            "workflow_count": COUNT, "workflow_graph_fields": ["name", "nodes", "connections", "settings", "nodeGroups"],
            "workflow_set_sha256": hashlib.sha256(canonical(candidate_graphs)).hexdigest(),
            "credential_count": 1, "credential_decryption_proven": True, "credential_proof": candidate_credential}
        receipt["stage"] = "source_preservation"
        second_archive, second_backup = backup(args.binary, args.home, job, boot, source_volume, source_id, args.port)
        if safe_archive_manifest(second_archive) != first_manifest:
            raise Failure("stopped_source_content_changed")
        if not custody.cleanup():
            raise Failure("candidate_cleanup_unproven")
        receipt["stage"] = "source_restart"
        docker("container", "start", source_id)
        for _ in range(30):
            try:
                if (source_workflows(args.port, canonical_key, templates) == source_graphs
                        and credential_listing(args.port, scoped_key) == (credential_id, credential_name)
                        and credential_proof(source_id, credential_id, credential_name) == source_credential):
                    break
            except Exception:
                pass
            time.sleep(2)
        else:
            raise Failure("source_restart_content_invalid")
        receipt.update({"target": {key: target_view[key] for key in
            ("selector", "version", "runtime_image", "index_digest", "child_manifest_digest", "config_digest")},
            "source_backups": {"first_sha256": first_backup["archive_sha256"],
                "second_sha256": second_backup["archive_sha256"], "member_manifest_sha256": first_manifest},
            "source_restored": {"workflows": COUNT, "credentials": 1}, "outcome": "passed"})
    except Exception as error:
        receipt["failure_stage"] = str(error) if isinstance(error, Failure) else "unexpected"
        if isinstance(error, product.CommandFailure):
            receipt["command_failure"] = error.diagnostic
    finally:
        candidates, source_cleanup = custody.cleanup(), not install_attempted
        secrets, home_removed = not install_attempted, False
        # A failed CLI may still have published complete Ready custody. Recover
        # only that exact proof; unresolved partial bootstrap remains unproven.
        if install_attempted and source is None:
            try:
                source = source_record(args.home, args.port)
            except Exception:
                receipt["source_cleanup_disposition"] = "unresolved_install_custody_preserved"
        if source is not None:
            job, _, source_volume, source_id = source
            try:
                source_cleanup = product.cleanup_owned_runtime_and_volume(
                    source_id, source_volume, job, args.port, runtime_already_absent=False)
            except Exception:
                source_cleanup = False
            if source_cleanup:
                secrets = clear_fixture_secrets(job)
        if candidates and source_cleanup and secrets:
            try:
                if args.home.is_dir() and not args.home.is_symlink():
                    shutil.rmtree(args.home)
                home_removed = not args.home.exists()
            except Exception:
                pass
        receipt["cleanup"] = {"candidates": candidates, "source": source_cleanup,
                              "bootstrap_and_canonical_secrets": secrets, "isolated_home": home_removed}
        receipt["cleanup_proven"] = candidates and source_cleanup and secrets and home_removed
        if not receipt["cleanup_proven"]:
            receipt["outcome"] = "failed"
        write_receipt(args.receipt, receipt)
    return 0 if receipt["outcome"] == "passed" and receipt["cleanup_proven"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
