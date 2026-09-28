#!/usr/bin/env python3
"""Static, fail-closed extractor for pinned OpenClaw bundled channel schemas."""
from __future__ import annotations
import argparse, ast, hashlib, json, pathlib, re
from collections.abc import Mapping

COMMIT="4c667aac8859114bd8f0a589ac6cd1de8bfe1474"
RAW_BYTES=292905
RAW_SHA256="28f31fd9eddfef5536ab5ec52136435cfc300cc52bff042f482f5e132f6d78bb"
INVENTORY_SHA256="54e9966a4508b8259bb6a05f88dd53daa9b827754b6b96fe0bda4bb516b753e9"
GIT_BLOB="b17cdc59ca46a10dd71f00044950090d68bf66c8"
RAW=re.compile(r'const RAW_BUNDLED_CHANNEL_CONFIG_METADATA = \[([\s\S]*?)\]\.join\(""\);')
MAX_DEPTH=96
ANNOTATIONS = {"$schema", "$id", "title", "description", "default", "examples", "deprecated", "readOnly", "writeOnly", "definitions", "$defs"}
SCALAR_CONSTRAINTS = {"enum", "const", "format", "pattern", "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"}

def digest(b): return hashlib.sha256(b).hexdigest()
def join(path, part): return f"{path}.{part}" if path else part

def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()

VALID_DISPOSITIONS={"mapped","needs_secret","needs_relink","needs_runtime","unsupported","unknown"}
VALID_ACTIONS={"direct_credential_mapping","neoth_credential_flow","relink_required","runtime_prerequisite_required","requires_target_contract","requires_neoth_adapter","requires_account_scoped_runtime","blocked_requires_explicit_leaf_mapping"}
ACTION_BY_DISPOSITION={"mapped":{"direct_credential_mapping"},"needs_secret":{"neoth_credential_flow"},"needs_relink":{"relink_required"},"needs_runtime":{"runtime_prerequisite_required"},"unsupported":{"requires_target_contract","requires_neoth_adapter","requires_account_scoped_runtime"},"unknown":{"blocked_requires_explicit_leaf_mapping"}}
POLICY_NAME="neoth-openclaw-channel-schema-migration-policy-v1"
POLICY_SOURCE={"repository":"openclaw/openclaw","commit":COMMIT,"metadata_path":"src/config/bundled-channel-config-metadata.generated.ts"}
POLICY_KEYS={"policy_name","policy_version","source","rows","synthetic"}
ROW_KEYS={"channel_id","path_template","json_type","scope","disposition","action_id","target_path"}
SINGLETON_SYNTHETIC_OUTCOMES={
    "account_container": ("unsupported", "requires_account_scoped_runtime"),
    "account_container_unmapped": ("unknown", "blocked_requires_explicit_account_mapping"),
    "whatsapp_auth_dir_string": ("needs_relink", "relink_required"),
}
SINGLETON_SYNTHETIC_KEYS={
    "account_container": {"kind","disposition","action_id"},
    "account_container_unmapped": {"kind","disposition","action_id"},
    "whatsapp_auth_dir_string": {"kind","channel_id","path_template","json_type","disposition","action_id"},
}
SECRET_REF_FAMILY_KEYS={"kind","channel_id","path_template","disposition","action_id","target_path"}

def is_secret_ref_family_parent(path_template):
    component=path_template.rsplit(".",1)[-1]
    return "{anyOf:" in component and "{oneOf:" in component

def policy_outcome_is_valid(disposition, action_id, target_present):
    return action_id in ACTION_BY_DISPOSITION.get(disposition, set()) and (disposition in {"mapped","needs_secret"}) == target_present

def validate_migration_policy(channels, policy):
    """Verify the separate policy overlay without changing source-derived leaves."""
    if not isinstance(policy, Mapping):
        raise ValueError("invalid migration policy")
    if set(policy) != POLICY_KEYS: raise ValueError("invalid migration policy fields")
    if policy.get("policy_name") != POLICY_NAME: raise ValueError("invalid migration policy name")
    if type(policy.get("policy_version")) is not int or policy["policy_version"] != 1: raise ValueError("invalid migration policy version")
    if policy.get("source") != POLICY_SOURCE: raise ValueError("invalid migration policy source pins")
    if not isinstance(policy.get("rows"), list): raise ValueError("invalid migration policy rows")
    if not isinstance(policy.get("synthetic"), list): raise ValueError("invalid migration policy synthetic")
    indexed={}
    for row in policy["rows"]:
        if not isinstance(row, Mapping): raise ValueError("invalid migration policy row")
        if not set(row) <= ROW_KEYS: raise ValueError("invalid migration policy row fields")
        key=tuple(row.get(k) for k in ("channel_id","path_template","json_type","scope"))
        if not all(isinstance(x,str) and x for x in key): raise ValueError(f"invalid migration policy identity:{key}")
        if row["scope"] not in {"typed_leaf","opaque_subtree"}: raise ValueError(f"invalid migration policy identity:{key}")
        if key in indexed: raise ValueError(f"duplicate migration policy identity:{key}")
        if row.get("disposition") not in VALID_DISPOSITIONS or row.get("action_id") not in ACTION_BY_DISPOSITION.get(row.get("disposition"),set()): raise ValueError(f"invalid migration policy outcome:{key}")
        needs_target=row["disposition"] in {"mapped","needs_secret"}
        if needs_target and not (isinstance(row.get("target_path"),str) and row["target_path"]): raise ValueError(f"invalid migration policy target:{key}")
        if not needs_target and "target_path" in row: raise ValueError(f"invalid migration policy target:{key}")
        indexed[key]=row
    source_leaf_keys=set()
    for channel in channels:
        if not isinstance(channel, Mapping) or not isinstance(channel.get("channel_id"), str) or not isinstance(channel.get("leaves"), list):
            raise ValueError("invalid extracted channel")
        for leaf in channel["leaves"]:
            if not isinstance(leaf, Mapping): raise ValueError("invalid extracted leaf")
            scope=leaf.get("scope", "typed_leaf")
            if scope not in {"typed_leaf","opaque_subtree"}: raise ValueError("invalid extracted leaf scope")
            identity=(channel["channel_id"],leaf.get("path_template"),leaf.get("json_type"),scope)
            if not all(isinstance(value, str) and value for value in identity): raise ValueError("invalid extracted leaf identity")
            source_leaf_keys.add(identity)
    expected_secret_ref_families={
        (channel_id, path_template.removesuffix(".id"))
        for channel_id, path_template, json_type, scope in source_leaf_keys
        if json_type == "string" and scope == "typed_leaf" and path_template.endswith(".id")
        and is_secret_ref_family_parent(path_template.removesuffix(".id"))
        and all((channel_id, path_template.removesuffix(".id") + suffix, "string", "typed_leaf") in source_leaf_keys for suffix in (".source", ".provider"))
    }
    synthetic={}
    secret_ref_families=set()
    for item in policy["synthetic"]:
        if not isinstance(item, Mapping) or not isinstance(item.get("kind"), str): raise ValueError("invalid migration policy synthetic")
        kind=item["kind"]
        if kind == "secret_ref_family":
            if not (SECRET_REF_FAMILY_KEYS - {"target_path"}) <= set(item) <= SECRET_REF_FAMILY_KEYS: raise ValueError("invalid migration policy secret_ref_family fields")
            family=(item.get("channel_id"),item.get("path_template"))
            if not all(isinstance(value,str) and value for value in family): raise ValueError(f"invalid migration policy secret_ref_family identity:{family}")
            if family in secret_ref_families: raise ValueError(f"duplicate migration policy secret_ref_family:{family}")
            target_present=isinstance(item.get("target_path"),str) and bool(item["target_path"])
            if not policy_outcome_is_valid(item.get("disposition"),item.get("action_id"),target_present): raise ValueError(f"invalid migration policy secret_ref_family outcome:{family}")
            if item.get("disposition") in {"mapped","needs_secret"} and not target_present: raise ValueError(f"invalid migration policy secret_ref_family target:{family}")
            if item.get("disposition") not in {"mapped","needs_secret"} and "target_path" in item: raise ValueError(f"invalid migration policy secret_ref_family target:{family}")
            if not is_secret_ref_family_parent(item["path_template"]): raise ValueError(f"invalid migration policy secret_ref_family parent:{family}")
            secret_ref_families.add(family)
            continue
        if kind not in SINGLETON_SYNTHETIC_OUTCOMES: raise ValueError(f"unknown migration policy synthetic:{kind}")
        if set(item) != SINGLETON_SYNTHETIC_KEYS[kind]: raise ValueError(f"invalid migration policy synthetic fields:{kind}")
        if kind in synthetic: raise ValueError(f"duplicate migration policy synthetic:{kind}")
        if (item.get("disposition"),item.get("action_id")) != SINGLETON_SYNTHETIC_OUTCOMES[kind]: raise ValueError(f"invalid migration policy synthetic outcome:{kind}")
        if kind == "whatsapp_auth_dir_string" and (item.get("channel_id"),item.get("path_template"),item.get("json_type")) != ("whatsapp","authDir","string"):
            raise ValueError("invalid migration policy synthetic identity:whatsapp_auth_dir_string")
        synthetic[kind]=item
    missing_synthetic=set(SINGLETON_SYNTHETIC_OUTCOMES)-set(synthetic)
    if missing_synthetic: raise ValueError(f"missing migration policy synthetic:{sorted(missing_synthetic)[0]}")
    missing_families=expected_secret_ref_families-secret_ref_families
    if missing_families: raise ValueError(f"missing migration policy secret_ref_family:{sorted(missing_families)[0]}")
    extra_families=secret_ref_families-expected_secret_ref_families
    if extra_families: raise ValueError(f"extra migration policy secret_ref_family:{sorted(extra_families)[0]}")
    for channel in channels:
        for leaf in channel["leaves"]:
            scope=leaf.get("scope", "typed_leaf")
            key=(channel["channel_id"],leaf["path_template"],leaf["json_type"],scope)
            row=indexed.pop(key,None)
            if row is None: raise ValueError(f"missing migration policy identity:{key}")
    if indexed: raise ValueError(f"extra migration policy identity:{sorted(indexed)[0]}")

def decode_static_metadata(raw):
    match = RAW.search(raw.decode("utf-8"))
    if not match:
        raise ValueError("static bundled channel metadata payload not found")
    chunks = ast.literal_eval("[" + match.group(1) + "]")
    if not isinstance(chunks, list) or not all(isinstance(chunk, str) for chunk in chunks):
        raise ValueError("static payload must be an array of strings")
    metadata = json.loads("".join(chunks))
    if not isinstance(metadata, list):
        raise ValueError("decoded metadata must be an array")
    return metadata

def resolve(root, ref):
    if ref == "#": return root
    if not ref.startswith("#/"): raise ValueError(f"external_ref:{ref}")
    value=root
    for p in ref[2:].split("/"):
        p=p.replace("~1","/").replace("~0","~")
        if not isinstance(value,Mapping) or p not in value: raise ValueError(f"unresolved_ref:{ref}")
        value=value[p]
    return value

def walk(root, node, path, leaves, blockers, stack, depth=0):
    if depth>MAX_DEPTH: blockers.append({"path":path,"reason":"schema_depth_exceeded"}); return
    if not isinstance(node,Mapping): blockers.append({"path":path,"reason":"schema_node_not_object"}); return
    marker=id(node)
    if marker in stack: blockers.append({"path":path,"reason":"recursive_schema_cycle"}); return
    stack.add(marker)
    try:
        if not node:
            # JSON Schema {} explicitly admits arbitrary JSON. Preserve that
            # open subtree instead of inventing nested fields or adapter support.
            leaves.append({"path_template": path, "json_type": "any", "scope": "opaque_subtree", "disposition": "blocked_requires_explicit_leaf_mapping"})
            return

        def keys_allowed(allowed):
            unknown = sorted(set(node) - ANNOTATIONS - allowed)
            blockers.extend({"path": path, "reason": f"unsupported_schema_keyword:{key}"} for key in unknown)
            return not unknown

        if "$ref" in node:
            if not keys_allowed({"$ref"}): return
            try: walk(root,resolve(root,str(node["$ref"])),path,leaves,blockers,stack,depth+1)
            except ValueError as e: blockers.append({"path":path,"reason":str(e)})
            return
        compositions=[k for k in ("allOf","anyOf","oneOf") if k in node]
        if compositions:
            if len(compositions)!=1 or not keys_allowed({compositions[0]}): blockers.append({"path":path,"reason":"mixed_composition_schema"}); return
            branches=node[compositions[0]]
            if not isinstance(branches,list) or not branches: blockers.append({"path":path,"reason":f"invalid_{compositions[0]}"}); return
            for i,b in enumerate(branches): walk(root,b,f"{path}{{{compositions[0]}:{i}}}",leaves,blockers,stack,depth+1)
            return
        kind=node.get("type")
        if kind=="object" or "properties" in node or "additionalProperties" in node:
            if not keys_allowed({"type", "properties", "additionalProperties", "required", "propertyNames", "minProperties", "maxProperties"}): return
            if kind not in (None, "object"): blockers.append({"path":path,"reason":"mixed_object_type"}); return
            if "propertyNames" in node:
                key_leaves = []
                walk(root, node["propertyNames"], join(path, "{key-name}"), key_leaves, blockers, stack, depth+1)
                if not key_leaves or any(leaf["json_type"] != "string" for leaf in key_leaves):
                    blockers.append({"path":path,"reason":"unsupported_property_names"})
            props=node.get("properties",{})
            if not isinstance(props,Mapping): blockers.append({"path":path,"reason":"invalid_properties"})
            else:
                for name in sorted(props): walk(root,props[name],join(path,name),leaves,blockers,stack,depth+1)
            if "additionalProperties" not in node or node["additionalProperties"] is True:
                blockers.append({"path":path,"reason":"open_additional_properties"})
            elif isinstance(node["additionalProperties"],Mapping): walk(root,node["additionalProperties"],join(path,"{key}"),leaves,blockers,stack,depth+1)
            elif node["additionalProperties"] is not False: blockers.append({"path":path,"reason":"invalid_additionalProperties"})
            return
        if kind=="array" or "items" in node:
            if not keys_allowed({"type", "items", "minItems", "maxItems", "uniqueItems", "additionalItems"}): return
            if kind not in (None, "array"): blockers.append({"path":path,"reason":"mixed_array_type"}); return
            items=node.get("items")
            if isinstance(items,Mapping): walk(root,items,path+"[]",leaves,blockers,stack,depth+1)
            elif isinstance(items,list):
                for i,item in enumerate(items): walk(root,item,f"{path}[{i}]",leaves,blockers,stack,depth+1)
                extra = node.get("additionalItems", True)
                if isinstance(extra, Mapping): walk(root,extra,path+"[additional]",leaves,blockers,stack,depth+1)
                elif extra is not False: blockers.append({"path":path,"reason":"open_additional_items"})
            else: blockers.append({"path":path,"reason":"array_without_valid_items"})
            return
        if not keys_allowed({"type"} | SCALAR_CONSTRAINTS): return
        if isinstance(kind, str) and kind in {"string","number","integer","boolean","null"}: leaves.append({"path_template":path,"json_type":kind}); return
        blockers.append({"path":path,"reason":f"unsupported_schema_keyword_or_type:{kind!r}"})
    finally: stack.remove(marker)

def main():
    p=argparse.ArgumentParser(); p.add_argument("--metadata",type=pathlib.Path,required=True); p.add_argument("--channel-inventory",type=pathlib.Path,required=True); p.add_argument("--migration-policy",type=pathlib.Path,default=pathlib.Path(__file__).parent.parent / "SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_migration_policy_v1.json"); p.add_argument("--commit",required=True); p.add_argument("--inventory",type=pathlib.Path,required=True); p.add_argument("--evidence",type=pathlib.Path,required=True); a=p.parse_args()
    if a.commit!=COMMIT: raise SystemExit("unexpected OpenClaw commit")
    raw=a.metadata.read_bytes()
    if len(raw)!=RAW_BYTES or digest(raw)!=RAW_SHA256 or git_blob(raw)!=GIT_BLOB: raise SystemExit("pinned metadata bytes, SHA-256, or Git blob mismatch")
    inv=a.channel_inventory.read_bytes()
    if digest(inv)!=INVENTORY_SHA256: raise SystemExit("pinned channel inventory SHA-256 mismatch")
    try: rows=json.loads(inv)["rows"]
    except (json.JSONDecodeError,KeyError,TypeError) as e: raise SystemExit(f"invalid pinned channel inventory: {e}")
    if not isinstance(rows,list) or any(not isinstance(x,Mapping) for x in rows): raise SystemExit("invalid pinned channel inventory rows")
    if any(x.get("source",{}).get("commit")!=COMMIT for x in [json.loads(inv)]): raise SystemExit("channel inventory source commit mismatch")
    expected={x.get("canonical_id") for x in rows if x.get("manifest_backed")}
    if None in expected or len(expected)!=26: raise SystemExit("invalid manifest-backed channel ID set")
    try: metadata = decode_static_metadata(raw)
    except (SyntaxError,ValueError,json.JSONDecodeError) as e: raise SystemExit(f"invalid static metadata payload: {e}")
    ids=[]; channels=[]; blockers=[]
    for entry in metadata:
        if not isinstance(entry,Mapping) or not isinstance(entry.get("channelId"),str) or not isinstance(entry.get("schema"),Mapping): blockers.append({"channel":entry.get("channelId") if isinstance(entry,Mapping) else None,"path":"","reason":"missing_or_invalid_channel_schema"}); continue
        cid=entry["channelId"]; ids.append(cid); leaves=[]; local=[]; walk(entry["schema"],entry["schema"],"",leaves,local,set()); channels.append({"plugin_id":entry.get("pluginId"),"channel_id":cid,"aliases":entry.get("aliases",[]),"account_template_present":any(x["path_template"].startswith("accounts.{key}") for x in leaves),"default_account_present":any(x["path_template"]=="defaultAccount" for x in leaves),"leaves":leaves,"blockers":local}); blockers.extend({"channel":cid,**x} for x in local)
    observed=set(ids)
    if len(ids)!=len(observed): blockers.append({"channel":None,"path":"","reason":"duplicate_channel_id"})
    if observed!=expected: blockers.append({"channel":None,"path":"","reason":"manifest_id_set_mismatch","expected_ids":sorted(expected),"observed_ids":sorted(observed)})
    channels.sort(key=lambda x:x["channel_id"])
    try: policy_bytes=a.migration_policy.read_bytes(); policy=json.loads(policy_bytes); validate_migration_policy(channels,policy)
    except (OSError,json.JSONDecodeError,ValueError) as e: raise SystemExit(f"migration policy refusal: {e}")
    a.inventory.write_text(json.dumps({"schema_version":1,"source":{"repository":"openclaw/openclaw","commit":a.commit,"metadata_path":"src/config/bundled-channel-config-metadata.generated.ts"},"channels":channels,"uncovered_blockers":blockers},indent=2,sort_keys=True)+"\n",encoding="utf-8")
    a.evidence.write_text(json.dumps({"schema_version":1,"source_path":"src/config/bundled-channel-config-metadata.generated.ts","sha256":digest(raw),"bytes":len(raw),"git_blob":GIT_BLOB,"channel_inventory_sha256":digest(inv),"migration_policy_sha256":digest(policy_bytes),"migration_policy_name":policy["policy_name"],"migration_policy_version":policy["policy_version"],"migration_policy_source":policy["source"],"expected_channel_ids":sorted(expected),"observed_channel_ids":sorted(observed),"uncovered_blocker_count":len(blockers)},indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return 0 if not blockers else 2
if __name__=="__main__": raise SystemExit(main())
