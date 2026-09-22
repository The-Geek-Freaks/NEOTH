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
    p=argparse.ArgumentParser(); p.add_argument("--metadata",type=pathlib.Path,required=True); p.add_argument("--channel-inventory",type=pathlib.Path,required=True); p.add_argument("--commit",required=True); p.add_argument("--inventory",type=pathlib.Path,required=True); p.add_argument("--evidence",type=pathlib.Path,required=True); a=p.parse_args()
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
    a.inventory.write_text(json.dumps({"schema_version":1,"source":{"repository":"openclaw/openclaw","commit":a.commit,"metadata_path":"src/config/bundled-channel-config-metadata.generated.ts"},"channels":channels,"uncovered_blockers":blockers},indent=2,sort_keys=True)+"\n",encoding="utf-8")
    a.evidence.write_text(json.dumps({"schema_version":1,"source_path":"src/config/bundled-channel-config-metadata.generated.ts","sha256":digest(raw),"bytes":len(raw),"git_blob":GIT_BLOB,"channel_inventory_sha256":digest(inv),"expected_channel_ids":sorted(expected),"observed_channel_ids":sorted(observed),"uncovered_blocker_count":len(blockers)},indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return 0 if not blockers else 2
if __name__=="__main__": raise SystemExit(main())
