"""Typed HTTP Nuclei scans using pinned, server-owned template revisions."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit

import yaml
import catalog
import provider
import runtime

SEVERITIES = ("info","low","medium","high","critical","unknown")
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
BOOTSTRAP = r'''
import base64,json,os,pathlib,sys
data=json.load(sys.stdin)
folder=pathlib.Path('/tmp/nuclei-templates'); folder.mkdir()
for entry in data['templates']:
    (folder/(entry['id']+'.yaml')).write_bytes(base64.b64decode(entry['data']))
os.environ['GOMEMLIMIT']='384MiB'
os.execvp('nuclei',['nuclei',*data['args']])
'''


def metadata(data):
    if len(data)>65536: raise ValueError("A template must fit within 64 KiB")
    item=yaml.load(data,Loader=getattr(yaml,"CSafeLoader",yaml.SafeLoader))
    if not isinstance(item,dict) or not isinstance(item.get("id"),str) or not IDENTIFIER.fullmatch(item["id"]):
        raise ValueError("Template must have a valid id")
    if not ("http" in item or "requests" in item) or any(key in item for key in (
        "code","javascript","headless","dns","network","tcp","ssl","websocket","file","workflows")):
        raise ValueError("The typed scanner accepts HTTP templates only")
    info=item.get("info",{})
    if not isinstance(info,dict): raise ValueError("Template info must be a mapping")
    tags=info.get("tags",[])
    if isinstance(tags,str): tags=tags.split(",")
    if not isinstance(tags,list) or any(not isinstance(tag,str) for tag in tags):
        raise ValueError("Template tags must be strings")
    severity=str(info.get("severity","unknown")).lower()
    return {"id":item["id"],"name":str(info.get("name",""))[:256],
            "severity":severity if severity in SEVERITIES else "unknown",
            "tags":[tag.strip()[:64] for tag in tags[:64]],"sha256":hashlib.sha256(data).hexdigest()}


def template_catalog():
    root=Path(os.environ.get("MCP_KALI_NUCLEI_TEMPLATES","/opt/kali-mcp/nuclei-templates")).resolve()
    manifest=root/"index.json"
    if not manifest.is_file():
        return root,{"revision":None,"templates":[],"note":"Install the template catalog with install-nuclei-templates.py; inline HTTP templates are also supported"}
    return root,json.loads(manifest.read_text())


def search(query="",severity=None,tags=None,offset=0,limit=25):
    if len(query)>512 or offset<0 or not 1<=limit<=100: raise ValueError("Invalid query or pagination")
    if tags and (len(tags)>20 or any(len(tag)>64 for tag in tags)): raise ValueError("Use at most 20 tags of 64 characters")
    if severity and any(value not in SEVERITIES for value in severity): raise ValueError("Invalid severity")
    _,manifest=template_catalog()
    words=query.casefold().split()
    required={value.casefold() for value in (tags or [])}
    rows=[row for row in manifest["templates"] if
          all(word in (row["id"]+" "+row["name"]+" "+" ".join(row["tags"])).casefold() for word in words)
          and (not severity or row["severity"] in severity)
          and required.issubset({tag.casefold() for tag in row["tags"]})]
    rows.sort(key=lambda row:(row["id"]!=query,row["id"]))
    return {"revision":manifest["revision"],"total":len(rows),"offset":offset,
            "templates":rows[offset:offset+limit],"next_offset":offset+limit if offset+limit<len(rows) else None,
            "note":manifest.get("note")}


def prepare(url,template_ids=None,template_yaml=None,rate_limit=10,concurrency=2,timeout_s=180,headers=None):
    catalog.executable("nuclei")
    parsed=urlsplit(url)
    if parsed.scheme not in ("http","https") or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL must be HTTP(S), without credentials or fragment")
    port=parsed.port or (443 if parsed.scheme=="https" else 80)
    if not 1<=port<=65535 or not 1<=rate_limit<=50 or not 1<=concurrency<=5 or not 1<=timeout_s<=600:
        raise ValueError("Invalid port, rate limit, concurrency or timeout")
    host=parsed.hostname.encode("idna").decode()
    provider.resolve_target(host,False)
    ids=template_ids or []
    if len(ids)>32 or any(not IDENTIFIER.fullmatch(value) for value in ids): raise ValueError("Choose at most 32 valid template IDs")
    if not ids and not template_yaml: raise ValueError("Select template_ids from nuclei_templates or supply an inline HTTP template_yaml")
    root,manifest=template_catalog()
    indexed={row["id"]:row for row in manifest["templates"]}
    templates={}
    for identifier in ids:
        if identifier not in indexed: raise ValueError(f"Unknown template {identifier}; use nuclei_templates")
        row=indexed[identifier]; path=(root/row["path"]).resolve()
        if not path.is_relative_to(root): raise ValueError("Template path escapes the catalog")
        data=path.read_bytes()
        if hashlib.sha256(data).hexdigest()!=row["sha256"]: raise ValueError("Template changed since indexing; rebuild the catalog")
        metadata(data)
        templates[identifier]=data
    if template_yaml:
        data=template_yaml.encode(); meta=metadata(data); templates[meta["id"]]=data
    if len(templates)>32 or sum(len(data) for data in templates.values())>262144:
        raise ValueError("A scan is limited to 32 templates and 256 KiB of template source")
    netloc=host + (f":{port}" if parsed.port else "")
    url=urlunsplit((parsed.scheme,"{target_ip}:"+str(port),parsed.path or "/",parsed.query,""))
    args=["-u",url,"-t","/tmp/nuclei-templates","-type","http","-duc","-ni","-dr",
          "-jsonl","-silent","-nc","-timeout","8","-retries","0","-rl",str(rate_limit),
          "-c",str(concurrency),"-bs","1","-o","/tmp/nuclei-results.jsonl","-sni",host,"-H",f"Host: {netloc}"]
    if headers and (len(headers)>20 or sum(len(k)+len(v) for k,v in headers.items())>4096):
        raise ValueError("Headers are limited to 20 fields and 4 KiB")
    for key,value in (headers or {}).items():
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",key) or "\r" in value or "\n" in value:
            raise ValueError("Invalid HTTP header")
        if key.lower()=="host":
            if value!=netloc: raise ValueError("Host header must match the declared URL")
            continue
        args.extend(["-H",f"{key}: {value}"])
    return {"host":host,"port":port,"timeout_s":timeout_s,"revision":manifest["revision"],
            "payload":{"args":args,"templates":[{"id":key,"data":base64.b64encode(data).decode()} for key,data in templates.items()]}}


def submit(**request):
    prepared=prepare(**request)
    return runtime.submit("nuclei",prepared)


def run_scan(host,port,timeout_s,revision,payload):
    ip=provider.resolve_target(host,False)
    payload={**payload,"args":[arg.replace("{target_ip}",ip) for arg in payload["args"]]}
    result=provider.run_sandboxed(["python3","-c",BOOTSTRAP,"nuclei"],ip,[port],timeout_s=timeout_s,
        stdin_text=json.dumps(payload),memory_mb=512,artifact_paths=["/tmp/nuclei-results.jsonl"])
    evidence=result.evidence()
    evidence["target_host"]=host
    evidence["sandbox"]["nuclei_template_revision"]=revision
    return evidence
