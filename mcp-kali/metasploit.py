"""Private, leased Metasploit RPC workspaces reached through HTTP MCP only."""
from __future__ import annotations

import json
import re
import subprocess
import time

import catalog
import provider
import runtime

BOOTSTRAP = r'''
import json,os,pathlib,secrets,subprocess,time,urllib.request,msgpack
state = pathlib.Path('/tmp/.kali-msf.json')
password = secrets.token_hex(32)
def save(value):
    temp = state.with_suffix('.next')
    temp.write_text(json.dumps(value)); os.chmod(temp,0o600); temp.replace(state)
save({'phase':'starting'})
log = open('/tmp/msfrpcd.log','w')
proc = subprocess.Popen(['msfrpcd','-a','127.0.0.1','-p','55553','-U','mcp','-P',password,'-S','-f','-n','-t','900'],stdout=log,stderr=log)
def call(args):
    request = urllib.request.Request('http://127.0.0.1:55553/api/',data=msgpack.packb(args,use_bin_type=True),headers={'Content-Type':'binary/message-pack'})
    with urllib.request.urlopen(request,timeout=5) as response:
        result=msgpack.unpackb(response.read(1048576),raw=False,strict_map_key=False)
        def text(value):
            if isinstance(value,bytes): return value.decode('utf-8',errors='replace')
            if isinstance(value,dict): return {text(k):text(v) for k,v in value.items()}
            if isinstance(value,list): return [text(v) for v in value]
            return value
        return text(result)
try:
    deadline = time.monotonic()+300
    last_error='Waiting for the RPC listener'
    while True:
        if proc.poll() is not None:
            raise RuntimeError('msfrpcd exited: '+pathlib.Path('/tmp/msfrpcd.log').read_text()[-2000:].replace(password,'[redacted]'))
        try:
            auth = call(['auth.login','mcp',password])
            if auth.get('result')=='success':
                token = auth['token']; version = call(['core.version',token]); break
            last_error='RPC did not accept authentication'
        except (OSError,ValueError) as exc:
            last_error=str(exc).replace(password,'[redacted]')[:200]
        save({'phase':'starting','startup_detail':last_error})
        if time.monotonic()>deadline:
            details=pathlib.Path('/tmp/msfrpcd.log').read_text()[-1500:].replace(password,'[redacted]')
            raise TimeoutError('RPC startup exceeded 300 seconds: '+last_error+'; '+details)
        time.sleep(0.5)
    save({'phase':'ready','token':token,'version':version})
    print(json.dumps({'rpc':'ready','version':version}),flush=True)
    if __PROBE_ONLY__:
        proc.terminate(); proc.wait(); raise SystemExit(0)
    raise SystemExit(proc.wait())
finally:
    if proc.poll() is None: proc.terminate()
'''

CLIENT = r'''
import base64,json,pathlib,secrets,sys,urllib.request,urllib.error,msgpack
request = json.load(sys.stdin)
statefile = pathlib.Path('/tmp/.kali-msf.json')
if not statefile.exists():
    print(json.dumps({'ready':False,'phase':'starting'})); raise SystemExit(0)
state = json.loads(statefile.read_text())
if request['op']=='status':
    print(json.dumps({'ready':state.get('phase')=='ready','phase':state.get('phase'),'version':state.get('version'),'startup_detail':state.get('startup_detail')})); raise SystemExit(0)
if state.get('phase')!='ready': raise RuntimeError('RPC is still starting; poll metasploit_status')
args = [request['method'],state['token'],*request['params']]
packet = urllib.request.Request('http://127.0.0.1:55553/api/',data=msgpack.packb(args,use_bin_type=True),headers={'Content-Type':'binary/message-pack'})
try: response=urllib.request.urlopen(packet,timeout=request['timeout_s'])
except urllib.error.HTTPError as error: response=error
with response:
    body=response.read(8388609)
if len(body)>8388608: raise ValueError('RPC response exceeds the 8 MiB limit')
def normalize(value):
    if isinstance(value,bytes):
        try: return value.decode('utf-8')
        except UnicodeDecodeError: return {'encoding':'base64','data':base64.b64encode(value).decode()}
    if isinstance(value,dict): return {str(normalize(k)):normalize(v) for k,v in value.items()}
    if isinstance(value,(tuple,list)): return [normalize(v) for v in value]
    return value
result=normalize(msgpack.unpackb(body,raw=False,strict_map_key=False))
full=json.dumps(result).encode()
if len(full)>8388608: raise ValueError('Normalized RPC result exceeds artifact limits')
artifact=None
if len(full)>60000:
    artifact='/tmp/msf-rpc-'+secrets.token_hex(16)+'.json'
    pathlib.Path(artifact).write_bytes(full)
total=next_offset=None
values = result if isinstance(result,list) else result.get('modules') if isinstance(result,dict) else None
if isinstance(values,list):
    total=len(values); offset,limit=request['offset'],request['limit']
    page=values[offset:offset+limit]; next_offset=offset+limit if offset+limit<total else None
    if isinstance(result,list): result=page
    else: result={**result,'modules':page}
truncated=False
if len(json.dumps(result).encode())>60000:
    result={'preview_json':json.dumps(result)[:4000]}; truncated=True
print(json.dumps({'ready':True,'result':result,'total':total,'next_offset':next_offset,
                  'truncated':truncated,'artifact_path':artifact}))
'''


def open_workspace(target=None, ports="80,443", udp_ports="", memory_mb=1536, lease_s=600):
    catalog.executable("msfrpcd")
    if not 128 <= memory_mb <= min(2048, runtime.limits()["memory_mb"]) or not 60 <= lease_s <= 600:
        raise ValueError("memory_mb must fit the worker budget; lease_s must be 60–600")
    if target:
        provider.resolve_target(target, False)
        from server import parse_ports
        if ports: parse_ports(ports)
        if udp_ports: parse_ports(udp_ports)
        if not ports and not udp_ports: raise ValueError("Declare TCP or UDP ports")
    job = runtime.submit("metasploit", dict(target=target,ports=ports,udp_ports=udp_ports,memory_mb=memory_mb,lease_s=lease_s))
    return status(job["id"])


def run_workspace(target=None, ports="80,443", udp_ports="", memory_mb=1536, lease_s=600):
    from server import parse_ports
    token = runtime.LOCAL.job
    def ready(name):
        with runtime.transaction() as conn:
            conn.execute("INSERT OR REPLACE INTO services VALUES(?,?,?,?)", (token,name,time.time(),time.time()+lease_s))
        runtime.progress("Starting Metasploit RPC; poll metasploit_status")
    result=provider.run_sandboxed(["python3","-"], target or "offline",parse_ports(ports) if target and ports else [],
        target_udp_ports=parse_ports(udp_ports) if target and udp_ports else [],
        network_mode="allowlist" if target else "none",memory_mb=memory_mb,timeout_s=lease_s,
        stdin_text=BOOTSTRAP.replace("__PROBE_ONLY__","False"),on_ready=ready)
    if result.exit_code and not result.cancelled and not result.timed_out:
        raise RuntimeError(result.stderr[-2000:] or "Metasploit RPC worker exited before completion")
    return result.evidence()


def _workspace(token):
    job = runtime.job_status(token)
    if job["kind"]!="metasploit": raise ValueError("Not a Metasploit workspace ID")
    with runtime.db() as conn:
        row = conn.execute("SELECT * FROM services WHERE job_id=?",(token,)).fetchone()
    return job, dict(row) if row else None


def _client(name, request):
    result = subprocess.run(["docker","exec","-i",name,"python3","-c",CLIENT],
        input=json.dumps(request).encode(),capture_output=True,timeout=request.get("timeout_s",5)+10)
    if result.returncode:
        raise ValueError("RPC request failed: "+result.stderr.decode(errors="replace")[-1500:])
    return json.loads(result.stdout)


def status(token):
    job, service = _workspace(token)
    info = {"workspace_id":token,"job":job,"phase":job["state"],"ready":False,
            "lease_expires":service["lease_expires"] if service else None}
    if job["cancel_requested"] and job["state"] not in runtime.TERMINAL:
        info["phase"]="stopping"
    if service and job["state"]=="running" and not job["cancel_requested"]:
        try:
            info.update(_client(service["container"],{"op":"status"}))
            if info.get("ready") and job["progress"]!="Metasploit RPC ready":
                with runtime.transaction() as conn:
                    conn.execute("UPDATE jobs SET progress='Metasploit RPC ready',updated=? WHERE id=? AND state='running'",(time.time(),token))
                info["job"]=runtime.job_status(token)
        except (ValueError,subprocess.SubprocessError):
            info["phase"]="stopping"
    return info


def rpc(token, method, params=None, offset=0, limit=100, timeout_s=30):
    if not re.fullmatch(r"(?:core|module|job|session|console|plugin|db)\.[a-zA-Z0-9_.]+",method):
        raise ValueError("Use a Metasploit core/module/job/session/console/plugin/db RPC method")
    if not 0 <= offset or not 1 <= limit <= 100 or not 1 <= timeout_s <= 60:
        raise ValueError("Invalid pagination or timeout")
    params = params or []
    if len(params)>64 or len(json.dumps(params).encode())>65536:
        raise ValueError("RPC parameters are limited to 64 entries and 64 KiB")
    job, service = _workspace(token)
    if not service or job["state"]!="running" or job["cancel_requested"]:
        raise ValueError("Workspace is not running; poll metasploit_status or open a new workspace")
    reply = _client(service["container"],dict(op="call",method=method,params=params,offset=offset,limit=limit,timeout_s=timeout_s))
    if not reply.get("ready"): raise ValueError("RPC is still starting; poll metasploit_status")
    artifact = None
    path = reply.get("artifact_path")
    if path:
        if not re.fullmatch(r"/tmp/msf-rpc-[0-9a-f]{32}\.json",path): raise ValueError("Invalid RPC artifact path")
        try: artifact = provider._capture_artifact(service["container"],path)
        finally: provider._run(["docker","exec",service["container"],"rm","-f",path],check=False)
    data=reply["result"]
    error=isinstance(data,dict) and bool(data.get("error") or data.get("result")=="failure")
    return dict(workspace_id=token,method=method,result=data,error=error,total=reply["total"],
                next_offset=reply["next_offset"],truncated=reply["truncated"],artifact=artifact)


def close_workspace(token):
    _workspace(token)
    runtime.cancel_job(token)
    return status(token)


def probe():
    return provider.run_sandboxed(["python3","-"],"offline",[],network_mode="none",memory_mb=1536,
        timeout_s=360,stdin_text=BOOTSTRAP.replace("__PROBE_ONLY__","True"))
