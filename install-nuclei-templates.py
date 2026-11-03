"""Install an explicit official template release; no runtime template downloads."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import tempfile
import urllib.request
import yaml

sys.path.insert(0,str(Path(__file__).resolve().parent/"mcp-kali"))
from nuclei import metadata


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref",default="v10.5.1",help="Pinned projectdiscovery/nuclei-templates tag or commit")
    parser.add_argument("--base",default="/opt/kali-mcp")
    args=parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}",args.ref): raise ValueError("Invalid revision")
    base=Path(args.base).resolve(); releases=base/"nuclei-template-releases"; releases.mkdir(parents=True,exist_ok=True)
    destination=releases/args.ref
    if not (destination/"index.json").is_file():
        url=f"https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/{args.ref}"
        with tempfile.TemporaryDirectory(dir=releases,prefix="download-") as temporary:
            folder=Path(temporary); archive_path=folder/"download.tar.gz"
            with urllib.request.urlopen(url,timeout=60) as response, archive_path.open("wb") as stream:
                total=0
                while chunk:=response.read(1048576):
                    total+=len(chunk)
                    if total>134217728: raise ValueError("Template archive exceeds 128 MiB")
                    stream.write(chunk)
            stage=folder/"release"; stage.mkdir(); records={}; expanded=0
            with tarfile.open(archive_path,"r|gz") as archive:
                for member in archive:
                    parts=PurePosixPath(member.name).parts
                    if not member.isfile() or member.size>65536 or len(parts)<2 or ".." in parts or "\\" in member.name: continue
                    relative=PurePosixPath(*parts[1:])
                    if relative.name=="LICENSE" and len(parts)==2:
                        (stage/"LICENSE").write_bytes(archive.extractfile(member).read()); continue
                    if relative.parts[0]!="http" or relative.suffix not in (".yaml",".yml"): continue
                    data=archive.extractfile(member).read()
                    try: info=metadata(data)
                    except (ValueError,TypeError,yaml.YAMLError): continue
                    if info["id"] in records: continue
                    expanded+=len(data)
                    if expanded>134217728: raise ValueError("Selected template source exceeds 128 MiB")
                    path=stage/str(relative); path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data)
                    records[info["id"]]={**info,"path":str(relative)}
            if not records: raise ValueError("No supported HTTP templates found")
            (stage/"index.json").write_text(json.dumps({"revision":args.ref,"templates":sorted(records.values(),key=lambda x:x["id"])}))
            stage.rename(destination)
    link=base/"nuclei-templates"; pending=base/"nuclei-templates.next"
    if link.exists() and not link.is_symlink(): raise ValueError("Existing template path is not a managed symlink")
    pending.unlink(missing_ok=True); pending.symlink_to(destination,target_is_directory=True); os.replace(pending,link)
    index=json.loads((destination/"index.json").read_text())
    print(f"Installed {len(index['templates'])} HTTP templates from {args.ref}")


if __name__=="__main__": main()
