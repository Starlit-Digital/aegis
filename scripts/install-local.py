#!/usr/bin/env python3
"""Install only into a user local prefix, with an inspectable receipt."""
import argparse, hashlib, json, pathlib, shutil, subprocess, datetime
p=argparse.ArgumentParser();p.add_argument('--prefix',default=str(pathlib.Path.home()/'.local'));args=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];prefix=pathlib.Path(args.prefix).expanduser().resolve()
if prefix != (pathlib.Path.home()/'.local').resolve():
    raise SystemExit('aegis installs only into ~/.local; use make compile for other destinations')
source=root/'build/aegis';dest=prefix/'bin/aegis';dest.parent.mkdir(parents=True,exist_ok=True)
shutil.copy2(source,dest);dest.chmod(0o755)
def git(*args):
    return subprocess.check_output(['git','-C',str(root),*args],text=True).strip()
receipt={'source_checkout':str(root),'commit':git('rev-parse','HEAD'),'dirty':bool(git('status','--porcelain')),'binary_sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'version':(root/'VERSION').read_text().strip(),'installed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
state=prefix/'share/aegis';state.mkdir(parents=True,exist_ok=True);(state/'install-info.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(f'Installed {dest}; service remains stopped and disabled')
