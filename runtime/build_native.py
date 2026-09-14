"""Build the pinned OpenSSL SRTP state engine; no system library fallback."""
import argparse, hashlib, json, os, pathlib, subprocess
p=argparse.ArgumentParser()
p.add_argument('--meson',required=True); p.add_argument('--build',type=pathlib.Path,required=True)
p.add_argument('--prefix',type=pathlib.Path,required=True)
p.add_argument('--openssl-prefix',type=pathlib.Path,required=True); p.add_argument('--jobs',type=int,default=2)
a=p.parse_args(); source=pathlib.Path(__file__).resolve().parents[1]
env=dict(os.environ);env['PATH']=str(pathlib.Path(a.meson).resolve().parent)+os.pathsep+env.get('PATH','')
env['PKG_CONFIG_PATH']=str(a.openssl_prefix/'lib/pkgconfig')
revision=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
if subprocess.check_output(['git','-C',str(source),'status','--porcelain'],text=True).strip():
 raise SystemExit('Build provenance requires a committed, clean SRTP source checkout')
command=[a.meson,'setup',str(a.build.resolve()),str(source),'--prefix='+str(a.prefix.resolve()),
 '--buildtype=release','--default-library=shared','-Dcrypto-library=openssl','-Dtests=disabled',
 '-Dpcap-tests=disabled','-Ddoc=disabled','-Ddebug-logging=false','-Dlog-stdout=false','-Dlog-file=']
if (a.build/'meson-private/coredata.dat').exists(): command.extend(['--reconfigure','--clearcache'])
subprocess.run(command,env=env,check=True)
subprocess.run([a.meson,'compile','-C',str(a.build),'-j',str(a.jobs)],env=env,check=True)
subprocess.run([a.meson,'install','-C',str(a.build),'--no-rebuild'],env=env,check=True)
artifacts={str(path.relative_to(a.prefix)):hashlib.sha256(path.read_bytes()).hexdigest()
 for folder in ['lib','bin','include'] if (a.prefix/folder).exists()
 for path in (a.prefix/folder).rglob('*') if path.is_file() and not path.is_symlink()}
(a.prefix/'build.json').write_text(json.dumps({'source_commit':revision,'source':str(source),
 'configuration':command,'artifacts':artifacts},indent=2)+'\n')
