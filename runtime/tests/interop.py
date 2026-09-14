"""Compile independent stock/native peers; compare packets across fresh restores."""
import argparse, pathlib, subprocess, tempfile
p=argparse.ArgumentParser(); p.add_argument('--stock-prefix',type=pathlib.Path,required=True)
p.add_argument('--runtime-build',type=pathlib.Path,required=True); a=p.parse_args()
source=pathlib.Path(__file__).resolve().parent; root=source.parents[1]
with tempfile.TemporaryDirectory(prefix='imapipe-srtp-interop-') as directory:
 d=pathlib.Path(directory)
 for name,prefix,extra in [('stock',a.stock_prefix,[]),('runtime',a.runtime_build,['-DRUNTIME_PEER','-I'+str(root/'include')])]:
  lib=prefix/'lib' if name=='stock' else prefix
  subprocess.run(['cc',str(source/'interop.c'),'-I'+str(prefix/'include/srtp2'),*extra,'-L'+str(lib),'-Wl,-rpath,'+str(lib),'-lsrtp2','-o',str(d/name)],check=True)
 for profile in (1,2,3):
  for sender,receiver in [('runtime','stock'),('stock','runtime')]:
   wire=subprocess.check_output([str(d/sender),str(profile),'1'])
   subprocess.run([str(d/receiver),str(profile),'0'],input=wire,check=True)
   print(f'profile {profile}: {sender} -> {receiver}, 400 RTP/SRTCP packets, 400 runtime restores passed')
