#!/usr/bin/env python3
# socat TCP-LISTEN:2323,reuseaddr,fork EXEC:"./deploy.py"
import tempfile
import pathlib
import os
import string
import time
import random
import json

if not os.path.exists('/tmp/ips.json'):
    f = open('/tmp/ips.json', 'w')
    f.write('{}')
    f.close()

ipFile = open('/tmp/ips.json', 'r+')
peerIp = "0.0.0.0"


os.chdir(pathlib.Path(__file__).parent.resolve())

fname = None
with tempfile.NamedTemporaryFile(delete=False) as tmp:
    buf = b''
    n = int(input('Length: '))
    while(len(buf) != n):
        print(len(buf))
        buf += os.read(0, 0x1000)
        buf = buf[:n]

    tmp.write(buf)
    tmp.close()
    fname = tmp.name

print(fname)
os.chmod(fname, 0o555)
containerName = ''.join(random.choice(
    string.ascii_uppercase + string.digits) for _ in range(0x10))
os.system(f'bash -c "sleep 5 && docker kill {containerName} 2>/dev/null" &')
os.system(
    f'docker run --name {containerName} --privileged --network=none -i --rm -v {fname}:/tmp/exploit readable')
