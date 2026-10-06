#!/usr/bin/env python3
"""SshLens oracle: every expected value comes from ssh-keygen itself -
fingerprints (-l, both digests), bit counts, and randomart grids (-lv)."""
import json, subprocess, os

BASE = 'tests/corpus'
KEYS = ['k_ed25519','k_rsa2048','k_rsa4096','k_rsa1024','k_ecdsa256','k_ecdsa384','k_ecdsa521']

def sh(*a):
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout

def fingerprints(path, digest):
    out = sh('ssh-keygen','-l','-E',digest,'-f',path).strip()
    # "256 SHA256:abc comment (ED25519)" or "2048 MD5:aa:bb comment (RSA)"
    parts = out.split(' ')
    return dict(bits=int(parts[0]), fingerprint=parts[1])

def randomart(path, digest):
    out = sh('ssh-keygen','-l','-v','-E',digest,'-f',path)
    lines = out.splitlines()
    grid, capture = [], False
    for ln in lines:
        if ln.startswith('+') and '[' in ln[:8]:
            capture = True; continue
        if capture:
            if ln.startswith('+'):
                break
            # strip the border pipes
            grid.append(ln[1:-1] if ln.startswith('|') else ln)
    return grid

def comment_of(path):
    txt = open(path).read().strip().split(' ', 2)
    return txt[2] if len(txt) > 2 else None

items = []
for k in KEYS:
    path = f'{BASE}/{k}.pub'
    s256 = fingerprints(path, 'sha256')
    m5 = fingerprints(path, 'md5')
    items.append(dict(
        name=k, file=k + '.pub',
        algo=open(path).read().split(' ')[0],
        bits=s256['bits'],
        comment=comment_of(path),
        sha256=s256['fingerprint'], md5=m5['fingerprint'],
        randomart_sha256=randomart(path, 'sha256'),
        randomart_md5=randomart(path, 'md5'),
    ))
    print(k, items[-1]['algo'], items[-1]['bits'], items[-1]['sha256'][:20], 'ra rows:', len(items[-1]['randomart_sha256']))

# error files carry only expectations of failure shape
errors = [
    dict(file='bad_garbage.txt', errors=1, keys=0),
    dict(file='bad_declared.txt', errors=1, keys=0),
    dict(file='bad_trunc.txt', errors=1, keys=0),
]
multi = dict(file='ak_multi', keys=2, errors=0)
options = dict(file='ak_options', keys=1, errors=0, options='command="/bin/rrsync /data",no-pty,no-agent-forwarding')
json.dump(dict(items=items, errors=errors, multi=multi, options=options), open('tests/expected.json','w'), indent=1)
print('expected.json written,', len(items), 'keys')
