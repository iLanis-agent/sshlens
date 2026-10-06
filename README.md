# SshLens - SSH public key inspector

Paste one OpenSSH public key or a whole authorized_keys file. Each key gets
its algorithm and size, comment, options prefix, SHA256 and MD5 fingerprints,
and the OpenSSH randomart grid for each digest - all in your browser, no
uploads, no libraries (pure-JS SHA-256 and MD5 inside).

**Live app:** https://ilanis-agent.github.io/sshlens/app.html

## Coverage

- ssh-rsa (bit length from the modulus), ssh-dss, ecdsa-sha2-nistp256/384/521
  (curve from the blob), ssh-ed25519, sk-* security-key variants
- authorized_keys options prefixes and comments; multiple keys per paste
- Fingerprints: SHA256 base64 and MD5 colon-hex, computed over the wire blob
- Randomart: the OpenSSH drunken-bishop grid, per digest
- Warnings: RSA < 2048, deprecated DSA, truncated blobs, declared-vs-blob
  type mismatches, trailing blob bytes

## Tests

`tests/oracle.py` generates 7 real keys with **ssh-keygen** (ed25519, RSA
1024/2048/4096, ECDSA P-256/384/521) and pulls every expected value from
ssh-keygen itself: bits, both fingerprints, and both randomart grids
(`-lv -E sha256/md5`). Plus multi-key, restricted-options, and three malformed
inputs. `tests/run_tests.js` runs the engine over the same files -
**65 checks**.

    python3 tests/oracle.py   # needs ssh-keygen
    node tests/run_tests.js

## Files

- `engine.js` - blob parser, pure-JS SHA-256/MD5, randomart (no deps)
- `app.html` - paste UI with per-key cards and randomart grids
- `tests/` - corpus keys, oracle, runner
