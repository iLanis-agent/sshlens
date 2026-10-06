/* SshLens node runner: engine vs ssh-keygen-derived expected.json */
'use strict';
const fs = require('fs');
const path = require('path');
const S = require(path.join(__dirname, '..', 'engine.js'));
const exp = JSON.parse(fs.readFileSync(path.join(__dirname, 'expected.json'), 'utf8'));

let checks = 0, fails = [];
function chk(c, m){ checks++; if (!c) fails.push(m); }
const C = path.join(__dirname, 'corpus');

for (const e of exp.items){
  const r = S.parseText(fs.readFileSync(path.join(C, e.file), 'utf8'));
  chk(r.keys.length === 1, `${e.name}: expected 1 key, got ${r.keys.length} (${r.errors.map(x=>x.error).join(';')})`);
  if (!r.keys.length) continue;
  const k = r.keys[0];
  chk(k.algo === e.algo, `${e.name}: algo ${k.algo} != ${e.algo}`);
  chk(k.bits === e.bits, `${e.name}: bits ${k.bits} != ${e.bits}`);
  chk((k.comment || null) === (e.comment || null), `${e.name}: comment ${JSON.stringify(k.comment)} != ${JSON.stringify(e.comment)}`);
  chk(k.sha256 === e.sha256, `${e.name}: sha256 ${k.sha256} != ${e.sha256}`);
  chk(k.md5 === e.md5, `${e.name}: md5 ${k.md5} != ${e.md5}`);
  chk(JSON.stringify(k.randomart_sha256) === JSON.stringify(e.randomart_sha256), `${e.name}: randomart sha256 mismatch\n  got:  ${JSON.stringify(k.randomart_sha256)}\n  want: ${JSON.stringify(e.randomart_sha256)}`);
  chk(JSON.stringify(k.randomart_md5) === JSON.stringify(e.randomart_md5), `${e.name}: randomart md5 mismatch`);
  if (e.name === 'k_rsa1024') chk(k.warnings.some(w => w.indexOf('2048') > 0), `${e.name}: expected small-RSA warning (${k.warnings.join(';')})`);
}
for (const ef of exp.errors){
  const r = S.parseText(fs.readFileSync(path.join(C, ef.file), 'utf8'));
  chk(r.errors.length === ef.errors && r.keys.length === ef.keys, `${ef.file}: got ${r.keys.length} keys / ${r.errors.length} errors`);
}
{
  const r = S.parseText(fs.readFileSync(path.join(C, exp.multi.file), 'utf8'));
  chk(r.keys.length === exp.multi.keys && r.errors.length === 0, `multi: got ${r.keys.length} keys, ${r.errors.length} errors`);
  chk(r.keys[0].algo === 'ssh-ed25519' && r.keys[1].algo === 'ssh-rsa', 'multi: order/algos');
}
{
  const r = S.parseText(fs.readFileSync(path.join(C, exp.options.file), 'utf8'));
  chk(r.keys.length === 1, `options: got ${r.keys.length} keys`);
  chk(r.keys[0] && r.keys[0].options === exp.options.options, `options: ${JSON.stringify(r.keys[0] && r.keys[0].options)}`);
  chk(r.keys[0] && r.keys[0].comment === 'ec@p256', `options: comment ${JSON.stringify(r.keys[0] && r.keys[0].comment)}`);
}
console.log(`${checks} checks, ${fails.length} failures`);
if (fails.length){ fails.forEach(f => console.log('FAIL', f.slice(0,300))); process.exit(1); }
console.log('ALL PASS');
