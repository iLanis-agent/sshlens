/* SshLens engine - OpenSSH public key inspector.
   Parses authorized_keys-style lines (with options), decodes the wire-format
   blob per algorithm (ssh-rsa, ssh-dss, ecdsa-sha2-*, ssh-ed25519, sk-*),
   computes SHA256 + MD5 fingerprints and OpenSSH randomart for each digest.
   Pure JS SHA-256 and MD5 inside. No dependencies. Browser + node. */
(function(root){
'use strict';

/* ---------- SHA-256 ---------- */
const SHA256_K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function sha256(bytes){
  const H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const l=bytes.length;
  const ml=l*8;
  const padded=new Uint8Array(((l+9+63)>>6)<<6);
  padded.set(bytes); padded[l]=0x80;
  const dv=new DataView(padded.buffer);
  dv.setUint32(padded.length-4, ml>>>0); dv.setUint32(padded.length-8, Math.floor(ml/4294967296));
  const w=new Uint32Array(64);
  for(let o=0;o<padded.length;o+=64){
    for(let t=0;t<16;t++) w[t]=dv.getUint32(o+t*4);
    for(let t=16;t<64;t++){
      const s0=(w[t-15]>>>7|w[t-15]<<25)^(w[t-15]>>>18|w[t-15]<<14)^(w[t-15]>>>3);
      const s1=(w[t-2]>>>17|w[t-2]<<15)^(w[t-2]>>>19|w[t-2]<<13)^(w[t-2]>>>10);
      w[t]=(w[t-16]+s0+w[t-7]+s1)>>>0;
    }
    let [a,b,c,d,e,f,g,h]=H;
    for(let t=0;t<64;t++){
      const S1=(e>>>6|e<<26)^(e>>>11|e<<21)^(e>>>25|e<<7);
      const ch=(e&f)^(~e&g);
      const t1=(h+S1+ch+SHA256_K[t]+w[t])>>>0;
      const S0=(a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10);
      const maj=(a&b)^(a&c)^(b&c);
      const t2=(S0+maj)>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
    }
    H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0;
  }
  const out=new Uint8Array(32);
  const od=new DataView(out.buffer);
  H.forEach((x,i)=>od.setUint32(i*4,x));
  return out;
}

/* ---------- MD5 ---------- */
const MD5_T = (function(){const t=[0];for(let i=1;i<=64;i++)t.push(Math.floor(Math.abs(Math.sin(i))*4294967296));return t;})();
const MD5_S=[7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
function md5(bytes){
  let a0=0x67452301,b0=0xefcdab89,c0=0x98badcfe,d0=0x10325476;
  const l=bytes.length;
  const padded=new Uint8Array(((l+9+63)>>6)<<6);
  padded.set(bytes); padded[l]=0x80;
  const dv=new DataView(padded.buffer);
  dv.setUint32(padded.length-8,l*8>>>0,true); dv.setUint32(padded.length-4,Math.floor(l*8/4294967296),true);
  for(let o=0;o<padded.length;o+=64){
    const M=[]; for(let i=0;i<16;i++) M.push(dv.getUint32(o+i*4,true));
    let A=a0,B=b0,C=c0,D=d0;
    for(let i=0;i<64;i++){
      let F,g;
      if(i<16){F=(B&C)|(~B&D);g=i;}
      else if(i<32){F=(D&B)|(~D&C);g=(5*i+1)%16;}
      else if(i<48){F=B^C^D;g=(3*i+5)%16;}
      else{F=C^(B|~D);g=(7*i)%16;}
      F=(F+A+MD5_T[i+1]+M[g])>>>0;
      A=D;D=C;C=B;
      B=(B+((F<<MD5_S[i])|(F>>>(32-MD5_S[i]))))>>>0;
    }
    a0=(a0+A)>>>0;b0=(b0+B)>>>0;c0=(c0+C)>>>0;d0=(d0+D)>>>0;
  }
  const out=new Uint8Array(16);
  const od=new DataView(out.buffer);
  od.setUint32(0,a0,true);od.setUint32(4,b0,true);od.setUint32(8,c0,true);od.setUint32(12,d0,true);
  return out;
}

/* ---------- helpers ---------- */
const B64='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64enc(bytes){
  let s='';
  for(let i=0;i<bytes.length;i+=3){
    const n=(bytes[i]<<16)|((bytes[i+1]||0)<<8)|(bytes[i+2]||0);
    s+=B64[(n>>18)&63]+B64[(n>>12)&63]+(i+1<bytes.length?B64[(n>>6)&63]:'=')+(i+2<bytes.length?B64[n&63]:'=');
  }
  return s;
}
function b64dec(s){
  const clean=s.replace(/[^A-Za-z0-9+/=]/g,'');
  const out=[];
  for(let i=0;i<clean.length;i+=4){
    const c=[B64.indexOf(clean[i]),B64.indexOf(clean[i+1]),B64.indexOf(clean[i+2]),B64.indexOf(clean[i+3])];
    const n=(c[0]<<18)|(c[1]<<12)|((c[2]<0?0:c[2])<<6)|(c[3]<0?0:c[3]);
    out.push((n>>16)&255);
    if(clean[i+2]!=='='&&c[2]>=0) out.push((n>>8)&255);
    if(clean[i+3]!=='='&&c[3]>=0) out.push(n&255);
  }
  return new Uint8Array(out);
}
function hexColon(bytes){ return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join(':'); }

/* ---------- OpenSSH randomart (drunken bishop, keygen.c) ---------- */
const RA_CHARS=' .o+=*BOX@%&#/^';
const RA_W=17, RA_H=9;
function randomart(digest){
  const field=[];
  for(let i=0;i<RA_W;i++) field.push(new Array(RA_H).fill(0));
  let x=8, y=4;
  const len=RA_CHARS.length;
  for(let i=0;i<digest.length;i++){
    let input=digest[i];
    for(let b=0;b<4;b++){
      x+=(input&0x1)?1:-1;
      y+=(input&0x2)?1:-1;
      x=Math.max(x,0);x=Math.min(x,RA_W-1);
      y=Math.max(y,0);y=Math.min(y,RA_H-1);
      if(field[x][y]<len-2) field[x][y]++;
      input>>=2;
    }
  }
  const ex=x, ey=y;
  const rows=[];
  for(let yy=0;yy<RA_H;yy++){
    let row='';
    for(let xx=0;xx<RA_W;xx++){
      if(xx===8&&yy===4){row+='S';continue;}
      if(xx===ex&&yy===ey){row+='E';continue;}
      row+=RA_CHARS[Math.min(field[xx][yy],len-1)];
    }
    rows.push(row);
  }
  return rows;
}

/* ---------- blob parsing ---------- */
function readStr(v,o){ if(o+4>v.length) throw new Error('truncated blob (string length)'); const len=(v[o]<<24)|(v[o+1]<<16)|(v[o+2]<<8)|v[o+3]; if(o+4+len>v.length) throw new Error('truncated blob (string data)'); return {bytes:v.slice(o+4,o+4+len),end:o+4+len}; }
function strAscii(b){ return Array.from(b).map(c=>String.fromCharCode(c)).join(''); }
function mpintBits(b){ let i=0; while(i<b.length&&b[i]===0) i++; if(i>=b.length) return 0; const first=b[i]; return (b.length-i-1)*8+(32-Math.clz32(first)); }

const ECDSA_BITS={'nistp256':256,'nistp384':384,'nistp521':521};
function parseBlob(blob){
  let o=0;
  const algoR=readStr(blob,o); const algo=strAscii(algoR.bytes); o=algoR.end;
  const info={algo:algo};
  if(algo==='ssh-rsa'){
    const e=readStr(blob,o);o=e.end;
    const n=readStr(blob,o);o=n.end;
    info.kind='RSA'; info.bits=mpintBits(n.bytes); info.exponentBytes=e.bytes.length;
  } else if(algo==='ssh-dss'){
    info.kind='DSA'; info.bits=1024;
    for(let i=0;i<4;i++){const r=readStr(blob,o);o=r.end; if(i===0)info.bits=mpintBits(r.bytes);}
  } else if(algo.indexOf('ecdsa-sha2-')===0){
    const curve=algo.slice('ecdsa-sha2-'.length);
    const c=readStr(blob,o);o=c.end;
    const pt=readStr(blob,o);o=pt.end;
    info.kind='ECDSA'; info.curve=strAscii(c.bytes); info.bits=ECDSA_BITS[info.curve]||null;
  } else if(algo==='ssh-ed25519'||algo==='sk-ssh-ed25519@openssh.com'){
    const pk=readStr(blob,o);o=pk.end;
    info.kind=algo==='ssh-ed25519'?'Ed25519':'Ed25519 security key'; info.bits=256;
  } else if(algo.indexOf('sk-ecdsa-sha2-nistp256@openssh.com')===0){
    info.kind='ECDSA security key'; info.curve='nistp256'; info.bits=256;
    const c=readStr(blob,o);o=c.end;
  } else {
    info.kind='unknown';
    info.unknown=true;
  }
  if(o<blob.length) info.trailing=blob.length-o;
  return info;
}

/* ---------- line parsing ---------- */
const ALGO_RE=/^(ssh-|ecdsa-|sk-)/;
function parseText(text){
  const keys=[], errors=[];
  const lines=text.split(/\r?\n/);
  lines.forEach((line,idx)=>{
    const t=line.trim();
    if(!t||t[0]==='#') return;
    const parts=t.split(/\s+/);
    let ai=parts.findIndex(p=>ALGO_RE.test(p));
    if(ai<0){ errors.push({line:idx+1,error:'no key type (ssh-*/ecdsa-*/sk-*) found'}); return; }
    const declared=parts[ai];
    let blob;
    try{ blob=b64dec(parts[ai+1]||''); }catch(e){ errors.push({line:idx+1,error:'bad base64'}); return; }
    if(!blob.length){ errors.push({line:idx+1,error:'missing or empty base64 blob'}); return; }
    let info;
    try{ info=parseBlob(blob); }
    catch(e){ errors.push({line:idx+1,error:e.message}); return; }
    if(info.algo!==declared){ errors.push({line:idx+1,error:'declared type "'+declared+'" but blob says "'+info.algo+'"'}); return; }
    const comment=parts.slice(ai+2).join(' ');
    const options=parts.slice(0,ai).join(' ');
    const s256=sha256(blob), m5=md5(blob);
    const warnings=[];
    if(info.kind==='RSA'&&info.bits<2048) warnings.push('RSA key under 2048 bits - below current baseline');
    if(info.kind==='DSA') warnings.push('DSA is deprecated and disabled in modern OpenSSH');
    if(info.unknown) warnings.push('unknown algorithm family - blob structure not decoded');
    if(info.trailing) warnings.push(info.trailing+' trailing byte(s) inside the blob');
    keys.push({
      line:idx+1, algo:info.algo, kind:info.kind, bits:info.bits||null, curve:info.curve||null,
      comment:comment||null, options:options||null,
      sha256:'SHA256:'+b64enc(s256).replace(/=+$/,''),
      md5:'MD5:'+hexColon(m5),
      randomart_sha256:randomart(s256),
      randomart_md5:randomart(m5),
      blobBytes:blob.length,
      warnings:warnings
    });
  });
  return {keys:keys, errors:errors};
}

const api={parseText:parseText, parseBlob:parseBlob, randomart:randomart, sha256:sha256, md5:md5, b64dec:b64dec};
if(typeof module!=='undefined'&&module.exports) module.exports=api;
root.SshLens=api;
})(typeof self!=='undefined'?self:globalThis);
