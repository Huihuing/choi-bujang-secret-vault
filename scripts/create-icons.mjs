// Generates PNG manifest icons from the app's simple geometric mark.
// Node built-ins only; no browser JS, app token, network access or user data.
import {writeFile,mkdir} from 'node:fs/promises';
import {deflateSync} from 'node:zlib';
import {resolve} from 'node:path';

const SIGNATURE=Buffer.from([137,80,78,71,13,10,26,10]);
const CRC_TABLE=Uint32Array.from({length:256},(_,i)=>{
 let c=i;for(let j=0;j<8;j++)c=c&1?0xedb88320^(c>>>1):c>>>1;return c>>>0;
});
function crc32(bytes){
 let c=0xffffffff;for(const b of bytes)c=CRC_TABLE[(c^b)&255]^(c>>>8);
 return (c^0xffffffff)>>>0;
}
function chunk(name,data) {
 const type=Buffer.from(name,'ascii'),length=Buffer.alloc(4),checksum=Buffer.alloc(4);
 length.writeUInt32BE(data.length);checksum.writeUInt32BE(crc32(Buffer.concat([type,data])));
 return Buffer.concat([length,type,data,checksum]);
}
function rounded(x,y,left,top,right,bottom,r) {
 const xx=Math.max(left+r,Math.min(x,right-r));
 const yy=Math.max(top+r,Math.min(y,bottom-r));
 return (x-xx)**2+(y-yy)**2<=r*r;
}
function mark(x,y){
 // Dark "B" icon inside a mint rounded-square safe area.
 if(x>=174&&x<=258&&y>=119&&y<=394)return true;
 const outer1=((x-269)/97)**2+((y-217)/100)**2<=1;
 const outer2=((x-269)/102)**2+((y-320)/88)**2<=1;
 const inner1=((x-267)/38)**2+((y-212)/43)**2<=1;
 const inner2=((x-267)/40)**2+((y-319)/34)**2<=1;
 return (outer1||outer2)&&!(inner1||inner2);
}
function png(size){
 const stride=1+size*3,raw=Buffer.alloc(size*stride);
 const scale=512/size;
 for(let y=0;y<size;y++){
  raw[y*stride]=0;
  for(let x=0;x<size;x++){
   const xx=(x+.5)*scale,yy=(y+.5)*scale;
   const mint=rounded(xx,yy,58,58,454,454,92);
   const dark=mark(xx,yy);
   const color=(!mint||dark)?[12,22,38]:[145,238,229];
   const i=y*stride+1+x*3;
   raw[i]=color[0];raw[i+1]=color[1];raw[i+2]=color[2];
  }
 }
 const ihdr=Buffer.alloc(13);
 ihdr.writeUInt32BE(size,0);ihdr.writeUInt32BE(size,4);
 ihdr[8]=8;ihdr[9]=2;
 return Buffer.concat([SIGNATURE,chunk('IHDR',ihdr),
  chunk('IDAT',deflateSync(raw,{level:9})),chunk('IEND',Buffer.alloc(0))]);
}
export async function generateIcons(){
 const dir=resolve(import.meta.dirname,'..','public');
 await mkdir(dir,{recursive:true});
 await Promise.all([192,512].map(n=>writeFile(resolve(dir,`icon-${n}.png`),png(n))));
}
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
 await generateIcons();
}
