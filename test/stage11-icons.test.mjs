import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {inflateSync} from 'node:zlib';
const root=new URL('../public/',import.meta.url);
test('PWA icons generated for Chrome/Edge installation have real pixel dimensions',async()=>{
 const manifest=JSON.parse(await readFile(new URL('manifest.webmanifest',root),'utf8'));
 for(const n of [192,512]){
  const item=manifest.icons.find(icon=>icon.src==='/icon-'+n+'.png');
  assert.equal(item?.sizes,n+'x'+n);
  assert.equal(item?.type,'image/png');
  const png=await readFile(new URL('icon-'+n+'.png',root));
  assert.equal(png.subarray(0,8).toString('hex'),'89504e470d0a1a0a');
  assert.equal(png.readUInt32BE(16),n);
  assert.equal(png.readUInt32BE(20),n);
  assert.equal(png[24],8);
  assert.equal(png[25],2);
  const size=png.readUInt32BE(33);
  const raw=inflateSync(png.subarray(41,41+size));
  assert.equal(raw.length,n*(1+n*3));
 }
});
