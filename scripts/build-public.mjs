import { copyFile, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';
import {generateIcons} from './create-icons.mjs';
import {buildWatchdogsAssets} from './build-watchdogs.mjs';

const root = resolve(import.meta.dirname, '..');
const source = resolve(root, 'data.json');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
const data = JSON.parse(await readFile(source, 'utf8'));

if (!Array.isArray(data.notes)) {
  throw new Error('실습용 자료 형식을 확인하세요. 실제 학생 자료를 넣으면 안 됩니다.');
}

await mkdir(resolve(root, 'public'), { recursive: true });
await generateIcons();
await buildWatchdogsAssets({root});

if (config.step === 1) {
  await copyFile(source, output);
  console.log('1단계 실습용 공개 자료를 public/data.json에 복사했습니다.');
} else if (config.step >= 2 && config.step <= 12) {
  if (data.notes.length !== 0) {
    throw new Error('2단계 이후에는 정적 data.json에 메모를 남기지 마세요.');
  }
  await writeFile(output, `${JSON.stringify({ notes: [] }, null, 2)}\n`, 'utf8');
  console.log('2~12단계 정적 data.json은 메모와 1단계 확인 표시 없이 유지합니다.');
} else {
  throw new Error('현재 빌드 흐름은 1~12단계까지만 준비되어 있습니다.');
}

if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}


// Hobby free plan supports at most 12 Vercel functions. Opt-in only for the
// separate package demonstration project, never for the existing production app.
// The two thin API entrypoints are removed in the ephemeral build worktree;
// vercel.json rewrites point to the existing war-room-summary entrypoint.
// Shared handler modules in src/ retain the exact authentication / quota logic.
if (process.env.PACKAGE_HOBBY_COMPACT === '1') {
  const wrappers = [
    ['ai.js', "export { default } from '../src/package-ai-handler.mjs';"],
    ['threat-intel.js', "export { default } from '../src/package-threat-intel-handler.mjs';"],
  ];
  for (const [file, expected] of wrappers) {
    const path = resolve(root, 'api', file);
    const actual = (await readFile(path, 'utf8')).trim();
    if (actual !== expected) throw new Error('PACKAGE_COMPACT_WRAPPER_MISMATCH: ' + file);
    await rm(path);
  }
  console.log('Hobby package: two thin API wrappers merged into existing authenticated dispatcher.');
}
