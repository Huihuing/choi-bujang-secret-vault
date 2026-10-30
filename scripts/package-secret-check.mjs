#!/usr/bin/env node
// Heuristic secret check for known credential formats on tracked HEAD and all
// reachable commits. Does not print matched contents and is not a complete DLP audit.
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
const patterns = [
  'sk-(proj-)?[A-Za-z0-9_-]{24,}',
  'sb_secret_[A-Za-z0-9_-]{20,}',
  'github_pat_[A-Za-z0-9_]{40,}',
  'gh[pousr]_[A-Za-z0-9]{30,}',
  'AIza[0-9A-Za-z_-]{35}',
  '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
];
const list = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' })
  .split('\0').filter(Boolean);
const envFiles = list.filter(file =>
  /(^|\/)\.env(?:\.[^/]+)?$/u.test(file) &&
  !file.endsWith('.example'));
if (envFiles.length) {
  console.error('FAIL: tracked runtime environment file(s):', envFiles.join(', '));
  process.exit(1);
}
const commits = execFileSync('git', ['rev-list', '--all', '--max-count=1001'],
  { encoding: 'utf8' }).trim().split(/\r?\n/u).filter(Boolean);
if (commits.length > 1000) {
  console.error('FAIL: history exceeds 1000 commits; audit requires a wider history scan.');
  process.exit(1);
}
const all = [...new Set(['HEAD', ...commits])];
for (const ref of all) {
  const result = spawnSync('git', ['grep', '-I', '-q', '-E',
    ...patterns.flatMap(re => ['-e', re]), ref, '--'], { encoding: 'utf8' });
  if (result.status === 0) {
    console.error('FAIL: possible credential in git ref', ref.slice(0, 12),
      '(contents intentionally suppressed).');
    process.exit(1);
  }
  if (result.status !== 1) {
    console.error('FAIL: git history scan could not complete:', ref.slice(0, 12));
    process.exit(1);
  }
}
console.log('PASS: checked', all.length, 'refs and', list.length,
  'tracked files for selected credential patterns; heuristic scope only.');
