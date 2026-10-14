import { readFile } from 'node:fs/promises';
import { decide as baseDecide } from './decider.mjs';
import { createGuard, loadRules as loadWebInjection } from '../xdr/web-injection/connect.mjs';
import {loadRules as loadKnownCve} from '../xdr/known-cve/respond.mjs';
import {createIsolationGuard,loadRules as loadPersistence} from '../xdr/persistence/respond.mjs';

async function loadBruteForce() {
  try {
    const parsed = JSON.parse(await readFile(new URL('../xdr/brute-force/deny-rules.json', import.meta.url), 'utf8'));
    return (parsed?.rules ?? []).map((rule) => ({
      id: rule.id,
      sourceIp: rule?.match?.sourceIp,
      startsAt: '1970-01-01T00:00:00.000Z',
      expiresAt: rule.expiresAt,
      alertId: rule?.evidenceAlertIds?.[0] ?? null,
      pattern: rule.reason,
    }));
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

// sourceIp is supplied by a trusted gateway, never by the browser request body.
const existingXdrDecide = createGuard(baseDecide, async () => [
  ...await loadBruteForce(),
  ...await loadWebInjection(),
  ...await loadKnownCve(),
]);
// Add device-specific persistence quarantine after existing XDR checks.
export const decideWithXdr=createIsolationGuard(existingXdrDecide,loadPersistence);
