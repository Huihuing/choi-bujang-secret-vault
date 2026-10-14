import { readFile } from 'node:fs/promises';
import { decide as baseDecide } from './decider.mjs';
import { createGuard, loadRules as loadWebInjection } from '../xdr/web-injection/connect.mjs';
import {loadRules as loadKnownCve} from '../xdr/known-cve/respond.mjs';
import {createIsolationGuard,loadRules as loadPersistence} from '../xdr/persistence/respond.mjs';
import {createSessionGuard,loadRules as loadPrivilege} from '../xdr/privilege/respond.mjs';
import {createDestinationGuard,loadRules as loadExfiltration} from '../xdr/exfiltration/respond.mjs';

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
const withDeviceIsolation=createIsolationGuard(existingXdrDecide,loadPersistence);
// Privilege denial uses only an SDP-verified subjectId and trusted mapping.
const withPrivilege=createSessionGuard(withDeviceIsolation,loadPrivilege);
// Extra guard receives server-verified context.destinationIp, never a browser request property.
export const decideWithXdr=createDestinationGuard(withPrivilege,loadExfiltration);
