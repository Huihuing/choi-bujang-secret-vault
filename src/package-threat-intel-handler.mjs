import { authenticatedStudent, json } from './package-auth.mjs';
import { lookupThreatIntel, validCve } from './package-threat-intel.mjs';

// Dependency injection is limited to local tests; deployed default always
// requires a verified student account before fetching any outside source.
export function createThreatIntelHandler({
  authenticate = authenticatedStudent,
  lookup = lookupThreatIntel,
  keyProvider = () => process.env.NVD_API_KEY ?? '',
} = {}) {
  return async function handler(req, res) {
    const ctx = await authenticate(req, res);
    if (!ctx) return;
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return json(res, 405, { error: 'method_not_allowed' });
    }
    const cve = req.query?.cve;
    if (!validCve(cve)) return json(res, 400, { error: 'invalid_cve' });
    try {
      const result = await lookup(cve, { nvdApiKey: keyProvider() });
      return json(res, result.state === 'unavailable' ? 503 : 200, result);
    } catch {
      return json(res, 503, { error: 'threat_intel_unavailable' });
    }
  };
}

export default createThreatIntelHandler();
