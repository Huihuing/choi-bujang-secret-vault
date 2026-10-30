export const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export function validCve(value) {
  return typeof value === 'string' && /^CVE-(199[0-9]|20[0-9]{2}|21[0-9]{2})-[0-9]{4,12}$/u.test(value);
}

async function readJson(fetcher, url, headers = {}) {
  const response = await fetcher(url, {
    method: 'GET', redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { Accept: 'application/json', ...headers },
  });
  if (!response?.ok) throw new Error('upstream_unavailable');
  return response.json();
}

export async function lookupThreatIntel(cveId, {
  fetcher = globalThis.fetch, now = () => new Date(), nvdApiKey = '',
} = {}) {
  if (!validCve(cveId)) throw new TypeError('invalid_cve');
  const [n, k] = await Promise.allSettled([
    readJson(fetcher, NVD_URL + '?cveId=' + encodeURIComponent(cveId),
      nvdApiKey ? { apiKey: nvdApiKey } : {}),
    readJson(fetcher, KEV_URL),
  ]);
  const recordedAt = now().toISOString();
  let nvd = { available: false, fetchedAt: null, found: null, error: 'upstream_unavailable' };
  let kev = { available: false, fetchedAt: null, knownExploited: null, error: 'upstream_unavailable' };
  if (n.status === 'fulfilled' && Array.isArray(n.value?.vulnerabilities)) {
    const entry = n.value.vulnerabilities.find(x => x?.cve?.id === cveId)?.cve;
    nvd = {
      available: true, fetchedAt: recordedAt, found: Boolean(entry),
      published: typeof entry?.published === 'string' ? entry.published : null,
      lastModified: typeof entry?.lastModified === 'string' ? entry.lastModified : null,
      summary: entry?.descriptions?.find(x => x?.lang === 'en')?.value?.slice(0, 1200) ?? null,
    };
  }
  if (k.status === 'fulfilled' && Array.isArray(k.value?.vulnerabilities)) {
    const entry = k.value.vulnerabilities.find(x => x?.cveID === cveId);
    kev = {
      available: true, fetchedAt: recordedAt, knownExploited: Boolean(entry),
      catalogVersion: typeof k.value.catalogVersion === 'string' ? k.value.catalogVersion : null,
      sourceReleasedAt: typeof k.value.dateReleased === 'string' ? k.value.dateReleased : null,
      dateAdded: typeof entry?.dateAdded === 'string' ? entry.dateAdded : null,
      requiredAction: typeof entry?.requiredAction === 'string'
        ? entry.requiredAction.slice(0, 500) : null,
    };
  }
  return {
    schema: 'watchdogs.threat-intel.v1', cveId,
    state: nvd.available && kev.available ? 'ok'
      : (nvd.available || kev.available ? 'partial' : 'unavailable'),
    // A failed source must never be represented as "not vulnerable" or "not exploited".
    sources: {
      nvd: { url: NVD_URL, ...nvd },
      cisaKev: { url: KEV_URL, ...kev },
    },
  };
}
