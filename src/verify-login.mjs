import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { createClient } from '@supabase/supabase-js';
import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u;

// A/B identities in the judge's signed JWT must never share a database owner.
// The signed sub alone does not attest to the distinct identity/assessment run.
// Derive a stable version-4-shaped UUID for the exact signed (run, identity, sub)
// tuple. Supabase student identities keep their original, verified auth UUID.
function scopedJudgeOwnerId(runId, identity, subjectId) {
  const hash = createHash('sha256')
    .update('aleph-judge-owner-v1\0').update(runId).update('\0')
    .update(identity).update('\0').update(subjectId).digest();
  const id = Buffer.from(hash.subarray(0,16));
  id[6] = (id[6] & 0x0f) | 0x40;
  id[8] = (id[8] & 0x3f) | 0x80;
  const hex = id.toString('hex');
  return [hex.slice(0,8),hex.slice(8,12),hex.slice(12,16),
    hex.slice(16,20),hex.slice(20)].join('-');
}

function httpsUrl(value, path) {
  if (typeof value !== 'string' || value !== value.trim()) throw new TypeError('invalid_login_issuer');
  let url;
  try { url = new URL(value); } catch { throw new TypeError('invalid_login_issuer'); }
  const host = url.hostname.toLowerCase();
  if (url.protocol !== 'https:' || url.username || url.password || url.port
      || url.pathname !== path || url.search || url.hash || !host.includes('.')
      || host === 'localhost' || isIP(host)
      || host.endsWith('.local') || host.endsWith('.internal')
      || host.endsWith('.invalid') || host.endsWith('.test') || host.endsWith('.example')) {
    throw new TypeError('invalid_login_issuer');
  }
  return url;
}

function verifiedConfig(config) {
  const judge = httpsUrl(config?.judgeIssuer, '/defense/judge');
  const app = httpsUrl(config?.publicAppUrl, '/');
  if (!app.hostname.endsWith('.vercel.app')) throw new TypeError('invalid_login_app_origin');
  const student = httpsUrl(config?.identityProvider?.issuer, '/auth/v1');
  if (student.origin === judge.origin || student.origin === app.origin
      || config.identityProvider.jwksUrl !== `${student.href}/.well-known/jwks.json`
      || typeof config.identityProvider.audience !== 'string'
      || !/^[a-zA-Z0-9._:-]{1,120}$/u.test(config.identityProvider.audience)) {
    throw new TypeError('invalid_student_identity_provider');
  }
  return { judgeIssuer: judge.href, judgeJwksUrl: `${judge.href}/.well-known/jwks.json`,
    audience: app.hostname, studentIssuer: student.href,
    studentAudience: config.identityProvider.audience, studentUrl: student.origin };
}

// Create once in the server runtime. The judge intake separately compares the
// checked-in judgeIssuer to its registered operator issuer before any attack.
export function createLoginVerifier({ config, supabaseSecretKey, judgeKeySet,
  supabaseClient } = {}) {
  const bound = verifiedConfig(config);
  if (!supabaseClient && (typeof supabaseSecretKey !== 'string'
      || !supabaseSecretKey.trim() || supabaseSecretKey !== supabaseSecretKey.trim())) {
    throw new TypeError('missing_supabase_secret_key');
  }
  const keys = judgeKeySet ?? createRemoteJWKSet(new URL(bound.judgeJwksUrl),
    { timeoutDuration: 5000, cacheMaxAge: 5 * 60 * 1000 });
  const supabase = supabaseClient ?? createClient(bound.studentUrl, supabaseSecretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  if (typeof keys !== 'function' || typeof supabase?.auth?.getClaims !== 'function') {
    throw new TypeError('invalid_login_verifier_configuration');
  }

  // reportFailure is a server-owned, optional sink for privacy-safe diagnostics.
  // It never receives JWTs, user IDs, error messages or unverified claims.
  return async function verifyLoginAuthorization(authorization, reportFailure) {
    const reject = (reason) => {
      if (typeof reportFailure === 'function') {
        try { reportFailure(reason); } catch { /* audit failures cannot alter auth */ }
      }
      return null;
    };
    if (authorization === undefined || authorization === null || authorization === '') return reject('missing');
    if (typeof authorization !== 'string' || authorization.length > 8192) return reject('format');
    const match = BEARER.exec(authorization);
    if (!match) return reject('format');
    const token = match[1];
    let issuer;
    try { issuer = decodeJwt(token).iss; } catch { return reject('format'); }
    if (issuer === bound.judgeIssuer) {
      try {
        const { payload, protectedHeader } = await jwtVerify(token, keys, {
          issuer: bound.judgeIssuer, audience: bound.audience, algorithms: ['ES256'],
          maxTokenAge: '15 minutes', clockTolerance: 5,
        });
        if (protectedHeader.alg !== 'ES256' || payload.aud !== bound.audience
            || !UUID_V4.test(payload.sub ?? '') || !UUID_V4.test(payload.aleph_run ?? '')
            || payload.aleph_role !== 'judge'
            || !['a', 'b'].includes(payload.aleph_identity)
            || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)
            || payload.exp <= payload.iat || payload.exp - payload.iat > 900) return reject('claims');
        return Object.freeze({
          kind: 'judge',
          userId: scopedJudgeOwnerId(payload.aleph_run, payload.aleph_identity, payload.sub),
          runId: payload.aleph_run, identity: payload.aleph_identity,
        });
      } catch (error) {
        if (error?.code === 'ERR_JWT_EXPIRED') return reject('expired');
        if (error?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') return reject('claims');
        if (error?.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') return reject('signature');
        return reject('verification');
      }
    }
    if (issuer === bound.studentIssuer) {
      try {
        // Supabase verifies asymmetric keys locally through JWKS and shared-secret
        // tokens through its Auth server. Never decode and trust a student claim here.
        const { data, error } = await supabase.auth.getClaims(token);
        const claims = data?.claims;
        if (error || !claims || claims.iss !== bound.studentIssuer
            || claims.aud !== bound.studentAudience
            || claims.role !== 'authenticated' || !UUID.test(claims.sub ?? '')
            || !Number.isSafeInteger(claims.exp)) return reject('claims');
        if (claims.exp <= Math.floor(Date.now() / 1000)) return reject('expired');
        return Object.freeze({ kind: 'student', userId: claims.sub });
      } catch { return reject('verification'); }
    }
    return reject('issuer');
  };
}
