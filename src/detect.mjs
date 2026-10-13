// Stage 9 detection consumes only engine-provided synthetic event fields:
// { at, method, identity: { sub } }. Never inspect token, body, names,
// client-provided device, network or role: none is in DETECT_EVENTS.md.
const WINDOW_MS = 10 * 60 * 1000;
const READ_LIMIT = 120;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u;

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  // Map prevents reserved subject strings from becoming object keys.
  // Only read the three documented, engine-verified fields.
  const reads = new Map();
  for (const event of events) {
    if (!event || typeof event !== 'object' || event.method !== 'GET') continue;
    const subject = event.identity?.sub;
    const at = event.at;
    if (typeof subject !== 'string' || !subject || subject !== subject.trim()
        || subject.length > 256 || typeof at !== 'string' || !ISO_UTC.test(at)) continue;
    const timestamp = Date.parse(at);
    if (!Number.isFinite(timestamp)) continue;
    let timestamps = reads.get(subject);
    if (!timestamps) {
      timestamps = [];
      reads.set(subject, timestamps);
    }
    timestamps.push(timestamp);
  }

  // Find any >120 GETs belonging to one subject in an inclusive
  // 10-minute sliding window. Sorting also handles out-of-order events.
  // Choose the earliest violating event, then the lexical subject on a tie;
  // input order must not decide whose access is proposed for revocation.
  let candidate = null;
  for (const [subject, timestamps] of reads) {
    if (timestamps.length <= READ_LIMIT) continue;
    timestamps.sort((a, b) => a - b);
    let left = 0;
    for (let right = 0; right < timestamps.length; right++) {
      while (timestamps[right] - timestamps[left] > WINDOW_MS) left++;
      if (right - left + 1 > READ_LIMIT) {
        const time = timestamps[right];
        if (candidate === null || time < candidate.time
            || (time === candidate.time && subject < candidate.subject)) {
          candidate = { subject, time };
        }
        break;
      }
    }
  }

  return candidate
    ? { action: 'propose_revocation', reasonCode: 'burst_read', subject: candidate.subject }
    : { action: 'observe' };
}
