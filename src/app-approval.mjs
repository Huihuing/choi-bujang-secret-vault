// Internal, process-local authorization flag. Cannot be set by a browser header.
export const APP_APPROVED=Symbol('verified_webauthn_approved_request');
export function hasApprovedProof(request){return request?.[APP_APPROVED]===true;}
export function studentDeviceAccess(login,request) {
 return login?.kind!=='student'||hasApprovedProof(request);
}
