/** Browser WebAuthn serialization. Real browser authenticator required.
 * Assertions are verified by py_webauthn on the server, never trusted here.
 */
export function decodeUrl(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), x => x.charCodeAt(0));
}

export function encodeUrl(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function ensureBrowser() {
  if (!window.isSecureContext || !navigator.credentials || !window.PublicKeyCredential) {
    throw new Error('A secure browser context with passkey support is required. Use http://localhost:8080 or HTTPS.');
  }
}

function registrationPayload(credential) {
  const response = credential.response;
  return {
    id: credential.id, rawId: encodeUrl(credential.rawId), type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
    response: {
      attestationObject: encodeUrl(response.attestationObject),
      clientDataJSON: encodeUrl(response.clientDataJSON),
      transports: response.getTransports?.() ?? [],
    },
  };
}

function assertionPayload(credential) {
  const response = credential.response;
  return {
    id: credential.id, rawId: encodeUrl(credential.rawId), type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
    response: {
      authenticatorData: encodeUrl(response.authenticatorData),
      clientDataJSON: encodeUrl(response.clientDataJSON),
      signature: encodeUrl(response.signature),
      userHandle: response.userHandle ? encodeUrl(response.userHandle) : null,
    },
  };
}

export async function enrollBrowserPasskey(req, subject) {
  ensureBrowser();
  const {publicKey, challenge_id} = await req('/v1/passkeys/registration/options', 'POST',
    {subject_id: subject});
  const credential = await navigator.credentials.create({publicKey: {
    ...publicKey,
    challenge: decodeUrl(publicKey.challenge),
    user: {...publicKey.user, id: decodeUrl(publicKey.user.id)},
    excludeCredentials: (publicKey.excludeCredentials || []).map(e => ({
      ...e, id: decodeUrl(e.id),
    })),
  }});
  if (!credential) throw new Error('Passkey enrollment canceled.');
  return req('/v1/passkeys/registration/verify', 'POST',
    {subject_id: subject, challenge_id, credential: registrationPayload(credential)});
}

export async function assertBrowserPasskey(req, intent) {
  ensureBrowser();
  const {publicKey, challenge_id} = await req('/v1/passkeys/authentication/options', 'POST', intent);
  const credential = await navigator.credentials.get({publicKey: {
    ...publicKey,
    challenge: decodeUrl(publicKey.challenge),
    allowCredentials: (publicKey.allowCredentials || []).map(e => ({
      ...e, id: decodeUrl(e.id),
    })),
  }});
  if (!credential) throw new Error('Passkey assertion canceled.');
  return {passkey_challenge_id: challenge_id,
          passkey_credential: assertionPayload(credential)};
}
