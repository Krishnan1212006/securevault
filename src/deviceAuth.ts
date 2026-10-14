type PublicKeyCreationJSON = Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> & {
  challenge: string
  user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string }
  excludeCredentials?: Array<Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }>
}

type PublicKeyRequestJSON = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
  challenge: string
  allowCredentials?: Array<Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }>
}

function decodeBase64Url(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64 + '='.repeat((4 - base64.length % 4) % 4))
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  return bytes.buffer
}

function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function serializeCredential(credential: PublicKeyCredential): Record<string, unknown> {
  const base = {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
  }
  if ('attestationObject' in credential.response) {
    const response = credential.response as AuthenticatorAttestationResponse
    return {
      ...base,
      response: {
        attestationObject: encodeBase64Url(response.attestationObject),
        clientDataJSON: encodeBase64Url(response.clientDataJSON),
        transports: response.getTransports?.() ?? [],
      },
    }
  }
  const response = credential.response as AuthenticatorAssertionResponse
  return {
    ...base,
    response: {
      authenticatorData: encodeBase64Url(response.authenticatorData),
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      signature: encodeBase64Url(response.signature),
      userHandle: response.userHandle ? encodeBase64Url(response.userHandle) : null,
    },
  }
}

export async function createPlatformCredential(options: Record<string, unknown>): Promise<Record<string, unknown>> {
  const json = options as unknown as PublicKeyCreationJSON
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...json,
    challenge: decodeBase64Url(json.challenge),
    user: { ...json.user, id: decodeBase64Url(json.user.id) },
    excludeCredentials: json.excludeCredentials?.map((item) => ({ ...item, id: decodeBase64Url(item.id) })),
  }
  const credential = await navigator.credentials.create({ publicKey })
  if (!(credential instanceof PublicKeyCredential)) throw new Error('Windows Hello did not return a platform credential.')
  return serializeCredential(credential)
}

export async function requestPlatformAssertion(options: Record<string, unknown>): Promise<Record<string, unknown>> {
  const json = options as unknown as PublicKeyRequestJSON
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...json,
    challenge: decodeBase64Url(json.challenge),
    allowCredentials: json.allowCredentials?.map((item) => ({ ...item, id: decodeBase64Url(item.id) })),
  }
  const credential = await navigator.credentials.get({ publicKey })
  if (!(credential instanceof PublicKeyCredential)) throw new Error('Windows Hello did not return a platform assertion.')
  return serializeCredential(credential)
}

export async function hasPlatformAuthenticator(): Promise<boolean> {
  if (!window.PublicKeyCredential) return false
  if (!PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) return false
  return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
}
