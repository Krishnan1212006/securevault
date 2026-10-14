import type { Activity, BiometricCapabilities, BiometricResult, DeviceAuthCeremony, DeviceAuthResult, DeviceAuthStatus, EncryptedSelection, Job, Stats } from './types'

let authToken = sessionStorage.getItem('securevault-token') ?? ''

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    headers: {
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...(authToken ? { 'X-SecureVault-Token': authToken } : {}),
      ...init.headers,
    },
  })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(body.detail ?? `Request failed (${response.status})`)
  return body as T
}

export async function connect(): Promise<void> {
  const data = await request<{ token: string }>('/session')
  authToken = data.token
  sessionStorage.setItem('securevault-token', authToken)
}

export const pickFolder = () => request<{ id: string; path: string }>('/pick/folder', { method: 'POST' })

export const api = {
  stats: () => request<Stats>('/dashboard'),
  scan: (folder_id: string) => request<{ job_id: string }>('/scan', { method: 'POST', body: JSON.stringify({ folder_id }) }),
  encrypt: (ids: string[], output_id: string, password: string) =>
    request<{ job_id: string }>('/encrypt', { method: 'POST', body: JSON.stringify({ ids, output_id, password }) }),
  pickEncrypted: () => request<{ files: EncryptedSelection[] }>('/pick/encrypted', { method: 'POST' }),
  biometricCapabilities: () => request<BiometricCapabilities>('/biometric/capabilities'),
  deviceAuthStatus: () => request<DeviceAuthStatus>('/device-auth/status'),
  deviceRegistrationOptions: () => request<DeviceAuthCeremony>('/device-auth/register/options', { method: 'POST' }),
  finishDeviceRegistration: (ceremony_id: string, credential: Record<string, unknown>) =>
    request<DeviceAuthStatus>('/device-auth/register/complete', { method: 'POST', body: JSON.stringify({ ceremony_id, credential }) }),
  deviceAuthenticationOptions: (encrypted_ids: string[], output_id: string) =>
    request<DeviceAuthCeremony>('/device-auth/authenticate/options', { method: 'POST', body: JSON.stringify({ encrypted_ids, output_id }) }),
  finishDeviceAuthentication: (ceremony_id: string, credential: Record<string, unknown>) =>
    request<DeviceAuthResult>('/device-auth/authenticate/complete', { method: 'POST', body: JSON.stringify({ ceremony_id, credential }) }),
  authenticateBiometric: (factor: 'face' | 'fingerprint', encrypted_ids: string[]) =>
    request<BiometricResult>('/biometric/authenticate', { method: 'POST', body: JSON.stringify({ factor, encrypted_ids }) }),
  requestDecryption: (ids: string[], output_id: string, password: string, device_authorization_id?: string, authentication_mode: 'password_fallback' | 'face_and_fingerprint' = 'password_fallback') =>
    request<{ job_id: string }>('/decrypt', { method: 'POST', body: JSON.stringify({ ids, output_id, password, device_authorization_id, authentication_mode }) }),
  poll: (id: string) => request<Job>(`/jobs/${id}`),
  cancel: (id: string) => request<{ status: string }>(`/jobs/${id}/cancel`, { method: 'POST' }),
  records: () => request<{ records: Activity[] }>('/audit'),
  export: async () => {
    const response = await fetch('/api/audit/export', { headers: { 'X-SecureVault-Token': authToken } })
    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      throw new Error(body.detail ?? 'Could not export audit report')
    }
    return response.blob()
  },
  auditProtection: (enabled: boolean) =>
    request<{ enabled: boolean; verified: boolean; records: number }>('/settings/audit-protection', { method: 'PUT', body: JSON.stringify({ enabled }) }),
  auditStatus: () => request<{ enabled: boolean; verified: boolean; records: number }>('/settings/audit-protection'),
}

export function saveBlob(blob: Blob, filename: string) {
  const href = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = href
  link.download = filename
  link.click()
  URL.revokeObjectURL(href)
}
