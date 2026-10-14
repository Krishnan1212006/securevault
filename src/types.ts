export type Page = 'Dashboard' | 'File Scanner' | 'Encryption Center' | 'Decryption & Biometric Verification' | 'Integrity Verification' | 'Audit Reports' | 'Biometric Settings' | 'Security Settings'

export interface BiometricFactor {
  available: boolean
  status: 'NOT_STARTED' | 'AWAITING_SYSTEM_AUTHENTICATION' | 'SUCCESS' | 'FAILED' | 'CANCELLED' | 'UNAVAILABLE' | 'READY' | 'HARDWARE_NOT_DETECTED' | 'ENROLLMENT_MISSING' | 'PROVIDER_UNAVAILABLE' | 'PROVIDER_NOT_IMPLEMENTED' | 'UNSUPPORTED'
  message: string
  provider_status: string
  hardware_status: string
  enrollment_status: string
  device_count: number
  modality_identifiable: boolean
}

export interface BiometricCapabilities {
  provider: string | null
  provider_status: string
  provider_message: string
  operating_system: { name: string; version: string | null }
  windows_biometric_service: { status: string; message: string }
  native_provider_status: string
  native_provider_message: string
  two_factor_supported: boolean
  decryption_authorized: boolean
  factors: {
    face: BiometricFactor
    fingerprint: BiometricFactor
  }
}

export interface DeviceAuthStatus {
  available: boolean
  os_supported: boolean
  configured: boolean
  credential_count: number
  registration_status: 'REGISTERED' | 'NOT_REGISTERED' | 'UNSUPPORTED_OS'
  provider: string | null
  message: string
}

export interface DeviceAuthCeremony {
  ceremony_id: string
  public_key: Record<string, unknown>
}

export interface DeviceAuthResult {
  authorization_id: string
  expires_at: string
  message: string
}

export interface BiometricResult {
  factor: 'face' | 'fingerprint'
  status: BiometricFactor['status']
  message: string
  authorization_id: string | null
  expires_at: string | null
}

export interface FileRecord {
  id: string
  name: string
  relative_path: string
  extension: string
  size: number
  modified_at: string
  sha256: string
}

export interface Activity {
  id: string
  filename: string
  operation: string
  timestamp: string
  status: string
  verification_result: string | null
  encrypted_path: string | null
  relative_source_path: string
  file_size: number
  sha256: string | null
  error_details: string | null
  face_authentication_status?: string | null
  fingerprint_authentication_status?: string | null
  authentication_result?: string | null
  decrypted_path?: string | null
  recovered_sha256?: string | null
}

export interface Stats {
  total_scanned: number
  total_encrypted: number
  total_decrypted: number
  verifications_passed: number
  failed_operations: number
  face_authentications: number
  fingerprint_authentications: number
  windows_hello_authentications: number
  failed_authentication_attempts: number
  recent: Activity[]
}

export interface Job {
  id: string
  status: 'queued' | 'running' | 'completed' | 'cancelled' | 'failed'
  progress: number
  total: number
  completed: number
  message: string
  results: Activity[]
  files?: FileRecord[]
  errors?: { path: string; error: string }[]
}

export interface EncryptedSelection {
  id: string
  name: string
  path: string
  size?: number
}
