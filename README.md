# SecureVault

SecureVault is a local-first file scanning, SHA-256 integrity, and authenticated-encryption application. The React/TypeScript interface talks to a Python FastAPI service bound only to `127.0.0.1`; files, passwords, and cryptographic keys are not sent to a cloud service.

## Requirements

- Windows 10 or later (the native folder/file picker uses Windows Tk dialogs)
- Node.js 20+ and npm
- Python 3.10+

## Install

From the project folder, install frontend and backend dependencies:

```powershell
npm install
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

## Run the application

```powershell
npm run desktop
```

This starts the local API at `127.0.0.1:8000` and the Vite interface at `127.0.0.1:5173`. Open <http://127.0.0.1:5173> in a browser. Keep the terminal open while using the app. The `desktop` command uses the project-local `.venv`.

## Build and test

```powershell
npm run build
.\.venv\Scripts\python.exe -m pytest backend\tests -q
```

The Vite development server proxies only `/api` requests to the loopback API. The API validates the frontend origin and requires a per-process session token for protected requests.

## Implemented functionality

- Recursive folder scan with file metadata, chunked SHA-256, exclusions for common generated folders, and symlink skipping.
- Trusted original hashes persisted in a local SQLite database.
- AES-256-GCM encryption with a random per-file salt, a unique 96-bit nonce per 1 MiB chunk, and Scrypt key derivation.
- Decryption supports the existing encryption passphrase and optional Windows Hello platform authentication. Windows Hello uses browser WebAuthn with a required user-verification assertion; a verified device grant is short-lived, single-use, and bound to the selected encrypted files and recovery folder. The original encryption passphrase is still required to derive the SVLT AES key.
- If Windows Hello is not configured or the user chooses not to invoke it, password-only recovery remains available as an explicit fallback. Passwords are sent to the local backend only for the operation; plaintext passwords and derived keys are never persisted.
- On Windows, SecureVault checks the Windows Biometric Service state, loads WBF, enumerates fingerprint units with `WinBioEnumBiometricUnits`, and checks the signed-in account's enrolled factors with `WinBioGetEnrolledFactors`. Live fingerprint verification uses a system-pool session with default flags and `WinBioVerify` against the current account SID; `WinBioIdentify` is not used because the target identity is already known. Handles, sessions, and WBF allocations are released on completion or error. `WinBioAcquireFocus` is deliberately not called: Microsoft documents it as Local System-only, and it is not required for `WinBioVerify`. The synchronous WBF verification may display a system prompt and requires the local backend to have access to the interactive Windows session. A successful fingerprint check is audited but does not issue a decryption grant.
- Each recovered file is staged and authenticated with AES-256-GCM before publication. When a trusted original SHA-256 exists, SecureVault compares the recovered content against it and refuses to publish a mismatch. Without a trusted baseline, the file may be recovered after AEAD authentication but the result is explicitly `UNAVAILABLE`, not a successful integrity match.
- Local SQLite operation history, formula-injection-safe Excel (`.xlsx`) export, and optional tamper-evident HMAC chain.
- Windows Hello/WebAuthn is reported as platform/device verification only. Its prompt may use face, fingerprint, or PIN and does not prove which method was used. WBF exposes fingerprint-specific matching, but its supported sensor-enumeration, session, and matching APIs do not provide face matching to SecureVault. Consequently face-plus-fingerprint authorization is not supported and mandatory requests fail closed; standalone fingerprint verification is not sufficient to decrypt. Password fallback is separate and explicitly labeled.
- The WebAuthn credential's public key and counter are stored in local SQLite. Registration is an explicit user action; Windows OS support alone does not create a SecureVault credential. Signed assertions are verified by the backend, and one-time recovery authorizations are bound to the active backend session, origin, selected encrypted files, and destination. Credential private keys and biometric data stay with the operating-system platform authenticator; SecureVault stores no biometric templates.
- Dashboard statistics sourced from persisted scans and operations, including actual successful factor results and failed attempts; unsupported capability checks are not misreported as successful or failed authentication.
- Eight navigation sections, local Windows folder/file selection, password prompts for encryption and recovery, and responsive dark interface.

## SVLT v1 binary format

The fixed big-endian header is `magic[4] ("SVLT") | version[1] | salt[16] | base_nonce[12] | chunk_size[4]`. Each data frame contains `chunk_index[4] | plaintext_length[4] | AES-GCM ciphertext[length] | tag[16]`. Associated data is the complete header followed by the frame index and plaintext length. For chunk `i`, the nonce is formed by XOR-ing `i` into the last 32 bits of the per-file random 96-bit base nonce; this makes chunk nonces unique within that file while incorporating the entire random nonce. A final authenticated zero-length frame marks successful end-of-file and detects truncation. The format has no original filename metadata; SecureVault preserves the scanned relative path under the selected output directory and adds `.svlt` to each filename.

## Local storage and security limitations

- Audit metadata and the optional HMAC key are stored under `%USERPROFILE%\.securevault`. The HMAC key is separate from the database but held under the same operating-system account; this helps detect accidental or database-only tampering, not an attacker who can replace both files.
- Passwords and derived keys are held in process memory only while an operation runs. SecureVault cannot recover a forgotten password. Windows Hello uses a local platform-authenticator credential and reports device verification only; it does not attest face versus fingerprint versus PIN.
- Windows Hello registration requires a supported browser with WebAuthn platform-authenticator support and a configured Windows Hello credential. Register it from **Biometric Settings > Register Windows Hello**; `Windows OS support`, `Browser platform authenticator`, and `Credential registration` are shown as distinct states. The WBF fingerprint provider additionally requires Windows, a running Windows Biometric Service, a WBF-compatible fingerprint sensor, and a fingerprint enrolled for the current account. Provider and policy tests use mocks; physical fingerprint capture was not invoked during this implementation. On this development machine (Windows 11 Home, build 26300), live WBF checks report the service running, an ELAN fingerprint sensor, and current-account fingerprint enrollment. A real fingerprint verification prompt was not triggered, and this host's ordinary RGB camera is not evidence of Windows Hello face hardware. If Windows Hello is unavailable, password-only recovery remains enabled.
- To use the supported fingerprint check, sign in to the intended Windows account, enroll a fingerprint under **Settings > Accounts > Sign-in options**, ensure **Windows Biometric Service** is running, then open SecureVault **Biometric Settings > Retry Detection**. Retry performs fresh local service, unit, enrollment, and provider checks; it is not an authentication. The fingerprint button initiates the actual Windows verification prompt. Face support would require a supported native provider that can return a trusted, modality-specific face match; a WebAuthn assertion or face-enrollment flag alone is insufficient. A request selecting mandatory face + fingerprint is rejected by the backend rather than downgraded.
- No password rate limiting or lockout is configured. Restrict backend access to this local user session and use a strong passphrase. Do not mistake the biometric capability display for an enrolled biometric or authentication test.
- The app is served locally in a browser; it is not yet packaged as a signed standalone desktop executable. Native folder/file dialogs are provided by the local Python service.
- File metadata and operation records are retained in the local database. Manage backups and deletion under your operating-system account; SecureVault does not provide secure erasure.
- AES-GCM authenticates each encrypted chunk. A whole file is not atomically authenticated as one monolithic unit; the authenticated end marker and ordered chunk indexes detect truncation, reordering, and trailing data.
- The local process and browser run with the current user's filesystem permissions. Use a trusted, updated operating system and do not expose the loopback API through a proxy or port-forward.

## Repository layout

```text
backend/       FastAPI API and scanning, hashing, crypto, audit, reporting modules
backend/tests/ Security and file-operation tests
src/           React/TypeScript interface and typed local API client
```
