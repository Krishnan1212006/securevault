import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity as ActivityIcon, AlertCircle, ArrowDownToLine, ArrowRight, ArrowUpRight, Check,
  CheckCircle2, ChevronDown, ChevronRight, Clock3, Download, FileArchive, FileCheck2, FileCode2,
  FileImage, FileKey2, FileSearch, FileText, Folder, FolderOpen, LayoutDashboard,
  Fingerprint, LoaderCircle, LockKeyhole, LogOut, Menu, MoreHorizontal, Plus, RefreshCw,
  ScanFace, ScanLine, Search, Settings2, Shield, ShieldAlert, ShieldCheck, X, XCircle,
} from 'lucide-react'
import { api, connect, pickFolder, saveBlob } from './api'
import { createPlatformCredential, hasPlatformAuthenticator, requestPlatformAssertion } from './deviceAuth'
import type { Activity, BiometricCapabilities, DeviceAuthStatus, EncryptedSelection, FileRecord, Job, Page, Stats } from './types'

type Notice = { type: 'success' | 'error' | 'info'; text: string }
const navigation: { title: Page; icon: typeof LayoutDashboard; caption?: string }[] = [
  { title: 'Dashboard', icon: LayoutDashboard },
  { title: 'File Scanner', icon: ScanLine },
  { title: 'Encryption Center', icon: LockKeyhole },
  { title: 'Decryption & Biometric Verification', icon: FileCheck2 },
  { title: 'Integrity Verification', icon: ShieldCheck },
  { title: 'Audit Reports', icon: FileText, caption: 'COMPLIANCE' },
  { title: 'Biometric Settings', icon: Fingerprint },
  { title: 'Security Settings', icon: Settings2 },
]
const emptyStats: Stats = { total_scanned: 0, total_encrypted: 0, total_decrypted: 0, verifications_passed: 0, failed_operations: 0, face_authentications: 0, fingerprint_authentications: 0, windows_hello_authentications: 0, failed_authentication_attempts: 0, recent: [] }
const relativeTime = (value: string) => {
  const time = new Date(value).getTime()
  if (!Number.isFinite(time)) return value
  const mins = Math.max(1, Math.floor((Date.now() - time) / 60000))
  if (mins < 60) return `${mins} min ago`
  if (mins < 1440) return `${Math.floor(mins / 60)} hr ago`
  return `${Math.floor(mins / 1440)} days ago`
}
const formatSize = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`
}
const iconFor = (name: string) => {
  const extension = name.split('.').pop()?.toLowerCase()
  if (['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp'].includes(extension ?? '')) return FileImage
  if (['zip', '7z', 'rar', 'svlt'].includes(extension ?? '')) return FileArchive
  if (['ts', 'tsx', 'js', 'py', 'json', 'html', 'css'].includes(extension ?? '')) return FileCode2
  return FileText
}
function App() {
  const [page, setPage] = useState<Page>('Dashboard')
  const [stats, setStats] = useState<Stats>(emptyStats)
  const [records, setRecords] = useState<Activity[]>([])
  const [files, setFiles] = useState<FileRecord[]>([])
  const [encrypted, setEncrypted] = useState<EncryptedSelection[]>([])
  const [pickedFolder, setPickedFolder] = useState('')
  const [pickedFolderId, setPickedFolderId] = useState('')
  const [outputDir, setOutputDir] = useState('')
  const [outputDirId, setOutputDirId] = useState('')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [password, setPassword] = useState('')
  const [decryptPassword, setDecryptPassword] = useState('')
  const [job, setJob] = useState<Job | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null)
  const [auditProtection, setAuditProtection] = useState(false)
  const [auditVerified, setAuditVerified] = useState(true)
  const [biometrics, setBiometrics] = useState<BiometricCapabilities | null>(null)
  const [deviceAuth, setDeviceAuth] = useState<DeviceAuthStatus | null>(null)
  const [platformAuthenticatorAvailable, setPlatformAuthenticatorAvailable] = useState(false)
  const [deviceAuthBusy, setDeviceAuthBusy] = useState(false)
  const [deviceAuthorizationId, setDeviceAuthorizationId] = useState('')
  const [deviceAuthorizationExpiresAt, setDeviceAuthorizationExpiresAt] = useState('')
  const [faceResult, setFaceResult] = useState('')
  const [fingerprintResult, setFingerprintResult] = useState('')
  const [authenticationMode, setAuthenticationMode] = useState<'password_fallback' | 'face_and_fingerprint'>('password_fallback')
  const [menuOpen, setMenuOpen] = useState(false)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [detail, setDetail] = useState<Activity | FileRecord | null>(null)
  const [confirm, setConfirm] = useState<{ title: string; message: string; action: () => void } | null>(null)
  const passwordRef = useRef<HTMLInputElement>(null)

  const toast = useCallback((type: Notice['type'], text: string) => {
    setNotice({ type, text })
    window.setTimeout(() => setNotice((current) => current?.text === text ? null : current), 4800)
  }, [])

  const refreshStats = useCallback(async () => {
    const data = await api.stats()
    setStats(data)
  }, [])
  const refreshRecords = useCallback(async () => {
    const data = await api.records()
    setRecords(data.records)
  }, [])
  const refreshAuditProtection = useCallback(async () => {
    const data = await api.auditStatus()
    setAuditProtection(data.enabled)
    setAuditVerified(data.verified)
  }, [])
  const refreshBiometrics = useCallback(async () => {
    const data = await api.biometricCapabilities()
    setBiometrics(data)
  }, [])
  const refreshDeviceAuth = useCallback(async () => {
    const [status, platformAvailable] = await Promise.all([api.deviceAuthStatus(), hasPlatformAuthenticator()])
    setDeviceAuth(status)
    setPlatformAuthenticatorAvailable(platformAvailable)
  }, [])
  const refreshAll = useCallback(async () => {
    setLoading(true)
    try {
      await Promise.all([refreshStats(), refreshRecords(), refreshAuditProtection(), refreshBiometrics(), refreshDeviceAuth()])
      setBackendOnline(true)
    } catch (error) {
      setBackendOnline(false)
      toast('error', error instanceof Error ? error.message : 'Unable to refresh local records.')
    } finally {
      setLoading(false)
    }
  }, [refreshStats, refreshRecords, refreshAuditProtection, refreshBiometrics, refreshDeviceAuth, toast])

  useEffect(() => {
    let mounted = true
    connect().then(() => {
      if (mounted) {
        setBackendOnline(true)
        void refreshAll()
      }
    }).catch((error: unknown) => {
      if (mounted) {
        setBackendOnline(false)
        toast('error', error instanceof Error ? error.message : 'SecureVault backend is unavailable. Start the desktop application backend.')
      }
    })
    return () => { mounted = false }
  }, [refreshAll, toast])

  useEffect(() => {
    if (!job || !['queued', 'running'].includes(job.status)) return
    let cancelled = false
    const timer = window.setInterval(async () => {
      try {
        const current = await api.poll(job.id)
        if (cancelled) return
        setJob(current)
        if (!['queued', 'running'].includes(current.status)) {
          window.clearInterval(timer)
          setBusy(false)
          if (page === 'File Scanner' && current.files) setFiles(current.files)
          if (current.results.length) setRecords((recordsNow) => [...current.results, ...recordsNow])
          if (current.status === 'completed') {
            const failures = current.results.filter((result) => result.status === 'FAILED').length
            const firstFailure = current.results.find((result) => result.status === 'FAILED')
            const failureDetails = firstFailure?.error_details ? ` ${firstFailure.filename}: ${firstFailure.error_details}` : ''
            toast(failures ? 'error' : 'success', failures ? `${current.message}.${failureDetails} See Audit Reports for details.` : current.message)
            if (current.errors?.length) toast('error', `${current.errors.length} file or folder access errors. ${current.errors[0].path}: ${current.errors[0].error}`)
            await Promise.all([refreshStats(), refreshRecords()])
          } else {
            const firstFailure = current.results.find((result) => result.status === 'FAILED')
            const failureDetails = firstFailure?.error_details ? ` ${firstFailure.filename}: ${firstFailure.error_details}` : ''
            toast(current.status === 'cancelled' ? 'info' : 'error', `${current.message}${failureDetails}`)
            await Promise.all([refreshStats(), refreshRecords()])
          }
          setPassword('')
          setDecryptPassword('')
          setSelected([])
        }
      } catch (error) {
        if (!cancelled) {
          setBusy(false)
          toast('error', error instanceof Error ? error.message : 'Could not retrieve operation status.')
        }
      }
    }, 650)
    return () => { cancelled = true; window.clearInterval(timer) }
  }, [job?.id, job?.status, page, refreshRecords, refreshStats, toast])

  const visibleFiles = useMemo(() => files.filter((file) =>
    `${file.name} ${file.relative_path} ${file.extension}`.toLowerCase().includes(query.toLowerCase())), [files, query])
  const visibleRecords = useMemo(() => records.filter((record) =>
    `${record.filename} ${record.relative_source_path} ${record.operation} ${record.status}`.toLowerCase().includes(query.toLowerCase())), [records, query])
  const latestBiometricAttempt = records.find((record) =>
    ['BIOMETRIC_FACE', 'BIOMETRIC_FINGERPRINT', 'DEVICE_AUTH'].includes(record.operation))

  async function scanFolder(folderId = pickedFolderId) {
    if (!folderId) {
      try {
        const choice = await pickFolder()
        if (!choice.path) return
        folderId = choice.id
        setPickedFolder(choice.path)
        setPickedFolderId(choice.id)
      } catch (error) {
        toast('error', error instanceof Error ? error.message : 'Could not open the folder picker.')
        return
      }
    }
    setBusy(true)
    try {
      const result = await api.scan(folderId)
      setJob({ id: result.job_id, status: 'queued', progress: 0, total: 0, completed: 0, message: 'Preparing scan', results: [] })
      toast('info', 'Folder scan started. Files are hashed locally using SHA-256.')
    } catch (error) {
      setBusy(false)
      toast('error', error instanceof Error ? error.message : 'Could not start folder scan.')
    }
  }

  async function startEncrypt() {
    if (!selected.length) return toast('error', 'Select at least one scanned file.')
    if (!password) { passwordRef.current?.focus(); return toast('error', 'Enter a password to encrypt the selected files.') }
    if (!outputDirId) return toast('error', 'Choose an existing destination folder.')
    if (pickedFolder && outputDir.toLowerCase() === pickedFolder.toLowerCase()) return toast('error', 'Choose a destination folder separate from the scanned source folder.')
    setBusy(true)
    try {
      const result = await api.encrypt(selected, outputDirId, password)
      setJob({ id: result.job_id, status: 'queued', progress: 0, total: selected.length, completed: 0, message: 'Preparing encryption', results: [] })
      toast('info', `Encrypting ${selected.length} file${selected.length === 1 ? '' : 's'} with AES-256-GCM.`)
    } catch (error) {
      setBusy(false)
      toast('error', error instanceof Error ? error.message : 'Could not start encryption.')
    }
  }

  async function selectEncrypted() {
    try {
      const result = await api.pickEncrypted()
      setEncrypted((current) => {
        const merged = new Map(current.map((item) => [item.id, item]))
        for (const file of result.files) merged.set(file.id, file)
        return [...merged.values()]
      })
      setDeviceAuthorizationId('')
      setDeviceAuthorizationExpiresAt('')
      if (result.files.length) toast('success', `${result.files.length} encrypted file${result.files.length === 1 ? '' : 's'} selected.`)
    } catch (error) {
      toast('error', error instanceof Error ? error.message : 'Could not open encrypted-file picker.')
    }
  }

  async function startDecrypt() {
    if (!encrypted.length) return toast('error', 'Select encrypted .svlt files first.')
    if (!decryptPassword) return toast('error', 'Enter the encryption password to recover the selected files.')
    if (!outputDirId) return toast('error', 'Choose an existing recovery directory.')
    setBusy(true)
    try {
      const result = await api.requestDecryption(
        encrypted.map((item) => item.id), outputDirId, decryptPassword, deviceAuthorizationId || undefined,
        authenticationMode,
      )
      setDeviceAuthorizationId('')
      setDeviceAuthorizationExpiresAt('')
      setDecryptPassword('')
      setJob({ id: result.job_id, status: 'queued', progress: 0, total: encrypted.length, completed: 0, message: 'Preparing authenticated recovery', results: [] })
      toast('info', `${deviceAuthorizationId ? 'Windows Hello verified; ' : ''}recovering ${encrypted.length} file${encrypted.length === 1 ? '' : 's'}.`)
    } catch (error) {
      setBusy(false)
      setDecryptPassword('')
      setDeviceAuthorizationId('')
      setDeviceAuthorizationExpiresAt('')
      toast('error', error instanceof Error ? error.message : 'Could not start decryption.')
    }
  }

  async function registerWindowsHello() {
    if (!platformAuthenticatorAvailable) return toast('error', 'This browser does not report an available platform authenticator.')
    setDeviceAuthBusy(true)
    try {
      const ceremony = await api.deviceRegistrationOptions()
      const credential = await createPlatformCredential(ceremony.public_key)
      const status = await api.finishDeviceRegistration(ceremony.ceremony_id, credential)
      setDeviceAuth(status)
      await refreshStats()
      toast('success', 'Windows Hello platform credential registered. It may prompt for face, fingerprint, or PIN.')
    } catch (error) {
      toast('error', error instanceof Error ? error.message : 'Windows Hello credential registration failed.')
    } finally {
      setDeviceAuthBusy(false)
    }
  }

  async function verifyWithWindowsHello() {
    if (!encrypted.length) return toast('error', 'Select encrypted files before device verification.')
    if (!outputDirId) return toast('error', 'Choose the recovery destination before device verification.')
    if (!deviceAuth?.configured || !platformAuthenticatorAvailable) {
      return toast('error', 'Register an available Windows Hello platform credential in Biometric Settings first.')
    }
    setDeviceAuthBusy(true)
    setDeviceAuthorizationId('')
    setDeviceAuthorizationExpiresAt('')
    try {
      const ids = encrypted.map((item) => item.id)
      const ceremony = await api.deviceAuthenticationOptions(ids, outputDirId)
      const credential = await requestPlatformAssertion(ceremony.public_key)
      const result = await api.finishDeviceAuthentication(ceremony.ceremony_id, credential)
      setDeviceAuthorizationId(result.authorization_id)
      setDeviceAuthorizationExpiresAt(result.expires_at)
      toast('success', result.message)
      await Promise.all([refreshStats(), refreshRecords()])
    } catch (error) {
      toast('error', error instanceof Error ? error.message : 'Windows Hello device verification failed.')
    } finally {
      setDeviceAuthBusy(false)
    }
  }

  async function requestBiometric(factor: 'face' | 'fingerprint') {
    if (!encrypted.length) return toast('error', 'Select encrypted files before requesting authentication.')
    try {
      const result = await api.authenticateBiometric(factor, encrypted.map((item) => item.id))
      if (factor === 'face') setFaceResult(result.status)
      else setFingerprintResult(result.status)
      toast(result.status === 'SUCCESS' ? 'success' : 'error', result.message)
      await Promise.all([refreshStats(), refreshRecords()])
    } catch (error) {
      toast('error', error instanceof Error ? error.message : 'Biometric authentication request failed.')
    }
  }

  async function refreshScanner() {
    if (!pickedFolder) return scanFolder('')
    setBusy(true)
    try {
      const result = await api.scan(pickedFolderId)
      setJob({ id: result.job_id, status: 'queued', progress: 0, total: 0, completed: 0, message: 'Refreshing scan', results: [] })
    } catch (error) {
      setBusy(false)
      toast('error', error instanceof Error ? error.message : 'Could not refresh scan.')
    }
  }

  const setOutputFromDialog = async () => {
    try {
      const choice = await pickFolder()
      if (choice.path) {
        setOutputDir(choice.path)
        setOutputDirId(choice.id)
        setDeviceAuthorizationId('')
        setDeviceAuthorizationExpiresAt('')
      }
    } catch (error) {
      toast('error', error instanceof Error ? error.message : 'Could not open the destination picker.')
    }
  }

  const choosePage = (next: Page) => { setPage(next); setMobileNavOpen(false); setQuery(''); if (next !== page) setPassword('') }
  const statCards = [
    { label: 'Files scanned', value: stats.total_scanned, icon: FileSearch, color: 'blue', change: 'From local scan records' },
    { label: 'Files encrypted', value: stats.total_encrypted, icon: LockKeyhole, color: 'teal', change: 'AES-256-GCM' },
    { label: 'Files decrypted', value: stats.total_decrypted, icon: ArrowDownToLine, color: 'purple', change: 'Authenticated recovery' },
    { label: 'Integrity verified', value: stats.verifications_passed, icon: ShieldCheck, color: 'green', change: 'Trusted SHA-256 match' },
    { label: 'Face authentications', value: stats.face_authentications, icon: ScanFace, color: 'blue', change: 'Backend-confirmed only' },
    { label: 'Fingerprint authentications', value: stats.fingerprint_authentications, icon: Fingerprint, color: 'teal', change: 'Backend-confirmed only' },
    { label: 'Windows Hello verifications', value: stats.windows_hello_authentications, icon: ShieldCheck, color: 'green', change: 'Device verification only' },
    { label: 'Failed auth attempts', value: stats.failed_authentication_attempts, icon: ShieldAlert, color: 'amber', change: 'Recorded authentication failures' },
  ]

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-mark"><Shield size={23} strokeWidth={2.4} /></div>
          <div><div className="brand-name">secure<span>vault</span></div><div className="brand-subtitle">FILE SECURITY</div></div>
          <button className="icon-btn sidebar-close" aria-label="Close menu" onClick={() => setMobileNavOpen(false)}><X size={18} /></button>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        <nav className="nav-list" aria-label="Main navigation">
          {navigation.map(({ title, icon: Icon, caption }) => (
            <button key={title} className={`nav-item ${page === title ? 'active' : ''}`} onClick={() => choosePage(title)}>
              <Icon size={18} strokeWidth={1.8} /><span>{title}</span>{caption && <span className="nav-caption">{caption}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-card">
            <div className="local-card-top"><span className="live-dot" /><span>LOCAL ENVIRONMENT</span><MoreHorizontal size={16} /></div>
            <div className="local-card-value">{backendOnline ? 'Connected securely' : backendOnline === false ? 'Backend offline' : 'Connecting…'}</div>
            <div className="local-card-note"><LockKeyhole size={13} /> Files never leave this device</div>
          </div>
          <button className="profile-button" onClick={() => choosePage('Security Settings')}>
            <div className="profile-avatar">SV</div><div className="profile-text"><strong>Local workspace</strong><span>Personal vault</span></div><ChevronDown size={15} className="muted-icon" />
          </button>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-start">
            <button className="icon-btn mobile-menu" aria-label="Open menu" onClick={() => setMobileNavOpen(true)}><Menu size={20} /></button>
            <span className="breadcrumb-muted">Workspace</span><ChevronRight size={14} className="muted-icon" /><span className="breadcrumb-current">{page}</span>
          </div>
          <div className="topbar-end">
            <div className={`backend-status ${backendOnline ? 'online' : backendOnline === false ? 'offline' : ''}`}>
              <span className="status-indicator" />{backendOnline ? 'Backend connected' : backendOnline === false ? 'Backend offline' : 'Connecting'}
            </div>
            <span className="topbar-divider" />
            <div className="avatar-small">SV</div>
            <button className="icon-btn mobile-menu topbar-more" aria-label="More actions" onClick={() => setMenuOpen((value) => !value)}><MoreHorizontal size={20} /></button>
          </div>
        </header>

        {backendOnline === false && <div className="backend-alert"><AlertCircle size={16} /> Could not reach the local API. Start SecureVault using `npm run desktop` from the project folder.<button onClick={refreshAll}><RefreshCw size={14} /> Retry</button></div>}

        <div className="page-content">
          {page === 'Dashboard' && <section className="page-section">
            <div className="page-heading-row">
              <div><div className="eyebrow"><span className="eyebrow-line" /> SECURITY OVERVIEW</div><h1>Good morning, welcome back.</h1><p className="page-description">Your files, protected. Here’s what’s happening in your vault.</p></div>
              <div className="heading-actions"><button className="button button-secondary" onClick={refreshAll} disabled={loading}><RefreshCw size={15} className={loading ? 'spin' : ''} /> Refresh</button><button className="button button-primary" onClick={() => choosePage('File Scanner')}><Plus size={17} /> New scan</button></div>
            </div>
            <div className="security-banner"><div className="banner-icon"><ShieldCheck size={22} /></div><div className="banner-copy"><strong>Your vault is secure</strong><span>All operations are processed locally on this device. Files and passwords are never uploaded.</span></div><div className="banner-chip"><span className="live-dot" /> PROTECTED</div><div className="banner-decoration" /></div>
            <div className="section-title-row"><div><h2>Security overview</h2><p>All-time activity from your local audit records.</p></div><span className="data-source"><span className="data-dot" /> REAL AUDIT DATA</span></div>
            <div className="stats-grid">{statCards.map(({ label, value, icon: Icon, color, change }) => <div className="stat-card" key={label}><div className="stat-top"><div className={`stat-icon ${color}`}><Icon size={19} /></div><button className="tiny-menu" aria-label={`Details for ${label}`} onClick={() => choosePage(label === 'Files scanned' ? 'File Scanner' : label.includes('auth') || label.includes('Authentication') ? 'Biometric Settings' : 'Audit Reports')}><MoreHorizontal size={17} /></button></div><div className="stat-value">{value.toLocaleString()}</div><div className="stat-label">{label}</div><div className="stat-foot"><span className="stat-note">{change}</span></div></div>)}</div>
            <div className="dashboard-columns">
              <div className="panel activity-panel">
                <div className="panel-header"><div><h2>Recent activity</h2><p>Your latest security operations</p></div><button className="text-button" onClick={() => choosePage('Audit Reports')}>View all <ArrowRight size={14} /></button></div>
                {stats.recent.length ? <div className="activity-list">{stats.recent.slice(0, 5).map((record) => <ActivityRow key={record.id} record={record} onClick={() => setDetail(record)} />)}</div> : <EmptyState icon={ActivityIcon} title="Nothing here yet" description="Scan a folder to create your first audit record." action="Scan a folder" onAction={() => choosePage('File Scanner')} /> }
                {stats.recent.length > 0 && <div className="panel-footer"><span>Latest {Math.min(stats.recent.length, 5)} operations</span><button className="text-button" onClick={() => choosePage('Audit Reports')}>See history <ArrowRight size={13} /></button></div>}
              </div>
              <div className="panel quick-panel">
                <div className="panel-header"><div><h2>Quick actions</h2><p>Jump right into your workflow</p></div></div>
                <div className="quick-actions">
                  <QuickAction icon={ScanLine} color="blue" title="Scan files" description="Find files and calculate hashes" onClick={() => choosePage('File Scanner')} />
                  <QuickAction icon={LockKeyhole} color="teal" title="Encrypt files" description="Protect files with AES-256-GCM" onClick={() => choosePage('Encryption Center')} />
                  <QuickAction icon={ShieldCheck} color="purple" title="Verify integrity" description="Review trusted verification records" onClick={() => choosePage('Integrity Verification')} />
                  <QuickAction icon={FileText} color="amber" title="Export audit report" description="Download your Excel security log" onClick={() => choosePage('Audit Reports')} />
                </div>
                <div className="quick-secure"><LockKeyhole size={14} /><span>Private by design</span><span className="quick-secure-separator" /> No cloud. No tracking.</div>
              </div>
            </div>
            <div className="bottom-activity"><div className="bottom-card"><div className="bottom-icon green"><CheckCircle2 size={18} /></div><div><strong>{stats.verifications_passed} successful verifications</strong><span>Verified against a stored original SHA-256 reference.</span></div></div><div className="bottom-card"><div className="bottom-icon red"><AlertCircle size={18} /></div><div><strong>{stats.failed_operations} failed operations</strong><span>Failed operations are retained in the audit history.</span></div></div></div>
          </section>}

          {page === 'File Scanner' && <section className="page-section">
            <PageHeading eyebrow="DISCOVER & HASH" title="File Scanner" description="Recursively scan a folder and calculate a trusted SHA-256 fingerprint for every file." action={<button className="button button-primary" disabled={busy || !backendOnline} onClick={() => scanFolder('')}><FolderOpen size={16} /> Choose folder to scan</button>} />
            <div className="scanner-intro"><div className="scanner-intro-icon"><ScanLine size={20} /></div><div><strong>Scan stays on your device</strong><span>Symbolic links are skipped. Application output, virtual environments, and generated reports are excluded.</span></div><div className="scanner-tag"><span className="live-dot" /> LOCAL ONLY</div></div>
            {pickedFolder && <div className="folder-path-card"><Folder size={17} /><div><span>Selected folder</span><strong title={pickedFolder}>{pickedFolder}</strong></div><button className="button button-quiet" onClick={refreshScanner} disabled={busy}><RefreshCw size={15} /> Rescan</button></div>}
            {job && <JobProgress job={job} onCancel={() => { void api.cancel(job.id).then(() => toast('info', 'Cancellation requested.')).catch((error) => toast('error', String(error))) }} />}
            <div className="panel files-panel">
              <div className="panel-header scanner-table-header"><div><h2>Scanned files <span className="count-badge">{visibleFiles.length}</span></h2><p>File metadata and full SHA-256 hashes are retained locally.</p></div><div className="table-actions"><SearchField value={query} onChange={setQuery} placeholder="Search files…" /><button className="button button-secondary button-small" disabled={!visibleFiles.length} onClick={() => setSelected(selected.length === visibleFiles.length ? [] : visibleFiles.map((file) => file.id))}>{selected.length === visibleFiles.length && visibleFiles.length ? <Check size={14} /> : null}{selected.length === visibleFiles.length && visibleFiles.length ? 'Deselect all' : 'Select all'}</button></div></div>
              {visibleFiles.length ? <div className="table-scroll"><table><thead><tr><th className="check-cell"></th><th>FILE NAME</th><th>RELATIVE PATH</th><th>TYPE</th><th>SIZE</th><th>LAST MODIFIED</th><th>SHA-256</th></tr></thead><tbody>{visibleFiles.map((file) => <tr key={file.id}><td className="check-cell"><input type="checkbox" checked={selected.includes(file.id)} onChange={() => setSelected((value) => value.includes(file.id) ? value.filter((id) => id !== file.id) : [...value, file.id])} aria-label={`Select ${file.name}`} /></td><td><button className="file-name-cell" onClick={() => setDetail(file)}><FileBadge name={file.name} /><span>{file.name}</span></button></td><td className="mono subdued" title={file.relative_path}>{file.relative_path}</td><td><span className="type-chip">{file.extension}</span></td><td className="subdued">{formatSize(file.size)}</td><td className="subdued">{new Date(file.modified_at).toLocaleString()}</td><td><button className="hash-button" onClick={() => setDetail(file)} title={file.sha256}>{file.sha256.slice(0, 10)}…{file.sha256.slice(-6)}<ChevronRight size={13} /></button></td></tr>)}</tbody></table></div> : <EmptyState icon={FileSearch} title={pickedFolder ? 'No files found' : 'Ready when you are'} description={pickedFolder ? 'This folder contains no readable files matching the scan filters.' : 'Choose a folder to recursively scan and fingerprint its files.'} action={pickedFolder ? 'Choose another folder' : 'Choose a folder'} onAction={() => scanFolder('')} />}
              {!!selected.length && <div className="selection-bar"><span><CheckCircle2 size={16} /> <strong>{selected.length}</strong> file{selected.length === 1 ? '' : 's'} selected</span><button className="button button-primary button-small" onClick={() => choosePage('Encryption Center')}>Encrypt selected <ArrowRight size={14} /></button></div>}
            </div>
            <div className="inline-info"><Shield size={15} /><span><strong>SHA-256 is a one-way hash, not encryption.</strong> It cannot be decrypted and is used here as a trusted integrity reference.</span></div>
          </section>}

          {page === 'Encryption Center' && <section className="page-section">
            <PageHeading eyebrow="ENCRYPTION CENTER" title="Protect your files." description="Secure your files with authenticated AES-256-GCM encryption. Your originals are never modified." />
            <div className="crypto-layout">
              <div className="panel crypto-form">
                <div className="form-section-title"><span className="step-number">01</span><div><strong>Select files</strong><span>Choose from your latest scan</span></div><button className="text-button" onClick={() => choosePage('File Scanner')}>Open scanner <ArrowRight size={13} /></button></div>
                {files.length ? <div className="selection-summary"><div className="summary-leading"><div className="file-square"><FileText size={17} /></div><div><strong>{selected.length ? `${selected.length} files selected` : `${files.length} files available`}</strong><span>{formatSize((selected.length ? files.filter((f) => selected.includes(f.id)) : files).reduce((sum, f) => sum + f.size, 0))} total size · scanned locally</span></div></div><button className="button button-secondary button-small" onClick={() => choosePage('File Scanner')}>{selected.length ? 'Change selection' : 'Select files'}</button></div> : <EmptyInline text="Scan a folder first, then select files for encryption." action="Go to scanner" onClick={() => choosePage('File Scanner')} />}
                <div className="form-separator" />
                <div className="form-section-title"><span className="step-number">02</span><div><strong>Set a password</strong><span>Protect your encryption key</span></div></div>
                <label className="field-label" htmlFor="encrypt-password">Encryption password</label><div className="password-wrap"><LockKeyhole size={16} /><input ref={passwordRef} id="encrypt-password" type="password" autoComplete="new-password" placeholder="Enter a strong password" value={password} onChange={(event) => setPassword(event.target.value)} /><span className="secure-input-badge"><Shield size={12} /> NEVER STORED</span></div><p className="field-hint">A strong, unique passphrase is recommended. You’ll need this password to recover your files.</p>
                <div className="form-separator" />
                <div className="form-section-title"><span className="step-number">03</span><div><strong>Choose destination</strong><span>Your encrypted files are saved separately</span></div></div>
                <label className="field-label" htmlFor="encrypt-destination">Output directory</label><div className="path-input"><Folder size={16} /><input id="encrypt-destination" placeholder="Select an existing destination folder…" value={outputDir} readOnly /><button type="button" onClick={setOutputFromDialog}>Browse</button></div><p className="field-hint">Existing encrypted files are never overwritten. Choose an output location different from your source folder.</p>
                <div className="crypto-action-row"><div className="local-assurance"><LockKeyhole size={14} /><span>Runs offline on your device</span></div><button className="button button-primary" disabled={busy || !backendOnline} onClick={startEncrypt}><LockKeyhole size={15} /> Encrypt {selected.length ? `${selected.length} file${selected.length === 1 ? '' : 's'}` : 'selected files'} <ArrowRight size={14} /></button></div>
              </div>
              <div className="crypto-aside"><div className="encryption-visual"><div className="visual-glow" /><div className="visual-grid" /><div className="visual-lock"><LockKeyhole size={31} /></div><div className="visual-tag"><span className="live-dot" /> AES-256-GCM</div><div className="visual-title">Private by design.</div><div className="visual-subtitle">Strong encryption. Zero compromises.</div><div className="visual-points"><div><Check size={14} /> Authenticated encryption</div><div><Check size={14} /> Random salt + unique nonce</div><div><Check size={14} /> Originals stay untouched</div></div></div><div className="encryption-note"><div className="note-icon"><AlertCircle size={16} /></div><div><strong>Your password can’t be recovered</strong><span>SecureVault never stores your password or encryption key. If lost, encrypted files cannot be decrypted.</span></div></div><div className="crypto-meta"><div><span>KEY DERIVATION</span><strong>Scrypt · 256-bit key</strong></div><div><span>FILE FORMAT</span><strong>SVLT v1 · authenticated chunks</strong></div></div></div>
            </div>
            {job && <JobProgress job={job} onCancel={() => { void api.cancel(job.id) }} />}
          </section>}

          {page === 'Decryption & Biometric Verification' && <section className="page-section">
            <PageHeading eyebrow="DEVICE-VERIFIED RECOVERY" title="Decryption & verification" description="Recover using the original encryption passphrase. Windows Hello is an optional device-verification step; face-plus-fingerprint recovery remains unavailable unless both modalities can be independently verified." />
            <div className="integrity-warning"><ShieldAlert size={18} /><span><strong>Face-plus-fingerprint decryption is not enabled.</strong> Windows Biometric Framework can verify a fingerprint, but does not expose a supported face-matching API to SecureVault. A standalone fingerprint result does not authorize decryption. Password recovery is a separate, explicitly labeled fallback.</span></div>
            <div className="panel crypto-form biometric-workflow">
              <div className="form-section-title"><span className="step-number">01</span><div><strong>Select encrypted files</strong><span>Only encrypted metadata is displayed; no plaintext is read.</span></div></div>
              <div className={`encrypted-dropzone ${encrypted.length ? 'has-files' : ''}`}><div className="drop-icon"><FileKey2 size={22} /></div><strong>{encrypted.length ? `${encrypted.length} encrypted file${encrypted.length === 1 ? '' : 's'} selected` : 'Select SecureVault files'}</strong><span>{encrypted.length ? encrypted.map((file) => `${file.name}${file.size === undefined ? '' : ` · ${formatSize(file.size)}`}`).join(', ') : 'Choose one or more .svlt files to review their metadata.'}</span><button className="button button-secondary button-small" onClick={selectEncrypted}><FolderOpen size={14} /> Browse encrypted files</button></div>
              <div className="form-separator" />
              <div className="form-section-title"><span className="step-number">02</span><div><strong>Recovery authorization</strong><span>Mandatory face + fingerprint is denied unless both providers are independently verified.</span></div></div>
              <label className="field-label" htmlFor="decrypt-auth-mode">Authorization policy</label><select id="decrypt-auth-mode" className="field-select" value={authenticationMode} onChange={(event) => setAuthenticationMode(event.target.value === 'face_and_fingerprint' ? 'face_and_fingerprint' : 'password_fallback')}><option value="password_fallback">Password fallback (not biometric)</option><option value="face_and_fingerprint" disabled={!biometrics?.two_factor_supported}>Require face + fingerprint {!biometrics?.two_factor_supported ? '(unavailable — required factor unsupported)' : ''}</option></select>
              <p className="field-hint">SecureVault never silently changes a required biometric policy to password-only. The backend independently enforces this setting.</p>
              <div className="form-separator" />
              <div className="form-section-title"><span className="step-number">03</span><div><strong>Password authentication</strong><span>Use the same passphrase entered when these files were encrypted.</span></div></div>
              <label className="field-label" htmlFor="decrypt-password">Encryption password</label><div className="password-wrap"><LockKeyhole size={16} /><input id="decrypt-password" type="password" autoComplete="current-password" placeholder="Enter the encryption passphrase" value={decryptPassword} onChange={(event) => setDecryptPassword(event.target.value)} /><span className="secure-input-badge"><Shield size={12} /> NOT STORED</span></div><p className="field-hint">The password is sent only to the local backend for key derivation and is never written to the database, browser storage, or audit log.</p>
              <div className="form-separator" />
              <div className="form-section-title"><span className="step-number">03</span><div><strong>Windows Hello device verification</strong><span>Optional extra device confirmation; the encryption passphrase is still required.</span></div></div>
              <div className="encrypted-dropzone has-files"><div className="drop-icon"><ShieldCheck size={22} /></div><strong>{deviceAuthorizationId ? 'Windows Hello verified' : deviceAuth?.configured ? 'Windows Hello platform credential ready' : 'Windows Hello not configured'}</strong><span>{deviceAuthorizationId && deviceAuthorizationExpiresAt ? `Verified for these files and destination until ${new Date(deviceAuthorizationExpiresAt).toLocaleTimeString()}.` : deviceAuth?.message ?? 'Checking for a registered local platform credential…'}{!deviceAuth?.configured && deviceAuth?.available && ' Open Biometric Settings to register it.'}</span><div className="heading-actions"><button className="button button-secondary button-small" disabled={deviceAuthBusy || !encrypted.length || !outputDirId || !deviceAuth?.configured || !platformAuthenticatorAvailable} onClick={() => void verifyWithWindowsHello()}><ShieldCheck size={14} /> {deviceAuthBusy ? 'Waiting for Windows Hello…' : 'Verify with Windows Hello'}</button>{!deviceAuth?.configured && deviceAuth?.available && <button className="button button-secondary button-small" onClick={() => choosePage('Biometric Settings')}>Set up device</button>}</div></div>
              <div className="form-section-title"><span className="step-number">04</span><div><strong>Biometric provider checks</strong><span>A fingerprint check is recorded only after the Windows biometric service verifies a live sample against the current Windows account. It does not grant decryption permission.</span></div></div>
              <div className="factor-grid">
                <BiometricFactorCard icon={ScanFace} title="Face identity verification" status={faceResult || biometrics?.factors.face.status || 'NOT_STARTED'} message={biometrics?.factors.face.message ?? 'Checking the local biometric provider…'} onClick={() => void requestBiometric('face')} disabled={!encrypted.length || !biometrics?.factors.face.available} />
                <BiometricFactorCard icon={Fingerprint} title="Fingerprint authentication" status={fingerprintResult || biometrics?.factors.fingerprint.status || 'NOT_STARTED'} message={biometrics?.factors.fingerprint.message ?? 'Checking the local biometric provider…'} onClick={() => void requestBiometric('fingerprint')} disabled={!encrypted.length || !biometrics?.factors.fingerprint.available} />
              </div>
              <div className="form-separator" />
              <div className="form-section-title"><span className="step-number">05</span><div><strong>Recovery destination</strong><span>Plaintext is atomically written only after authenticated decryption and any available hash check.</span></div></div>
              <label className="field-label" htmlFor="decrypt-destination">Output directory</label><div className="path-input"><Folder size={16} /><input id="decrypt-destination" placeholder="Select an existing recovery folder…" value={outputDir} readOnly /><button type="button" onClick={setOutputFromDialog}>Browse</button></div>
              <div className="crypto-action-row"><div className="local-assurance"><LockKeyhole size={14} /><span>{deviceAuthorizationId ? 'Windows Hello device-verified password fallback' : 'Password fallback (not biometric authorization)'}</span></div><button className="button button-primary" disabled={busy || !backendOnline || !encrypted.length || !outputDirId || !decryptPassword} onClick={startDecrypt}><ShieldCheck size={15} /> {deviceAuthorizationId ? 'Decrypt with Windows Hello' : 'Decrypt with password fallback'} <ArrowRight size={14} /></button></div>
              {job && <JobProgress job={job} onCancel={() => { void api.cancel(job.id) }} />}
            </div>
            <p className="biometric-hint">AES-GCM authentication failures (wrong password or altered ciphertext) produce no recovered file. When a trusted original hash exists, a mismatch also prevents recovery output from being published.</p>
          </section>}

          {page === 'Integrity Verification' && <section className="page-section">
            <PageHeading eyebrow="TRUSTED FILE INTEGRITY" title="Integrity verification" description="Review verification outcomes that were recorded against an independently stored original SHA-256." />
            <div className="integrity-warning"><ShieldAlert size={18} /><span><strong>Verification requires the encryption password.</strong> Results are MATCH, MISMATCH, or UNAVAILABLE when no trusted original hash exists; decryption success alone is not counted as a match.</span></div>
            <div className="panel audit-panel"><div className="panel-header"><div><h2>Recorded comparisons <span className="count-badge">{records.filter((record) => record.verification_result).length}</span></h2><p>Only persisted backend comparison results appear here.</p></div><button className="button button-secondary button-small" onClick={() => void refreshRecords()}><RefreshCw size={14} /> Refresh</button></div>{records.some((record) => record.verification_result) ? <div className="table-scroll"><table><thead><tr><th>FILE</th><th>TRUSTED ORIGINAL SHA-256</th><th>RESULT</th><th>RECORDED AT</th></tr></thead><tbody>{records.filter((record) => record.verification_result).map((record) => <tr key={record.id}><td><button className="file-name-cell" onClick={() => setDetail(record)}><FileBadge name={record.filename} /><span>{record.filename}<small>{record.relative_source_path}</small></span></button></td><td className="mono subdued">{record.sha256 ?? 'Unavailable'}</td><td><StatusChip status={record.verification_result ?? 'UNAVAILABLE'} /></td><td className="subdued">{new Date(record.timestamp).toLocaleString()}</td></tr>)}</tbody></table></div> : <EmptyState icon={ShieldCheck} title="No verification results recorded" description="SecureVault does not invent matches. A result appears here only after authenticated recovery and comparison with a trusted original hash." action="Open decryption" onAction={() => choosePage('Decryption & Biometric Verification')} />}</div>
          </section>}

          {page === 'Audit Reports' && <section className="page-section">
            <PageHeading eyebrow="AUDIT & REPORTING" title="An honest record." description="Review locally persisted operations and export their audit history to an Excel workbook." action={<div className="heading-actions"><button className="button button-secondary" disabled={loading} onClick={async () => { try { await Promise.all([refreshRecords(), refreshStats(), refreshAuditProtection()]); toast('success', 'Audit records refreshed.') } catch (error) { toast('error', error instanceof Error ? error.message : 'Could not refresh records.') } }}><RefreshCw size={15} className={loading ? 'spin' : ''} /> Refresh</button><button className="button button-primary" disabled={!records.length} onClick={async () => { try { saveBlob(await api.export(), 'securevault-audit.xlsx'); toast('success', 'Excel audit report exported.') } catch (error) { toast('error', error instanceof Error ? error.message : 'Could not export report.') } }}><Download size={15} /> Export .xlsx</button></div>} />
            <div className="audit-summary-row"><div className="audit-summary"><div className="audit-summary-icon blue"><ActivityIcon size={18} /></div><div><span>TOTAL RECORDS</span><strong>{records.length}</strong></div></div><div className="audit-summary"><div className="audit-summary-icon green"><ShieldCheck size={18} /></div><div><span>SUCCESSFUL</span><strong>{records.filter((record) => record.status === 'SUCCESS').length}</strong></div></div><div className="audit-summary"><div className="audit-summary-icon red"><ShieldAlert size={18} /></div><div><span>FAILED</span><strong>{records.filter((record) => record.status === 'FAILED').length}</strong></div></div><div className="audit-summary audit-summary-protected"><div className="audit-summary-icon teal"><LockKeyhole size={18} /></div><div><span>RECORD PROTECTION</span><strong>{auditProtection ? auditVerified ? 'Verified' : 'Integrity warning' : 'Not enabled'}</strong></div></div></div>
            {auditProtection && !auditVerified && <div className="integrity-warning"><AlertCircle size={17} /><span><strong>Audit chain verification failed.</strong> Records may have been changed outside SecureVault.</span></div>}
            <div className="panel audit-panel"><div className="panel-header audit-panel-header"><div><h2>Operation history <span className="count-badge">{visibleRecords.length}</span></h2><p>Persisted locally · audit metadata excludes secrets</p></div><SearchField value={query} onChange={setQuery} placeholder="Search records…" /></div>{visibleRecords.length ? <div className="table-scroll"><table className="audit-table"><thead><tr><th>FILE</th><th>OPERATION</th><th>TIMESTAMP</th><th>STATUS</th><th>VERIFICATION</th><th>OUTPUT</th></tr></thead><tbody>{visibleRecords.map((record) => <tr key={record.id}><td><button className="file-name-cell" onClick={() => setDetail(record)}><FileBadge name={record.filename} /><span>{record.filename}<small>{record.relative_source_path}</small></span></button></td><td><OperationChip operation={record.operation} /></td><td className="subdued">{new Date(record.timestamp).toLocaleString()}</td><td><StatusChip status={record.status} /></td><td>{record.verification_result ? <StatusChip status={record.verification_result} /> : <span className="subdued">—</span>}</td><td className="mono path-cell" title={record.encrypted_path ?? ''}>{record.encrypted_path?.split(/[\\/]/).slice(-2).join('\\') ?? '—'}</td></tr>)}</tbody></table></div> : <EmptyState icon={FileText} title="No audit records yet" description="Your scans and operations will appear here after they run." action="Start a scan" onAction={() => choosePage('File Scanner')} />}{records.length > 0 && <div className="panel-footer"><span>Showing {visibleRecords.length} of {records.length} records</span><button className="text-button" onClick={() => void refreshRecords()}>Refresh data <RefreshCw size={13} /></button></div>}</div>
            <div className="report-security-note"><Shield size={16} /><div><strong>Reports contain file metadata and hashes only.</strong><span>Passwords and raw encryption keys are never included. User-entered values are escaped against spreadsheet formula injection.</span></div></div>
          </section>}

          {page === 'Biometric Settings' && <section className="page-section">
            <PageHeading eyebrow="DEVICE AUTHENTICATION" title="Windows Hello and biometric status." description="Register a platform credential to use Windows Hello as a device-verification step for recovery." action={<div className="heading-actions"><button className="button button-secondary" disabled={loading} onClick={async () => { try { await Promise.all([refreshBiometrics(), refreshDeviceAuth(), refreshRecords()]); toast('info', 'Local authentication status refreshed.') } catch (error) { toast('error', error instanceof Error ? error.message : 'Could not refresh authentication status.') } }}><RefreshCw size={15} /> Retry Detection</button><button className="button button-primary" disabled={deviceAuthBusy || !deviceAuth?.os_supported || !platformAuthenticatorAvailable} onClick={() => void registerWindowsHello()}><ShieldCheck size={15} /> {deviceAuthBusy ? 'Waiting for Windows Hello…' : 'Register Windows Hello'}</button></div>} />
            <div className="integrity-warning biometric-block"><ShieldAlert size={18} /><span><strong>Windows Hello does not attest which modality was used.</strong> WBF offers fingerprint-specific matching, which is detected below. A separate face match is not exposed by its supported application APIs, so the required two-factor combination cannot be authorized.</span></div>
            <div className="panel settings-panel provider-note"><h2>Windows Hello platform credential</h2><p>{deviceAuth?.message ?? 'Checking local credential registration…'} SecureVault validates the signed assertion using the stored public key; the private key stays with the platform authenticator.</p><p className="field-hint">If browser detection is unavailable, open this loopback app in a WebAuthn-capable browser such as Edge or Chrome and configure Windows Hello under Settings &gt; Accounts &gt; Sign-in options.</p><div className="settings-info-line"><span>Windows OS support</span><strong>{deviceAuth?.os_supported ? 'Supported' : 'Unsupported'}</strong></div><div className="settings-info-line"><span>Browser platform authenticator</span><strong>{platformAuthenticatorAvailable ? 'Detected by browser API' : 'Unavailable or not exposed by browser'}</strong></div><div className="settings-info-line"><span>Credential registration</span><strong>{deviceAuth?.registration_status ?? 'UNKNOWN'} · {deviceAuth?.credential_count ?? 0} credential(s)</strong></div><div className="settings-info-line"><span>Credential assertion authentication</span><strong>{deviceAuth?.configured ? 'Available; requires a fresh signed assertion' : 'Unavailable until registered'}</strong></div><div className="settings-info-line"><span>Authentication modality</span><strong>Not attested by WebAuthn; may be face, fingerprint, or PIN</strong></div></div>
            <div className="panel settings-panel provider-note"><h2>Windows Biometric Framework diagnostics</h2><p>{biometrics?.provider_message ?? 'Checking provider capabilities through the local backend…'} Retry Detection re-queries Windows Biometric Service, WBF sensor enumeration, and current-account enrollment. Detection is not an authentication.</p><div className="settings-info-line"><span>Operating system</span><strong>{biometrics ? `${biometrics.operating_system.name} ${biometrics.operating_system.version ?? ''}`.trim() : 'Checking…'}</strong></div><div className="settings-info-line"><span>Windows Biometric Service</span><strong>{biometrics?.windows_biometric_service.status ?? 'UNKNOWN'} · {biometrics?.windows_biometric_service.message ?? 'Checking…'}</strong></div><div className="settings-info-line"><span>Native provider initialization</span><strong>{biometrics?.native_provider_status ?? 'Checking…'} · {biometrics?.native_provider_message ?? ''}</strong></div><div className="settings-info-line"><span>Fingerprint hardware</span><strong>{biometrics?.factors.fingerprint.hardware_status ?? 'UNKNOWN'} · {biometrics?.factors.fingerprint.device_count ?? 0} device(s)</strong></div><div className="settings-info-line"><span>Fingerprint enrollment</span><strong>{biometrics?.factors.fingerprint.enrollment_status ?? 'UNKNOWN'}</strong></div><div className="settings-info-line"><span>Latest biometric/device authentication</span><strong>{latestBiometricAttempt ? `${latestBiometricAttempt.operation}: ${latestBiometricAttempt.status} · ${new Date(latestBiometricAttempt.timestamp).toLocaleString()}` : 'No authentication attempt recorded'}</strong></div><div className="settings-info-line"><span>Independent face + fingerprint authorization</span><strong>{biometrics?.two_factor_supported ? 'Supported' : 'Unavailable — face modality is not independently exposed'}</strong></div></div>
            <div className="factor-settings-grid"><BiometricCapabilityCard icon={ScanFace} title="Face identity verification" factor={biometrics?.factors.face} /><BiometricCapabilityCard icon={Fingerprint} title="Fingerprint authentication" factor={biometrics?.factors.fingerprint} /></div>
            <div className="panel settings-panel provider-note"><h2>Provider-specific requirements</h2><p>Face verification requires a separate supported native provider that can attest its modality. A standard webcam is not evidence of a Windows Hello facial sensor. Fingerprint requires a WBF-compatible sensor, Windows Biometric Service, and fingerprint enrollment for the signed-in Windows account.</p><div className="settings-info-line"><span>Face modality</span><strong>{biometrics?.factors.face.modality_identifiable ? 'Independently identifiable' : 'Not independently available'}</strong></div><div className="settings-info-line"><span>Fingerprint modality</span><strong>{biometrics?.factors.fingerprint.modality_identifiable ? 'Independently identifiable' : 'Not independently available'}</strong></div><div className="settings-info-line"><span>Face + fingerprint policy</span><strong>{biometrics?.two_factor_supported ? 'Available' : 'Denied — a required factor is unavailable'}</strong></div><div className="settings-info-line"><span>Password fallback</span><strong>Available · separate from biometrics</strong></div></div>
            <div className="report-security-note"><Clock3 size={16} /><div><strong>No biometric templates are stored.</strong><span>SecureVault stores a WebAuthn public key and credential metadata only. Windows Hello retains the private credential and biometric data on the device.</span></div></div>
          </section>}

          {page === 'Security Settings' && <section className="page-section">
            <PageHeading eyebrow="PREFERENCES & SECURITY" title="Security settings" description="Manage local audit protection and review the security boundaries of this installation." />
            <div className="settings-layout"><div className="panel settings-panel"><div className="settings-section-heading"><div className="settings-leading-icon"><ShieldCheck size={19} /></div><div><h2>Security</h2><p>Strengthen your local audit records and review active security protections.</p></div></div><div className="setting-row"><div className="setting-copy"><strong>Tamper-evident audit chain</strong><span>Protects operation history with a local HMAC-SHA-256 chain. Its signing key is stored separately from the audit database.</span>{auditProtection && <span className={`verification-line ${auditVerified ? 'verified' : 'unverified'}`}>{auditVerified ? <CheckCircle2 size={14} /> : <AlertCircle size={14} />}{auditVerified ? 'Audit records verified' : 'Audit records failed verification'}</span>}</div><button type="button" role="switch" aria-checked={auditProtection} className={`toggle-switch ${auditProtection ? 'toggle-on' : ''}`} onClick={() => { setConfirm({ title: auditProtection ? 'Disable audit record protection?' : 'Enable audit record protection?', message: auditProtection ? 'New audit activity will no longer extend the integrity chain.' : 'An HMAC-SHA-256 chain will be initialized for all current and future audit records.', action: () => { void api.auditProtection(!auditProtection).then((result) => { setAuditProtection(result.enabled); setAuditVerified(result.verified); toast('success', result.enabled ? 'Audit protection enabled.' : 'Audit protection disabled.') }).catch((error) => toast('error', error instanceof Error ? error.message : 'Could not update audit protection.')) } }) }}><span /></button></div><div className="settings-divider" /><div className="setting-row"><div className="setting-copy"><strong>Local session authentication</strong><span>API requests require a session token generated at backend startup. The API binds to loopback only.</span></div><span className={`setting-status ${backendOnline ? 'status-good' : 'status-bad'}`}><span className="status-indicator" />{backendOnline ? 'Active' : 'Unavailable'}</span></div><div className="settings-divider" /><div className="setting-row"><div className="setting-copy"><strong>Windows Hello device verification</strong><span>{deviceAuth?.configured ? 'A registered Windows Hello platform credential can verify the local user before recovery. The operating system may use face, fingerprint, or PIN; SecureVault cannot identify which method was used.' : 'Windows Hello is not registered yet. Register a platform credential in Biometric Settings to enable optional device verification. Password-only recovery remains available.'} Face-only and fingerprint-only authentication are not independently supported.</span></div><span className={`setting-status ${deviceAuth?.configured ? 'status-good' : 'status-bad'}`}><span className="status-indicator" />{deviceAuth?.configured ? 'Configured' : 'Not configured'}</span></div></div>
              <div className="settings-aside"><div className="panel settings-info"><div className="settings-info-icon"><LockKeyhole size={19} /></div><h3>Your security, by design.</h3><p>Cryptographic keys and passwords stay in memory only for the active operation. Audit data is stored locally under your user profile.</p><div className="settings-info-line"><span>Encryption</span><strong>AES-256-GCM</strong></div><div className="settings-info-line"><span>Key derivation</span><strong>Scrypt</strong></div><div className="settings-info-line"><span>Integrity hashes</span><strong>SHA-256</strong></div><div className="settings-info-line"><span>Network access</span><strong>Loopback only</strong></div></div><div className="settings-notice"><AlertCircle size={15} /><span>Local audit records do not use a certified hardware key store. Protect your operating-system account and backup important data.</span></div></div></div>
          </section>}
        </div>
        <footer className="app-footer"><div className="footer-brand"><Shield size={14} /> <span>SECUREVAULT</span><span className="footer-version">v1.0.0</span></div><div className="footer-links"><span><span className="live-dot" /> ALL FILES STAY ON THIS DEVICE</span><span className="footer-divider" /><span>ENCRYPTION IS NOT CERTIFICATION</span></div><span className="footer-copy">© SecureVault</span></footer>
      </main>

      {notice && <div className={`toast toast-${notice.type}`} role="status"><div className="toast-icon">{notice.type === 'success' ? <CheckCircle2 size={18} /> : notice.type === 'error' ? <XCircle size={18} /> : <ActivityIcon size={17} />}</div><span>{notice.text}</span><button aria-label="Dismiss notification" onClick={() => setNotice(null)}><X size={15} /></button></div>}
      {detail && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setDetail(null) }}><div className="modal detail-modal"><div className="modal-header"><div><div className="eyebrow"><span className="eyebrow-line" /> RECORD DETAILS</div><h2>{'filename' in detail ? detail.filename : detail.name}</h2></div><button className="icon-btn" aria-label="Close details" onClick={() => setDetail(null)}><X size={18} /></button></div>{'sha256' in detail && <div className="detail-body">{'size' in detail && <DetailItem label="FILE SIZE" value={formatSize(detail.size)} />}{'file_size' in detail && <DetailItem label="FILE SIZE" value={formatSize(detail.file_size)} />}{'relative_path' in detail && <DetailItem label="RELATIVE PATH" value={detail.relative_path} />}{'relative_source_path' in detail && <DetailItem label="SOURCE PATH" value={detail.relative_source_path} />}{'extension' in detail && <DetailItem label="FILE TYPE" value={detail.extension} />}{'operation' in detail && <DetailItem label="OPERATION" value={detail.operation} />}{'timestamp' in detail && <DetailItem label="TIMESTAMP" value={new Date(detail.timestamp).toLocaleString()} />}{'sha256' in detail && <div className="detail-item detail-hash"><span>SHA-256</span><code>{detail.sha256}</code><button className="copy-button" onClick={() => { if (detail.sha256) { void navigator.clipboard.writeText(detail.sha256); toast('success', 'SHA-256 copied to clipboard.') } }}>Copy hash</button></div>}{'encrypted_path' in detail && detail.encrypted_path && <DetailItem label="ENCRYPTED OUTPUT" value={detail.encrypted_path} />}{'status' in detail && <DetailItem label="STATUS" value={detail.status} />}{'verification_result' in detail && <DetailItem label="VERIFICATION" value={detail.verification_result ?? 'Not performed'} />}{'error_details' in detail && detail.error_details && <DetailItem label="ERROR" value={detail.error_details} />}</div>}<div className="modal-footer"><button className="button button-secondary" onClick={() => setDetail(null)}>Close</button></div></div></div>}
      {confirm && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setConfirm(null) }}><div className="modal confirm-modal"><div className="confirm-icon"><AlertCircle size={20} /></div><h2>{confirm.title}</h2><p>{confirm.message}</p><div className="modal-footer"><button className="button button-secondary" onClick={() => setConfirm(null)}>Cancel</button><button className="button button-primary" onClick={() => { confirm.action(); setConfirm(null) }}>Confirm</button></div></div></div>}
      {menuOpen && <div className="mobile-overflow" onClick={() => setMenuOpen(false)}><div className="overflow-menu" onClick={(event) => event.stopPropagation()}><button onClick={() => { setMenuOpen(false); choosePage('Security Settings') }}><Settings2 size={15} /> Security settings</button><button onClick={() => { setMenuOpen(false); choosePage('Biometric Settings') }}><Fingerprint size={15} /> Biometric settings</button><button onClick={() => { setMenuOpen(false); void refreshAll() }}><RefreshCw size={15} /> Refresh data</button><button onClick={() => { setMenuOpen(false); choosePage('Audit Reports') }}><FileText size={15} /> Audit reports</button><button onClick={() => { setMenuOpen(false); toast('info', 'SecureVault runs entirely on your local device.') }}><LogOut size={15} /> Local workspace</button></div></div>}
    </div>
  )
}

function FileBadge({ name }: { name: string }) { const Icon = iconFor(name); return <span className="file-badge"><Icon size={16} /></span> }
function BiometricFactorCard({ icon: Icon, title, status, message, onClick, disabled }: { icon: typeof ScanFace; title: string; status: string; message: string; onClick: () => void; disabled: boolean }) {
  const supported = status === 'SUCCESS' || status === 'READY'
  const buttonLabel = disabled
    ? status === 'UNSUPPORTED' ? 'Unsupported by provider' : `Unavailable — ${status.replace(/_/g, ' ').toLowerCase()}`
    : title.startsWith('Fingerprint') ? 'Verify fingerprint (no decryption grant)' : 'Start system verification'
  return <div className={`factor-card ${supported ? 'factor-supported' : 'factor-unavailable'}`}><div className="factor-card-top"><span className="factor-icon"><Icon size={19} /></span><StatusChip status={status} /></div><strong>{title}</strong><p>{message}</p><button className="button button-secondary button-small" disabled={disabled} onClick={onClick}>{buttonLabel}</button></div>
}
function BiometricCapabilityCard({ icon: Icon, title, factor }: { icon: typeof ScanFace; title: string; factor?: { available: boolean; status: string; message: string; hardware_status: string; enrollment_status: string; modality_identifiable: boolean; device_count: number } }) {
  return <div className={`panel capability-card ${factor?.available ? 'factor-supported' : 'factor-unavailable'}`}><div className="factor-card-top"><span className="factor-icon"><Icon size={20} /></span><StatusChip status={factor?.status ?? 'UNAVAILABLE'} /></div><h2>{title}</h2><p>{factor?.message ?? 'Capability status has not been retrieved from the local backend.'}</p><div className="capability-result"><span>Hardware</span><strong>{factor?.hardware_status ?? 'UNKNOWN'}</strong></div><div className="capability-result"><span>Current-account enrollment</span><strong>{factor?.enrollment_status ?? 'UNKNOWN'}</strong></div><div className="capability-result"><span>Device count</span><strong>{factor?.device_count ?? 0}</strong></div><div className="capability-result"><span>Independent modality verification</span><strong>{factor?.modality_identifiable ? 'Supported' : 'Unsupported'}</strong></div></div>
}
function ActivityRow({ record, onClick }: { record: Activity; onClick: () => void }) {
  const style = record.operation === 'ENCRYPT' ? 'teal' : record.operation === 'DECRYPT' ? 'purple' : 'blue'
  const Icon = record.status === 'FAILED' ? AlertCircle : record.operation === 'ENCRYPT' ? LockKeyhole : record.operation === 'DECRYPT' ? ArrowDownToLine : FileCheck2
  return <button className="activity-row" onClick={onClick}><div className={`activity-icon ${style}`}><Icon size={15} /></div><div className="activity-copy"><strong>{record.filename}</strong><span>{record.operation === 'ENCRYPT' ? 'Encrypted' : record.operation === 'DECRYPT' ? 'Decrypted' : record.operation} · {relativeTime(record.timestamp)}</span></div><StatusChip status={record.status} /><ArrowUpRight size={14} className="activity-open" /></button>
}
function QuickAction({ icon: Icon, color, title, description, onClick }: { icon: typeof ScanLine; color: string; title: string; description: string; onClick: () => void }) { return <button className="quick-action" onClick={onClick}><span className={`quick-icon ${color}`}><Icon size={17} /></span><span className="quick-copy"><strong>{title}</strong><small>{description}</small></span><ChevronRight size={16} className="quick-chevron" /></button> }
function StatusChip({ status }: { status: string }) {
  const value = status === 'MATCH' || status === 'SUCCESS' || status === 'READY' ? 'success' : status === 'MISMATCH' || status === 'FAILED' ? 'error' : 'neutral'
  const label = status === 'SUCCESS' ? 'Success' : status === 'FAILED' ? 'Failed' : status === 'MATCH' ? 'Match' : status === 'MISMATCH' ? 'Mismatch' : status === 'READY' ? 'Ready' : status === 'UNAVAILABLE' ? 'Unavailable' : status.replace(/_/g, ' ').toLowerCase()
  return <span className={`status-chip ${value}`}><span />{label}</span>
}
function OperationChip({ operation }: { operation: string }) { return <span className={`operation-chip ${operation.toLowerCase()}`}><span className="operation-dot" />{operation}</span> }
function EmptyState({ icon: Icon, title, description, action, onAction }: { icon: typeof FileSearch; title: string; description: string; action: string; onAction: () => void }) { return <div className="empty-state"><div className="empty-icon"><Icon size={23} /></div><strong>{title}</strong><p>{description}</p><button className="button button-secondary button-small" onClick={onAction}>{action} <ArrowRight size={14} /></button></div> }
function EmptyInline({ text, action, onClick }: { text: string; action: string; onClick: () => void }) { return <div className="empty-inline"><span>{text}</span><button className="text-button" onClick={onClick}>{action} <ArrowRight size={13} /></button></div> }
function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: React.ReactNode }) { return <div className="page-heading-row"><div><div className="eyebrow"><span className="eyebrow-line" /> {eyebrow}</div><h1>{title}</h1><p className="page-description">{description}</p></div>{action}</div> }
function SearchField({ value, onChange, placeholder }: { value: string; onChange: (value: string) => void; placeholder: string }) { return <label className="search-field"><Search size={15} /><input aria-label={placeholder} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} />{value && <button aria-label="Clear search" onClick={() => onChange('')}><X size={13} /></button>}</label> }
function DetailItem({ label, value }: { label: string; value: string }) { return <div className="detail-item"><span>{label}</span><strong>{value}</strong></div> }
function JobProgress({ job, onCancel }: { job: Job; onCancel: () => void }) { const terminal = !['queued', 'running'].includes(job.status); return <div className={`job-card ${terminal ? 'job-done' : ''}`}><div className="job-icon">{terminal ? job.status === 'completed' ? <CheckCircle2 size={17} /> : <AlertCircle size={17} /> : <LoaderCircle size={17} className="spin" />}</div><div className="job-main"><div className="job-title-row"><strong>{job.message}</strong><span>{job.completed}{job.total ? ` / ${job.total}` : ''} {job.total ? 'files' : ''}</span></div><div className="progress-track"><span style={{ width: `${job.progress}%` }} /></div><div className="job-status-line"><span>{terminal ? job.status : 'In progress'} · {job.progress}%</span>{!terminal && <button onClick={onCancel}>Cancel</button>}</div></div></div> }

export default App
