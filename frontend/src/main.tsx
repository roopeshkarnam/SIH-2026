import React, { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { ArrowRight, Check, Download, Inbox, KeyRound, Lock, LockKeyhole, Search, Send, ShieldCheck, Upload, UserRound } from 'lucide-react'
import './styles.css'

type DocumentItem = { document_id: string; filename: string; document_hash: string; encrypted: boolean; created_at: string }
type Result = Record<string, any>
type Role = 'sender' | 'recipient' | 'investigator'
type StepId = 'keys' | 'encrypt' | 'decrypt' | 'sign' | 'trace'

const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

const ROLES: { id: Role; label: string; icon: any; who: string }[] = [
  { id: 'sender', label: 'Sender', icon: Send, who: 'You are the office distributing a confidential document.' },
  { id: 'recipient', label: 'Recipient', icon: Inbox, who: 'You are the officer who receives the document and opens it.' },
  { id: 'investigator', label: 'Investigator', icon: Search, who: 'A copy of the document has leaked. You find out whose copy it was.' },
]

const STEPS: { id: StepId; role: Role; title: string; plain: string; crypto: string }[] = [
  {
    id: 'keys', role: 'recipient', title: 'Create your keys',
    plain: 'Before anyone can send you a protected file, you need keys: a public "lock" that senders use to seal files for you, and a private key that only you hold to open them. A second key pair lets you sign records.',
    crypto: 'Generates an ML-KEM-768 key pair (FIPS 203, key encapsulation) and a separate ML-DSA-65 key pair (FIPS 204, signatures). Private keys are stored AES-256-GCM encrypted on the server. Regenerating keys makes files encrypted to the old keys unreadable.',
  },
  {
    id: 'encrypt', role: 'sender', title: 'Encrypt & send a document',
    plain: 'Choose a file. It is locked with a fresh random key, and that key is sealed with the recipient\'s public lock, so only the recipient can open it.',
    crypto: 'A new 256-bit AES-GCM key encrypts the file with a random 12-byte nonce. ML-KEM-768 encapsulation against the recipient\'s public key gives a shared secret; HKDF-SHA256, bound to this document ID and recipient ID, turns it into a wrapping key that encrypts the AES key. The SHA-256 hash of the original is stored for integrity checks.',
  },
  {
    id: 'decrypt', role: 'recipient', title: 'Open the document',
    plain: 'Open the file you were sent. Your copy gets a unique, invisible watermark ID hidden inside it, so if it ever leaks it can be traced back to this exact opening.',
    crypto: 'ML-KEM decapsulation with your private key recovers the shared secret → HKDF → wrapping key → AES key → file, then the SHA-256 hash is checked. A decryption session is created with a random session nonce and a watermark ID (WM-…), which is written into PDFs as invisible text and metadata.',
  },
  {
    id: 'sign', role: 'recipient', title: 'Sign the access record',
    plain: 'Create a tamper-proof record of who opened which document and when. It is digitally signed, so any later change to it is detected.',
    crypto: 'The record (document ID and hash, recipient, session, watermark ID, session nonce, timestamp) is canonicalised and hashed with SHA-256, signed with ML-DSA-65, and committed to the development ledger adapter (Hyperledger Fabric planned).',
  },
  {
    id: 'trace', role: 'investigator', title: 'Trace a leaked copy',
    plain: 'Upload the leaked PDF. The hidden watermark ID is read out of it and matched against the signed records to show whose copy it was.',
    crypto: 'The watermark ID is extracted from the PDF text layer and metadata, then looked up among the ML-DSA-signed provenance records. Limitation: this text-layer watermark survives forwarding and re-saving, but not screenshots or print-and-scan.',
  },
]

async function api(path: string, options: RequestInit = {}, token?: string) {
  const headers = new Headers(options.headers)
  if (!(options.body instanceof FormData) && !(options.body instanceof URLSearchParams)) headers.set('Content-Type', 'application/json')
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const response = await fetch(`${API}${path}`, { ...options, headers })
  const data = await response.json().catch(() => ({}))
  if (response.status === 401 && token) {
    // Login expired: sign out and explain why on the login screen.
    localStorage.removeItem('sih_token'); localStorage.setItem('sih_notice', 'Your session expired. Please sign in again.'); location.reload()
  }
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`)
  return data
}

const short = (v: unknown) => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s.length > 48 ? `${s.slice(0, 24)}…${s.slice(-12)}` : s }

function App() {
  const [token, setToken] = useState(localStorage.getItem('sih_token') || '')
  const [userId, setUserId] = useState(localStorage.getItem('sih_user_id') || '')
  const [username, setUsername] = useState(localStorage.getItem('sih_username') || '')
  const [password, setPassword] = useState('')
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [notice, setNotice] = useState(localStorage.getItem('sih_notice') || '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState<Partial<Record<StepId, Result>>>({})
  const [role, setRole] = useState<Role>('recipient')
  const [file, setFile] = useState<File | null>(null)
  const [leak, setLeak] = useState<File | null>(null)
  const [documents, setDocuments] = useState<DocumentItem[]>([])
  const [selectedDocument, setSelectedDocument] = useState('')
  const [watermark, setWatermark] = useState('')

  const current = STEPS.find(s => !done[s.id])

  useEffect(() => { localStorage.removeItem('sih_notice') }, [])
  useEffect(() => { if (token) refreshDocuments() }, [token])
  // Move to whoever acts next.
  useEffect(() => { if (current) setRole(current.role) }, [current?.id])

  async function refreshDocuments() {
    try { setDocuments(await api('/documents/mine', {}, token)) } catch (e) { setError((e as Error).message) }
  }

  async function submitAuth() {
    setBusy(true); setNotice('')
    try {
      if (mode === 'register') {
        await api('/auth/register', { method: 'POST', body: JSON.stringify({ username, password }) })
        setMode('login'); setNotice('Account created. Sign in to continue.')
      } else {
        const data = await api('/auth/login', { method: 'POST', body: new URLSearchParams({ username, password }) })
        setToken(data.access_token); setUserId(data.user_id)
        localStorage.setItem('sih_token', data.access_token); localStorage.setItem('sih_user_id', data.user_id); localStorage.setItem('sih_username', data.username)
      }
    } catch (e) { setNotice((e as Error).message) } finally { setBusy(false) }
  }

  function logout() { localStorage.removeItem('sih_token'); setToken(''); setDone({}); setDocuments([]) }

  // Runs one step; on success the step is marked done with its result.
  async function run(step: StepId, action: () => Promise<Result>) {
    setBusy(true); setError('')
    try { const data = await action(); setDone(d => ({ ...d, [step]: data })) }
    catch (e) { setError((e as Error).message) } finally { setBusy(false) }
  }

  const generateKeys = () => run('keys', () => api(`/users/${userId}/pqc-keys`, { method: 'POST' }, token))

  const encrypt = () => run('encrypt', async () => {
    const form = new FormData(); form.append('file', file!)
    const data = await api(`/documents/upload?recipient_id=${encodeURIComponent(userId)}`, { method: 'POST', body: form }, token)
    setSelectedDocument(data.document_id); await refreshDocuments()
    return data
  })

  const decrypt = () => run('decrypt', () => api(`/decryption/${selectedDocument}/${userId}`, { method: 'POST' }, token))

  const sign = () => run('sign', () => api(`/provenance/create/${done.decrypt!.session_id}`, { method: 'POST' }, token))

  const trace = () => run('trace', () => {
    const form = new FormData(); form.append('file', leak!)
    return api('/forensics/extract', { method: 'POST', body: form }, token)
  })

  const lookup = () => run('trace', () => api(`/forensics/lookup/${encodeURIComponent(watermark)}`, {}, token))

  async function download() {
    try {
      const response = await fetch(`${API}/decryption/file/${done.decrypt!.session_id}`, { headers: { Authorization: `Bearer ${token}` } })
      if (!response.ok) throw new Error((await response.json().catch(() => ({}))).detail || 'Download failed.')
      const name = documents.find(d => d.document_id === done.decrypt!.document_id)?.filename || 'document.pdf'
      const link = document.createElement('a'); link.href = URL.createObjectURL(await response.blob()); link.download = `watermarked_${name}`; link.click()
    } catch (e) { setError((e as Error).message) }
  }

  function restart() { setDone({}); setFile(null); setLeak(null); setWatermark(''); setError('') }

  if (!token) return <Auth mode={mode} setMode={setMode} username={username} setUsername={setUsername} password={password} setPassword={setPassword} submit={submitAuth} busy={busy} message={notice} />

  function controls(id: StepId) {
    if (id === 'keys') return <button className="primary" onClick={generateKeys} disabled={busy}>{busy ? 'Generating…' : 'Generate my keys'} <ArrowRight size={16}/></button>
    if (id === 'encrypt') return <>
      <label className="drop"><Upload size={22}/><span>{file ? file.name : 'Click to choose a file (PDF works best)'}</span><input type="file" onChange={e => setFile(e.target.files?.[0] || null)}/></label>
      <button className="primary" onClick={encrypt} disabled={busy || !file}>{busy ? 'Encrypting…' : 'Encrypt & send'} <ArrowRight size={16}/></button>
    </>
    if (id === 'decrypt') return <>
      <select value={selectedDocument} onChange={e => setSelectedDocument(e.target.value)}><option value="">Choose a document</option>{documents.map(d => <option key={d.document_id} value={d.document_id}>{d.filename}</option>)}</select>
      <button className="primary" onClick={decrypt} disabled={busy || !selectedDocument}>{busy ? 'Opening…' : 'Open & watermark'} <ArrowRight size={16}/></button>
    </>
    if (id === 'sign') return <button className="primary" onClick={sign} disabled={busy}>{busy ? 'Signing…' : 'Sign the record'} <ArrowRight size={16}/></button>
    return <>
      <label className="drop"><Upload size={22}/><span>{leak ? leak.name : 'Click to choose the leaked PDF (e.g. the copy you downloaded in step 3)'}</span><input type="file" accept="application/pdf" onChange={e => setLeak(e.target.files?.[0] || null)}/></label>
      <button className="primary" onClick={trace} disabled={busy || !leak}>{busy ? 'Tracing…' : 'Find the source'} <ArrowRight size={16}/></button>
      <div className="orLookup"><span>or look up an ID directly</span><input value={watermark} onChange={e => setWatermark(e.target.value)} placeholder="WM-…"/><button onClick={lookup} disabled={busy || !watermark}>Look up</button></div>
    </>
  }

  function summary(id: StepId, r: Result) {
    if (id === 'keys') return 'ML-KEM-768 and ML-DSA-65 key pairs created'
    if (id === 'encrypt') return <><b>{r.filename}</b> encrypted with AES-256-GCM and sealed for the recipient</>
    if (id === 'decrypt') return <>Opened. Watermark <code>{r.watermark_id}</code> {r.watermark_status === 'embedded-in-pdf' ? 'is hidden inside your copy' : 'recorded (not a PDF, so nothing embedded)'}</>
    if (id === 'sign') return <>Signed with ML-DSA-65 · ledger entry <code>{short(r.ledger_transaction_id)}</code></>
    return <>Leak traced to <b>{r.recipient_id === userId ? `${username} (you, in demo mode)` : r.recipient_id}</b> · session <code>{short(r.session_id)}</code></>
  }

  const roleInfo = ROLES.find(r => r.id === role)!
  const roleSteps = STEPS.filter(s => s.role === role)

  return <div className="app">
    <header className="topbar">
      <div className="brand"><div className="brandMark"><ShieldCheck size={20}/></div><div><strong>CRYPTA</strong><span>Cryptographic Attribution</span></div></div>
      <nav className="roleTabs">{ROLES.map(r => {
        const steps = STEPS.filter(s => s.role === r.id)
        const complete = steps.every(s => done[s.id])
        const waiting = current?.role === r.id
        return <button key={r.id} className="roleTab" data-selected={role === r.id} onClick={() => setRole(r.id)}>
          <r.icon size={16}/>{r.label}{complete ? <span className="tabDone"><Check size={12}/></span> : waiting ? <span className="tabNow"/> : null}
        </button>
      })}</nav>
      <div className="who"><UserRound size={16}/><span>{username}</span><button onClick={logout}>Sign out</button></div>
    </header>

    <main className="page">
      <ol className="journey">{STEPS.map((s, i) => {
        const state = done[s.id] ? 'done' : s.id === current?.id ? 'current' : 'locked'
        return <li key={s.id} data-state={state} onClick={() => setRole(s.role)}>
          <span className="jDot">{state === 'done' ? <Check size={14}/> : i + 1}</span>
          <span className="jText"><small>{ROLES.find(r => r.id === s.role)!.label}</small>{s.title}</span>
        </li>
      })}</ol>

      <p className="demoNote">Demo mode: one account plays all three roles. The page switches to whoever needs to act next; you can click any tab to look around.</p>

      <section className="roleIntro"><roleInfo.icon size={26}/><div><h1>{roleInfo.label}</h1><p>{roleInfo.who}</p></div></section>

      {roleSteps.map(s => {
        const n = STEPS.indexOf(s) + 1
        const result = done[s.id]
        const state = result ? 'done' : s.id === current?.id ? 'current' : 'locked'
        const blocker = current && STEPS.indexOf(current)
        return <article key={s.id} className="step" data-state={state}>
          <div className="stepHead">
            <span className="stepBadge">{state === 'done' ? <Check size={16}/> : state === 'locked' ? <Lock size={14}/> : n}</span>
            <div><small>Step {n}{state === 'done' ? ' · done' : state === 'current' ? ' · your turn' : ''}</small><h2>{s.title}</h2></div>
          </div>
          {state === 'done' && <div className="stepSummary">
            <p>{summary(s.id, result!)}</p>
            {s.id === 'decrypt' && <button className="secondary" onClick={download}><Download size={15}/> Download your watermarked copy</button>}
          </div>}
          {state === 'current' && <div className="stepBody">
            <p className="plain">{s.plain}</p>
            {controls(s.id)}
            {error && <div className="error">{error}</div>}
          </div>}
          {state === 'locked' && current && <p className="waiting">Waiting for step {blocker! + 1}: {current.title} ({ROLES.find(r => r.id === current.role)!.label})</p>}
          {state !== 'locked' && <details className="crypto"><summary>Show crypto details</summary><p>{s.crypto}</p>
            {result && <dl className="rows">{Object.entries(result).map(([k, v]) => <div key={k}><dt>{k.replace(/_/g, ' ')}</dt><dd title={typeof v === 'string' ? v : JSON.stringify(v)}>{short(v)}</dd></div>)}</dl>}
          </details>}
        </article>
      })}

      {current && current.role !== role && roleSteps.every(s => done[s.id]) &&
        <button className="nextRole" onClick={() => setRole(current.role)}>Next: step {STEPS.indexOf(current) + 1}, {current.title}, as {ROLES.find(r => r.id === current.role)!.label} <ArrowRight size={16}/></button>}

      {!current && <div className="finish"><ShieldCheck size={22}/><div><b>All five steps complete.</b> The leaked copy was traced to the recipient who opened it, backed by a signed record.</div><button className="secondary" onClick={restart}>Run the demo again</button></div>}
    </main>
  </div>
}

function Auth({ mode, setMode, username, setUsername, password, setPassword, submit, busy, message }: any) {
  return <div className="authPage"><div className="authGlow"/><div className="authCard"><div className="brand center"><div className="brandMark"><ShieldCheck size={24}/></div><div><strong>CRYPTA</strong><span>Cryptographic Attribution</span></div></div><p className="eyebrow">SIH 2026 · SECURE ACCESS</p><h1>{mode === 'login' ? 'Enter the secure console' : 'Create recipient access'}</h1><p className="sub">Post-quantum protected document provenance.</p><div className="form"><input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username"/><input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" onKeyDown={e => e.key === 'Enter' && submit()}/><button onClick={submit} disabled={busy}>{busy ? 'Please wait…' : mode === 'login' ? 'Sign in securely' : 'Create account'} <ArrowRight size={17}/></button></div>{message && <div className="notice">{message}</div>}<button className="link" onClick={() => setMode(mode === 'login' ? 'register' : 'login')}>{mode === 'login' ? 'Need a recipient account? Register' : 'Already registered? Sign in'}</button><div className="authFoot"><span><LockKeyhole size={14}/> JWT protected</span><span><KeyRound size={14}/> ML-KEM-768</span><span><ShieldCheck size={14}/> ML-DSA-65</span></div></div></div>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
