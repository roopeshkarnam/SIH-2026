import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Activity, ArrowRight, CheckCircle2, FileLock2, Fingerprint, KeyRound, LockKeyhole, Search, ShieldCheck, Upload, UserRound } from 'lucide-react'
import './styles.css'

type DocumentItem = { document_id: string; filename: string; document_hash: string; encrypted: boolean; created_at: string }
type Result = Record<string, unknown> | null

const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

async function api(path: string, options: RequestInit = {}, token?: string) {
  const headers = new Headers(options.headers)
  if (!(options.body instanceof FormData) && !(options.body instanceof URLSearchParams)) headers.set('Content-Type', 'application/json')
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const response = await fetch(`${API}${path}`, { ...options, headers })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`)
  return data
}

function App() {
  const [token, setToken] = useState(localStorage.getItem('sih_token') || '')
  const [userId, setUserId] = useState(localStorage.getItem('sih_user_id') || '')
  const [username, setUsername] = useState(localStorage.getItem('sih_username') || '')
  const [password, setPassword] = useState('')
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [file, setFile] = useState<File | null>(null)
  const [documents, setDocuments] = useState<DocumentItem[]>([])
  const [selectedDocument, setSelectedDocument] = useState('')
  const [watermark, setWatermark] = useState('')
  const [result, setResult] = useState<Result>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  const loggedIn = Boolean(token)
  const status = useMemo(() => [
    ['AES-256-GCM', true], ['ML-KEM-768', true], ['ML-DSA-65', true], ['Watermark MVP', true], ['Fabric Ledger', false],
  ], [])

  useEffect(() => { if (token) refreshDocuments() }, [token])

  async function refreshDocuments() {
    try { setDocuments(await api('/documents/mine', {}, token)) } catch (e) { setMessage((e as Error).message) }
  }

  async function submitAuth() {
    setBusy(true); setMessage('')
    try {
      if (mode === 'register') {
        const data = await api('/auth/register', { method: 'POST', body: JSON.stringify({ username, password }) })
        setUserId(data.user_id); setMode('login'); setMessage('Account created. Sign in to continue.')
      } else {
        const body = new URLSearchParams({ username, password })
        const data = await api('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }, undefined)
        setToken(data.access_token); setUserId(data.user_id); localStorage.setItem('sih_token', data.access_token); localStorage.setItem('sih_user_id', data.user_id); localStorage.setItem('sih_username', data.username)
        setMessage('Secure session established.')
      }
    } catch (e) { setMessage((e as Error).message) } finally { setBusy(false) }
  }

  function logout() { localStorage.clear(); setToken(''); setUserId(''); setDocuments([]); setResult(null) }

  async function generateKeys() {
    setBusy(true); setMessage('Generating ML-KEM-768 and ML-DSA-65 keys…')
    try { setResult(await api(`/users/${userId}/pqc-keys`, { method: 'POST' }, token)); setMessage('PQC key material initialized in the encrypted local keystore.') }
    catch (e) { setMessage((e as Error).message) } finally { setBusy(false) }
  }

  async function upload() {
    if (!file) return setMessage('Choose a document first.')
    setBusy(true); setMessage('Encrypting document…')
    try {
      const form = new FormData(); form.append('file', file)
      const data = await api(`/documents/upload?recipient_id=${encodeURIComponent(userId)}`, { method: 'POST', body: form }, token)
      setSelectedDocument(data.document_id); setResult(data); setMessage('Document encrypted and stored.')
      await refreshDocuments()
    } catch (e) { setMessage((e as Error).message) } finally { setBusy(false) }
  }

  async function decrypt() {
    if (!selectedDocument) return setMessage('Select a document first.')
    setBusy(true); setMessage('Decrypting and creating a session fingerprint…')
    try {
      const data = await api(`/decryption/${selectedDocument}/${userId}`, { method: 'POST' }, token)
      setWatermark(data.watermark_id); setResult(data); setMessage('Decryption session created.')
    } catch (e) { setMessage((e as Error).message) } finally { setBusy(false) }
  }

  async function provenance() {
    if (!result || typeof result.session_id !== 'string') return setMessage('Decrypt a document first.')
    setBusy(true); setMessage('Signing provenance with ML-DSA-65…')
    try { setResult(await api(`/provenance/create/${result.session_id}`, { method: 'POST' }, token)); setMessage('Signed provenance record created.') }
    catch (e) { setMessage((e as Error).message) } finally { setBusy(false) }
  }

  async function lookup() {
    if (!watermark) return setMessage('No watermark ID available yet.')
    setBusy(true); setMessage('Looking up provenance…')
    try { setResult(await api(`/forensics/lookup/${encodeURIComponent(watermark)}`, {}, token)); setMessage('Forensic lookup completed.') }
    catch (e) { setMessage((e as Error).message) } finally { setBusy(false) }
  }

  if (!loggedIn) return <Auth mode={mode} setMode={setMode} username={username} setUsername={setUsername} password={password} setPassword={setPassword} submit={submitAuth} busy={busy} message={message} />

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><div className="brandMark"><ShieldCheck size={22}/></div><div><strong>CRYPTA</strong><span>Attribution Console</span></div></div>
      <div className="sideSection"><span>SECURITY STACK</span>{status.map(([name, ok]) => <div className="stackItem" key={name as string}><span className="dot" data-ok={ok}/>{name}</div>)}</div>
      <div className="sideBottom"><div className="identity"><UserRound size={17}/><div><b>{username}</b><small>Recipient · {userId.slice(0, 10)}…</small></div></div><button className="ghost" onClick={logout}>Sign out</button></div>
    </aside>
    <main className="main">
      <header className="top"><div><p className="eyebrow">SIH 2026 · CYBERSECURITY</p><h1>Cryptographic Attribution</h1><p className="sub">Secure distribution, session-level provenance and forensic lookup.</p></div><div className="live"><Activity size={16}/> SYSTEM ONLINE</div></header>
      {message && <div className="notice"><CheckCircle2 size={17}/>{message}</div>}
      <section className="heroGrid">
        <div className="heroCard"><div className="heroIcon"><LockKeyhole size={28}/></div><div><span className="label">PROTECTED WORKFLOW</span><h2>Identity → Decryption → Attribution</h2><p>Every decryption gets a unique session identifier and cryptographic provenance record.</p></div></div>
        <div className="metric"><span>POST-QUANTUM</span><b>ML-KEM-768</b><small>Key establishment</small></div>
        <div className="metric"><span>PROVENANCE</span><b>ML-DSA-65</b><small>Digital signature</small></div>
      </section>
      <section className="grid">
        <article className="card"><div className="cardHead"><div><span className="step">01</span><h3>Initialize recipient keys</h3></div><KeyRound size={20}/></div><p>Generate the recipient's post-quantum KEM and signature keys. Private material is encrypted locally.</p><button onClick={generateKeys} disabled={busy}>Generate PQC keys <ArrowRight size={16}/></button></article>
        <article className="card"><div className="cardHead"><div><span className="step">02</span><h3>Encrypt & distribute</h3></div><FileLock2 size={20}/></div><label className="drop"><Upload size={22}/><span>{file ? file.name : 'Choose a PDF or document'}</span><input type="file" onChange={e => setFile(e.target.files?.[0] || null)}/></label><button onClick={upload} disabled={busy || !file}>Encrypt document <ArrowRight size={16}/></button></article>
        <article className="card"><div className="cardHead"><div><span className="step">03</span><h3>Create decryption session</h3></div><Fingerprint size={20}/></div><select value={selectedDocument} onChange={e => setSelectedDocument(e.target.value)}><option value="">Select encrypted document</option>{documents.map(d => <option key={d.document_id} value={d.document_id}>{d.filename}</option>)}</select><button onClick={decrypt} disabled={busy || !selectedDocument}>Decrypt & fingerprint <ArrowRight size={16}/></button></article>
        <article className="card"><div className="cardHead"><div><span className="step">04</span><h3>Sign provenance</h3></div><ShieldCheck size={20}/></div><p>Bind the document, session and watermark identifier into a signed provenance record.</p><button onClick={provenance} disabled={busy || !result?.session_id}>Create signed record <ArrowRight size={16}/></button></article>
        <article className="card wide"><div className="cardHead"><div><span className="step">05</span><h3>Forensic lookup</h3></div><Search size={20}/></div><div className="lookup"><input value={watermark} onChange={e => setWatermark(e.target.value)} placeholder="WM-… watermark identifier"/><button onClick={lookup} disabled={busy || !watermark}>Lookup <ArrowRight size={16}/></button></div><small className="muted">MVP lookup resolves the stored watermark identifier. Pixel-level PDF extraction is the next watermark module.</small></article>
      </section>
      <section className="output"><div className="outputHead"><span>EVENT OUTPUT</span><span>{busy ? 'PROCESSING…' : 'READY'}</span></div><pre>{result ? JSON.stringify(result, null, 2) : 'Run a workflow step to inspect the security event output.'}</pre></section>
    </main>
  </div>
}

function Auth({ mode, setMode, username, setUsername, password, setPassword, submit, busy, message }: any) {
  return <div className="authPage"><div className="authGlow"/><div className="authCard"><div className="brand center"><div className="brandMark"><ShieldCheck size={24}/></div><div><strong>CRYPTA</strong><span>Cryptographic Attribution</span></div></div><p className="eyebrow">SIH 2026 · SECURE ACCESS</p><h1>{mode === 'login' ? 'Enter the secure console' : 'Create recipient access'}</h1><p className="sub">Post-quantum protected document provenance.</p><div className="form"><input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username"/><input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Password"/><button onClick={submit} disabled={busy}>{busy ? 'Please wait…' : mode === 'login' ? 'Sign in securely' : 'Create account'} <ArrowRight size={17}/></button></div>{message && <div className="notice">{message}</div>}<button className="link" onClick={() => setMode(mode === 'login' ? 'register' : 'login')}>{mode === 'login' ? 'Need a recipient account? Register' : 'Already registered? Sign in'}</button><div className="authFoot"><span><LockKeyhole size={14}/> JWT protected</span><span><KeyRound size={14}/> ML-KEM-768</span><span><ShieldCheck size={14}/> ML-DSA-65</span></div></div></div>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
