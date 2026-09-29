import React, { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { ArrowRight, Check, Download, FileText, Inbox, Lock, Search, Send, UserRound } from 'lucide-react'
import '@fontsource/dm-sans/400.css'
import '@fontsource/dm-sans/500.css'
import '@fontsource/dm-sans/600.css'
import '@fontsource/dm-sans/700.css'
import '@fontsource/space-grotesk/500.css'
import '@fontsource/space-grotesk/600.css'
import '@fontsource/space-grotesk/700.css'
import './styles.css'
import logo from './assets/mudra-logo.png'

type InboxItem = { document_id: string; filename: string; document_hash: string; sender: string; created_at: string }
type Recipient = { id: string; username: string }
type Activity = { recipient?: string; event: string; at: string }
type Layer = { layer: number; name: string; found: boolean; code: string | null; confidence: number; matched?: boolean }
type Result = Record<string, any>
type Role = 'sender' | 'recipient' | 'investigator'
type StepId = 'keys' | 'encrypt' | 'decrypt' | 'trace'

// Desktop app: the backend serves this UI, so the API is on the same origin.
// Dev server: the backend runs on port 8000 of the same host.
const API = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? `http://${location.hostname}:8000` : location.origin)

const ACRONYM = [['M', 'ulti-recipient'], ['U', 'ndeniable'], ['D', 'ecryption'], ['R', 'ecord &'], ['A', 'ttribution']]

const ROLES: { id: Role; label: string; icon: any }[] = [
  { id: 'sender', label: 'Sender', icon: Send },
  { id: 'recipient', label: 'Recipient', icon: Inbox },
  { id: 'investigator', label: 'Investigator', icon: Search },
]

const STEPS: { id: StepId; role: Role; title: string; hint: string; crypto: string }[] = [
  { id: 'keys', role: 'recipient', title: 'Keys', hint: 'Post-quantum keys that only you hold.',
    crypto: 'ML-KEM-768 (FIPS 203) key pair for receiving and ML-DSA-65 (FIPS 204) key pair for signing. Private keys are stored AES-256-GCM encrypted.' },
  { id: 'encrypt', role: 'sender', title: 'Encrypt & send', hint: 'Encrypted once, sealed separately for each recipient.',
    crypto: 'One AES-256-GCM encryption of the file, bound to the document ID. One ML-KEM-768 envelope per recipient: fresh encapsulation, HKDF-SHA256 bound to document and recipient, wrapping the document key.' },
  { id: 'decrypt', role: 'recipient', title: 'Open & sign', hint: 'Your key signs the record before the copy opens. Your copy is marked as yours alone.',
    crypto: 'Your ML-DSA-65 key signs the access record (document, hash, session, watermark ID, nonce, time) before any plaintext is released. Then your envelope is opened, the file is decrypted and hash-checked, and a copy unique to this opening is made: word-spacing marks, zero-width text marks and an FFT-synchronised image watermark.' },
  { id: 'trace', role: 'investigator', title: 'Trace leak', hint: 'A PDF, screenshot, photo or pasted text is enough.',
    crypto: 'Each watermark layer is read independently from the leaked file, screenshot, photo or pasted text and matched to the decryption session and its signed record.' },
]

async function api(path: string, options: RequestInit = {}, token?: string) {
  const headers = new Headers(options.headers)
  if (!(options.body instanceof FormData) && !(options.body instanceof URLSearchParams)) headers.set('Content-Type', 'application/json')
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const response = await fetch(`${API}${path}`, { ...options, headers })
  const data = await response.json().catch(() => ({}))
  if (response.status === 401 && token) {
    localStorage.removeItem('sih_token'); localStorage.setItem('sih_notice', 'Your session expired. Please sign in again.'); location.reload()
  }
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`)
  return data
}

async function blob(path: string, token: string) {
  const response = await fetch(`${API}${path}`, { headers: { Authorization: `Bearer ${token}` } })
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).detail || 'Could not load the file.')
  return response.blob()
}

const short = (v: unknown) => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s.length > 48 ? `${s.slice(0, 24)}…${s.slice(-12)}` : s }
const time = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })

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
  const [pasted, setPasted] = useState('')
  const [inbox, setInbox] = useState<InboxItem[]>([])
  const [recipients, setRecipients] = useState<Recipient[]>([])
  const [chosen, setChosen] = useState<string[]>([])
  const [selectedDocument, setSelectedDocument] = useState('')
  const [pages, setPages] = useState<string[]>([])
  const [previewText, setPreviewText] = useState<string | null>(null)
  const [activity, setActivity] = useState<Activity[]>([])

  const current = STEPS.find(s => !done[s.id])

  useEffect(() => { localStorage.removeItem('sih_notice') }, [])
  useEffect(() => { if (token) { refreshInbox(); refreshRecipients() } }, [token])
  // Sending to yourself is the default, so the one-account demo still works.
  useEffect(() => { if (userId) setChosen([userId]) }, [userId])
  useEffect(() => { if (current) setRole(current.role) }, [current?.id])
  // The sender sees, live, who opened and downloaded the document.
  useEffect(() => {
    const id = done.encrypt?.document_id
    if (!id) return
    const load = () => api(`/documents/${id}/activity`, {}, token).then(setActivity).catch(() => {})
    load(); const timer = setInterval(load, 4000)
    return () => clearInterval(timer)
  }, [done.encrypt?.document_id])

  async function refreshInbox() {
    try { setInbox(await api('/documents/inbox', {}, token)) } catch (e) { setError((e as Error).message) }
  }
  async function refreshRecipients() {
    try { setRecipients(await api('/users/recipients', {}, token)) } catch (e) { setError((e as Error).message) }
  }
  const toggleRecipient = (id: string) => setChosen(c => c.includes(id) ? c.filter(x => x !== id) : [...c, id])

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

  function logout() { localStorage.removeItem('sih_token'); setToken(''); restart() }

  async function run(step: StepId, action: () => Promise<Result>) {
    setBusy(true); setError('')
    try { const data = await action(); setDone(d => ({ ...d, [step]: data })) }
    catch (e) { setError((e as Error).message) } finally { setBusy(false) }
  }

  const generateKeys = () => run('keys', async () => {
    const data = await api(`/users/${userId}/pqc-keys`, { method: 'POST' }, token)
    await refreshRecipients()
    return data
  })

  const encrypt = () => run('encrypt', async () => {
    const form = new FormData(); form.append('file', file!); chosen.forEach(id => form.append('recipient_ids', id))
    const data = await api('/documents/upload', { method: 'POST', body: form }, token)
    setSelectedDocument(data.document_id); await refreshInbox()
    return data
  })

  // Opening shows the watermarked copy straight away; downloading is a separate choice.
  const decrypt = () => run('decrypt', async () => {
    const data = await api(`/decryption/${selectedDocument}/${userId}`, { method: 'POST' }, token)
    if (data.preview === 'text') setPreviewText((await api(`/decryption/${data.session_id}/text`, {}, token)).text)
    const urls: string[] = []
    for (let n = 0; n < data.pages; n++) urls.push(URL.createObjectURL(await blob(`/decryption/${data.session_id}/page/${n}`, token)))
    setPages(urls)
    return data
  })

  const trace = () => run('trace', () => {
    if (leak) { const form = new FormData(); form.append('file', leak); return api('/forensics/extract', { method: 'POST', body: form }, token) }
    const form = new FormData(); form.append('text', pasted)
    return api('/forensics/text', { method: 'POST', body: form }, token)
  })

  async function download() {
    try {
      const data = await blob(`/decryption/file/${done.decrypt!.session_id}`, token)
      const link = document.createElement('a'); link.href = URL.createObjectURL(data); link.download = done.decrypt!.filename; link.click()
    } catch (e) { setError((e as Error).message) }
  }

  function restart() {
    pages.forEach(URL.revokeObjectURL)
    setDone({}); setFile(null); setLeak(null); setPasted(''); setError(''); setPages([]); setPreviewText(null); setActivity([]); setChosen(userId ? [userId] : [])
  }

  if (!token) return <Auth mode={mode} setMode={setMode} username={username} setUsername={setUsername} password={password} setPassword={setPassword} submit={submitAuth} busy={busy} message={notice} />

  const nameOf = (id: string) => id === userId ? `${username} (you)` : recipients.find(r => r.id === id)?.username || id

  function controls(id: StepId) {
    if (id === 'keys') return <button className="primary" onClick={generateKeys} disabled={busy}>{busy ? 'Generating…' : 'Generate keys'} <ArrowRight size={16}/></button>
    if (id === 'encrypt') return <>
      <label className="drop"><FileText size={20}/><span>{file ? file.name : 'Choose a file'}</span><input type="file" onChange={e => setFile(e.target.files?.[0] || null)}/></label>
      <div className="chips">{recipients.map(r => <button key={r.id} className="chip" data-on={chosen.includes(r.id)} onClick={() => toggleRecipient(r.id)}>
        {chosen.includes(r.id) && <Check size={13}/>}{r.username}{r.id === userId ? ' (you)' : ''}</button>)}</div>
      <button className="primary" onClick={encrypt} disabled={busy || !file || !chosen.length}>{busy ? 'Encrypting…' : `Encrypt for ${chosen.length}`} <ArrowRight size={16}/></button>
    </>
    if (id === 'decrypt') return <>
      <select value={selectedDocument} onChange={e => setSelectedDocument(e.target.value)}><option value="">Inbox</option>{inbox.map(d => <option key={d.document_id} value={d.document_id}>{d.filename} · {d.sender}</option>)}</select>
      <button className="primary" onClick={decrypt} disabled={busy || !selectedDocument}>{busy ? 'Signing & opening…' : 'Sign & open'} <ArrowRight size={16}/></button>
    </>
    return <>
      <label className="drop"><Search size={20}/><span>{leak ? leak.name : 'Leaked PDF, screenshot or photo'}</span><input type="file" accept="application/pdf,image/png,image/jpeg,text/plain" onChange={e => { setLeak(e.target.files?.[0] || null); setPasted('') }}/></label>
      <textarea value={pasted} onChange={e => { setPasted(e.target.value); setLeak(null) }} placeholder="…or paste leaked text"/>
      <button className="primary" onClick={trace} disabled={busy || (!leak && !pasted.trim())}>{busy ? 'Analysing…' : 'Trace'} <ArrowRight size={16}/></button>
    </>
  }

  function summary(id: StepId, r: Result) {
    if (id === 'keys') return <>ML-KEM-768 · ML-DSA-65</>
    if (id === 'encrypt') return <><b>{r.filename}</b> · {r.envelopes_created} envelope{r.envelopes_created === 1 ? '' : 's'}</>
    if (id === 'decrypt') return <><b>{r.filename}</b> · signed ML-DSA-65 · <code>{r.watermark_id}</code></>
    return r.matched ? <><b>{nameOf(r.recipient_id)}</b> · <code>{r.watermark_id}</code></> : <>No match</>
  }

  function detail(id: StepId, r: Result) {
    if (id === 'encrypt') return <Feed items={activity}/>
    if (id === 'decrypt') return <Preview pages={pages} text={previewText} watermark={r.watermark_id} onDownload={download}/>
    if (id === 'trace') return <TraceResult result={r} nameOf={nameOf}/>
    return null
  }

  const roleSteps = STEPS.filter(s => s.role === role)
  const progress = STEPS.filter(s => done[s.id]).length / STEPS.length

  return <div className="app">
    <header className="topbar">
      <div className="brand"><img src={logo} alt=""/><strong>MUDRA</strong></div>
      <nav className="roleTabs">{ROLES.map(r => {
        const complete = STEPS.filter(s => s.role === r.id).every(s => done[s.id])
        return <button key={r.id} className="roleTab" data-selected={role === r.id} onClick={() => setRole(r.id)}>
          <r.icon size={15}/>{r.label}{complete ? <span className="tabDone"><Check size={11}/></span> : current?.role === r.id ? <span className="tabNow"/> : null}
        </button>
      })}</nav>
      <div className="who"><UserRound size={15}/><span>{username}</span><button onClick={logout}>Sign out</button></div>
    </header>

    <main className="page">
      <p className="acronymLine">{ACRONYM.map(([letter, rest], i) => <span key={letter} style={{ animationDelay: `${i * 90}ms` }}><b>{letter}</b>{rest}</span>)}</p>
      <ol className="journey" style={{ '--progress': progress } as React.CSSProperties}>{STEPS.map((s, i) => {
        const state = done[s.id] ? 'done' : s.id === current?.id ? 'current' : 'locked'
        return <li key={s.id} data-state={state} onClick={() => setRole(s.role)}>
          <span className="jDot">{state === 'done' ? <Check size={13}/> : i + 1}</span><span className="jText">{s.title}</span>
        </li>
      })}</ol>

      <section className="stepList" key={role}>{roleSteps.map((s, index) => {
        const result = done[s.id]
        const state = result ? 'done' : s.id === current?.id ? 'current' : 'locked'
        return <article key={s.id} className="step" data-state={state} style={{ animationDelay: `${index * 70}ms` }}>
          <div className="stepHead">
            <span className="stepBadge">{state === 'done' ? <Check size={15}/> : state === 'locked' ? <Lock size={13}/> : STEPS.indexOf(s) + 1}</span>
            <h2>{s.title}</h2>
            {state === 'done' && <p className="stepSummary">{summary(s.id, result!)}</p>}
          </div>
          {state !== 'done' && <p className="hint">{s.hint}</p>}
          {state === 'current' && <div className="stepBody">{controls(s.id)}{error && <div className="error">{error}</div>}</div>}
          {state === 'done' && detail(s.id, result!)}
          {state !== 'locked' && <details className="crypto"><summary>Details</summary><p>{s.crypto}</p>
            {result && <dl className="rows">{Object.entries(result).filter(([, v]) => typeof v !== 'object').map(([k, v]) => <div key={k}><dt>{k.replace(/_/g, ' ')}</dt><dd title={String(v)}>{short(v)}</dd></div>)}</dl>}
          </details>}
        </article>
      })}</section>

      {role === 'investigator' && <LedgerCheck token={token}/>}

      {!current && <div className="finish"><Check size={18}/><span>Traced to <b>{nameOf(done.trace!.recipient_id)}</b></span><button className="secondary" onClick={restart}>Run again</button></div>}
    </main>
  </div>
}

function Preview({ pages, text, watermark, onDownload }: { pages: string[]; text: string | null; watermark: string; onDownload: () => void }) {
  return <div className="preview">
    <div className="previewBar"><span className="wmBadge">Watermarked · {watermark.slice(0, 11)}…</span><button className="secondary" onClick={onDownload}><Download size={15}/> Download</button></div>
    {text !== null && <pre className="previewText">{text}</pre>}
    <div className="pages">{pages.map((src, i) => <img key={src} src={src} alt={`Page ${i + 1}`} style={{ animationDelay: `${i * 90}ms` }}/>)}</div>
    {!pages.length && text === null && <p className="muted">No preview for this file type.</p>}
  </div>
}

function LedgerCheck({ token }: { token: string }) {
  const [state, setState] = useState<Result | null>(null)
  const [busy, setBusy] = useState(false)
  async function check() {
    setBusy(true)
    try { setState(await api('/forensics/ledger/verify', {}, token)) } catch (e) { setState({ error: (e as Error).message }) } finally { setBusy(false) }
  }
  return <div className="ledger" data-state={state ? (state.intact ? 'ok' : 'bad') : 'idle'}>
    <div><b>Tamper-evident ledger</b><small>Hash-chained, ML-DSA-65 signed record of every distribution, opening, preview and download.</small></div>
    {state && !state.error && <span className="ledgerResult">{state.intact ? `Intact · ${state.entries} entries` : `Tampered at entry #${state.broken_at}: ${state.reason}`}</span>}
    {state?.error && <span className="ledgerResult">{state.error}</span>}
    <button className="secondary" onClick={check} disabled={busy}>{busy ? 'Verifying…' : 'Verify ledger'}</button>
  </div>
}

function Feed({ items }: { items: Activity[] }) {
  if (!items.length) return <p className="feedEmpty"><span className="pulse"/>Waiting for recipients</p>
  return <ul className="feed">{items.map((a, i) => <li key={`${a.at}-${a.event}-${i}`}><span className={`event ${a.event}`}>{a.event}</span><b>{a.recipient}</b><time>{time(a.at)}</time></li>)}</ul>
}

function TraceResult({ result, nameOf }: { result: Result; nameOf: (id: string) => string }) {
  const layers: Layer[] = result.layers || []
  return <div className="trace">
    <ul className="layers">{layers.map(l => <li key={l.layer} data-found={l.found}>
      <span className="layerNo">L{l.layer}</span><span className="layerName">{l.name}</span>
      <span className="meter"><span style={{ width: `${Math.round(l.confidence * 100)}%` }}/></span>
      <span className="layerState">{l.found ? (l.matched === false ? 'no session' : 'found') : '—'}</span>
    </li>)}</ul>
    {result.matched && <div className="attribution">
      <div><small>Recipient</small><b>{nameOf(result.recipient_id)}</b></div>
      <div><small>Document</small><b>{result.filename}</b></div>
      <div><small>Signed record</small><b>{result.signed_record ? (result.signature_verified ? 'verified' : 'invalid') : 'not signed'}</b></div>
      <ul className="feed">{(result.activity || []).map((a: Activity, i: number) => <li key={i}><span className={`event ${a.event}`}>{a.event}</span><time>{time(a.at)}</time></li>)}</ul>
    </div>}
  </div>
}

function Auth({ mode, setMode, username, setUsername, password, setPassword, submit, busy, message }: any) {
  return <div className="authPage">
    <div className="ridge" aria-hidden/>
    <div className="authCard">
      <img className="authLogo" src={logo} alt="MUDRA"/>
      <p className="tagline">Every copy knows its owner.</p>
      <p className="subTagline">Post-quantum encryption · per-recipient watermarks · signed access records</p>
      <div className="form">
        <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username"/>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" onKeyDown={e => e.key === 'Enter' && submit()}/>
        <button className="primary" onClick={submit} disabled={busy}>{busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'} <ArrowRight size={16}/></button>
      </div>
      {message && <div className="notice">{message}</div>}
      <button className="link" onClick={() => setMode(mode === 'login' ? 'register' : 'login')}>{mode === 'login' ? 'Create an account' : 'I have an account'}</button>
    </div>
  </div>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
