import React, { useState } from 'react'
import { api } from '../api.js'

// Queue a new scan. Scope is optional (comma-separated CIDRs/hosts); blank lets
// the backend default to localhost + private ranges.
export default function ScanForm({ onCreated }) {
  const [target, setTarget] = useState('')
  const [scope, setScope] = useState('')
  const [mode, setMode] = useState('offline')
  const [provider, setProvider] = useState('anthropic')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const body = { target: target.trim(), mode }
      const scopeList = scope.split(',').map((s) => s.trim()).filter(Boolean)
      if (scopeList.length) body.scope = scopeList
      if (mode === 'llm') body.provider = provider
      const res = await api.createScan(body)
      onCreated(res.id)
      setTarget('')
      setScope('')
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message || 'failed to queue scan')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="form" onSubmit={submit}>
      <label>Target (host / IP / domain)</label>
      <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="www.example.com" />

      <label>Scope (optional, comma-separated)</label>
      <input value={scope} onChange={(e) => setScope(e.target.value)} placeholder="192.168.56.0/24" />

      <label>Mode</label>
      <select value={mode} onChange={(e) => setMode(e.target.value)}>
        <option value="offline">offline (no LLM, rule-based)</option>
        <option value="llm">llm (autonomous agent)</option>
      </select>

      {mode === 'llm' && (
        <>
          <label>Provider</label>
          <select value={provider} onChange={(e) => setProvider(e.target.value)}>
            <option value="anthropic">anthropic</option>
            <option value="openai">openai</option>
            <option value="openrouter">openrouter</option>
            <option value="gemini">gemini</option>
          </select>
        </>
      )}

      {err && <p style={{ color: 'var(--crit)', fontSize: '0.8rem' }}>{err}</p>}
      <button className="btn" disabled={busy || !target.trim()}>
        {busy ? 'Queuing…' : 'Start scan'}
      </button>
    </form>
  )
}
