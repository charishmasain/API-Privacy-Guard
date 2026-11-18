import { useEffect, useState } from 'react'
import { Plus, Trash2, Users, KeyRound, Pencil } from 'lucide-react'
import { api } from '../api/client'
import Modal from '../components/Modal'

const EMPTY = { name: '', token: '', description: '', home_resource_id: '' }

export default function Accounts() {
  const [targets, setTargets] = useState([])
  const [targetId, setTargetId] = useState('')
  const [accounts, setAccounts] = useState([])
  const [modal, setModal] = useState(false)
  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState(EMPTY)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/targets').then((ts) => {
      setTargets(ts)
      if (ts.length && !targetId) setTargetId(String(ts[0].id))
    }).catch((e) => setError(e.message))
  }, [])

  const load = (id) => {
    if (!id) return setAccounts([])
    return api.get(`/targets/${id}/accounts`).then(setAccounts).catch((e) => setError(e.message))
  }

  useEffect(() => { load(targetId) }, [targetId])

  const openAdd = () => { setEditing(null); setForm(EMPTY); setError(''); setModal(true) }
  const openEdit = (a) => {
    setEditing(a)
    setForm({ name: a.name, token: '', description: a.description || '', home_resource_id: a.home_resource_id || '' })
    setModal(true)
  }

  const submit = async (ev) => {
    ev.preventDefault()
    setError('')
    const payload = {
      name: form.name,
      description: form.description || null,
      home_resource_id: form.home_resource_id || null,
    }
    if (form.token) payload.token = form.token
    try {
      if (editing) {
        await api.put(`/accounts/${editing.id}`, payload)
      } else {
        if (!payload.token) throw new Error('Bearer token is required')
        await api.post(`/targets/${targetId}/accounts`, payload)
      }
      setModal(false)
      load(targetId)
    } catch (e) {
      setError(e.message)
    }
  }

  const remove = async (a) => {
    if (!window.confirm(`Remove account "${a.name}"?`)) return
    await api.del(`/accounts/${a.id}`)
    load(targetId)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Users size={24} className="text-indigo-400" /> Test Accounts
          </h1>
          <p className="text-sm text-slate-400">
            At least two accounts per target are required for cross-user BOLA testing. Tokens are encrypted at rest and masked in the UI.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select className="input !w-56" value={targetId} onChange={(e) => setTargetId(e.target.value)}>
            {targets.length === 0 && <option value="">No targets — add one first</option>}
            {targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <button className="btn-primary" onClick={openAdd} disabled={!targetId}>
            <Plus size={16} /> Add Account
          </button>
        </div>
      </div>

      <div className="card overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-navy-600/50">
              <th className="table-th">Name</th>
              <th className="table-th">Bearer token</th>
              <th className="table-th">Own resource id</th>
              <th className="table-th">Description</th>
              <th className="table-th text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((a) => (
              <tr key={a.id} className="border-b border-navy-700/40 hover:bg-navy-700/20">
                <td className="table-td font-medium text-white">{a.name}</td>
                <td className="table-td font-mono text-indigo-300 flex items-center gap-2">
                  <KeyRound size={14} className="text-slate-500" /> {a.token_masked}
                </td>
                <td className="table-td font-mono">{a.home_resource_id || '–'}</td>
                <td className="table-td text-slate-400">{a.description || '–'}</td>
                <td className="table-td text-right space-x-2">
                  <button className="btn-ghost !px-2 !py-1" onClick={() => openEdit(a)}><Pencil size={13} /></button>
                  <button className="btn-danger" onClick={() => remove(a)}><Trash2 size={13} /></button>
                </td>
              </tr>
            ))}
            {accounts.length === 0 && (
              <tr><td colSpan={5} className="table-td text-center text-slate-500 py-10">
                {targetId ? 'No accounts for this target yet.' : 'Select a target and add at least two test accounts.'}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
      {accounts.length === 1 && (
        <div className="card p-3 text-yellow-400 text-sm border-yellow-500/40">
          One more account is required before a BOLA scan can run.
        </div>
      )}

      <Modal title={editing ? `Edit account: ${editing.name}` : 'Add Test Account'} open={modal} onClose={() => setModal(false)}>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="label">Account name</label>
            <input className="input" required value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="e.g. alice (must match the API username for evidence checks)" />
          </div>
          <div>
            <label className="label">Bearer token {editing && '(leave blank to keep current)'}</label>
            <input className="input font-mono" type="password" autoComplete="new-password"
              value={form.token} onChange={(e) => setForm({ ...form, token: e.target.value })}
              placeholder="eyJhbGciOi…" />
            <p className="text-xs text-slate-500 mt-1">Encrypted with Fernet before storage; never shown again in full.</p>
          </div>
          <div>
            <label className="label">Resource id owned by this account (optional)</label>
            <input className="input font-mono" value={form.home_resource_id}
              onChange={(e) => setForm({ ...form, home_resource_id: e.target.value })}
              placeholder="e.g. 101 — used for reverse-direction testing" />
          </div>
          <div>
            <label className="label">Description (optional)</label>
            <input className="input" value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </div>
          {error && <div className="text-sm text-red-400">{error}</div>}
          <button className="btn-primary w-full justify-center" type="submit">
            <Plus size={16} /> {editing ? 'Save changes' : 'Add account'}
          </button>
        </form>
      </Modal>
    </div>
  )
}
