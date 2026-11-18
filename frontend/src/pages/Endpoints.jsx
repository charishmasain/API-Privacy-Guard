import { useEffect, useState } from 'react'
import { Plus, Trash2, Route as RouteIcon, Pencil, ToggleLeft, ToggleRight } from 'lucide-react'
import { api } from '../api/client'
import Modal from '../components/Modal'

const EMPTY = {
  name: '', path_template: '', method: 'GET', resource_id: '',
  owner_account_id: '', expected_access: 'owner_only', notes: '',
}

export default function Endpoints() {
  const [targets, setTargets] = useState([])
  const [targetId, setTargetId] = useState('')
  const [endpoints, setEndpoints] = useState([])
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
    if (!id) { setEndpoints([]); setAccounts([]); return }
    api.get(`/targets/${id}/endpoints`).then(setEndpoints).catch((e) => setError(e.message))
    api.get(`/targets/${id}/accounts`).then(setAccounts).catch(() => {})
  }
  useEffect(() => { load(targetId) }, [targetId])

  const openAdd = () => {
    setEditing(null)
    setForm({ ...EMPTY, owner_account_id: accounts[0]?.id || '' })
    setError('')
    setModal(true)
  }
  const openEdit = (ep) => {
    setEditing(ep)
    setForm({
      name: ep.name, path_template: ep.path_template, method: ep.method,
      resource_id: ep.resource_id, owner_account_id: ep.owner_account_id,
      expected_access: ep.expected_access, notes: ep.notes || '',
    })
    setModal(true)
  }

  const submit = async (ev) => {
    ev.preventDefault()
    setError('')
    const payload = {
      ...form,
      owner_account_id: Number(form.owner_account_id),
      notes: form.notes || null,
    }
    try {
      if (editing) {
        await api.put(`/endpoints/${editing.id}`, { ...payload, enabled: editing.enabled })
      } else {
        await api.post(`/targets/${targetId}/endpoints`, payload)
      }
      setModal(false)
      load(targetId)
    } catch (e) {
      setError(e.message)
    }
  }

  const toggle = async (ep) => {
    await api.put(`/endpoints/${ep.id}`, {
      name: ep.name, path_template: ep.path_template, method: ep.method,
      resource_id: ep.resource_id, owner_account_id: ep.owner_account_id,
      expected_access: ep.expected_access, notes: ep.notes,
      enabled: !ep.enabled,
    })
    load(targetId)
  }

  const remove = async (ep) => {
    if (!window.confirm(`Delete endpoint "${ep.name}"?`)) return
    await api.del(`/endpoints/${ep.id}`)
    load(targetId)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <RouteIcon size={24} className="text-indigo-400" /> Endpoint Configuration
          </h1>
          <p className="text-sm text-slate-400">
            Object-level endpoints with resource ids and owners. Read-only (GET) testing only.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select className="input !w-56" value={targetId} onChange={(e) => setTargetId(e.target.value)}>
            {targets.length === 0 && <option value="">No targets — add one first</option>}
            {targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <button className="btn-primary" onClick={openAdd} disabled={!targetId || accounts.length === 0}>
            <Plus size={16} /> Add Endpoint
          </button>
        </div>
      </div>

      <div className="card overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-navy-600/50">
              <th className="table-th">Name</th>
              <th className="table-th">Method</th>
              <th className="table-th">Path template</th>
              <th className="table-th">Resource id</th>
              <th className="table-th">Owner</th>
              <th className="table-th">Expected access</th>
              <th className="table-th">Enabled</th>
              <th className="table-th text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {endpoints.map((ep) => (
              <tr key={ep.id} className="border-b border-navy-700/40 hover:bg-navy-700/20">
                <td className="table-td font-medium text-white">{ep.name}</td>
                <td className="table-td"><span className="px-2 py-0.5 rounded bg-sky-500/15 text-sky-400 border border-sky-500/30 text-xs font-bold">{ep.method}</span></td>
                <td className="table-td font-mono text-indigo-300 text-xs">{ep.path_template}</td>
                <td className="table-td font-mono">{ep.resource_id}</td>
                <td className="table-td">{ep.owner_name}</td>
                <td className="table-td text-slate-400 text-xs">{ep.expected_access === 'owner_only' ? 'Owner only (private)' : 'Public'}</td>
                <td className="table-td">
                  <button onClick={() => toggle(ep)} className="text-slate-300">
                    {ep.enabled ? <ToggleRight size={22} className="text-emerald-400" /> : <ToggleLeft size={22} className="text-slate-500" />}
                  </button>
                </td>
                <td className="table-td text-right space-x-2">
                  <button className="btn-ghost !px-2 !py-1" onClick={() => openEdit(ep)}><Pencil size={13} /></button>
                  <button className="btn-danger" onClick={() => remove(ep)}><Trash2 size={13} /></button>
                </td>
              </tr>
            ))}
            {endpoints.length === 0 && (
              <tr><td colSpan={8} className="table-td text-center text-slate-500 py-10">
                {targetId ? 'No endpoints for this target yet.' : 'Select a target first.'}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal title={editing ? `Edit endpoint: ${editing.name}` : 'Add Endpoint'} open={modal} onClose={() => setModal(false)}>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="label">Endpoint name</label>
            <input className="input" required value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="e.g. Order details by id" />
          </div>
          <div>
            <label className="label">Relative URL with {'{resource_id}'} placeholder</label>
            <input className="input font-mono" required value={form.path_template}
              onChange={(e) => setForm({ ...form, path_template: e.target.value })}
              placeholder="/v1/insecure/profiles/{resource_id}" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">HTTP method (read-only)</label>
              <select className="input" value={form.method} onChange={(e) => setForm({ ...form, method: e.target.value })}>
                <option value="GET">GET</option>
                <option value="HEAD">HEAD</option>
              </select>
            </div>
            <div>
              <label className="label">Expected access behaviour</label>
              <select className="input" value={form.expected_access}
                onChange={(e) => setForm({ ...form, expected_access: e.target.value })}>
                <option value="owner_only">Owner only (private object)</option>
                <option value="public">Public (anyone may read)</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">Resource identifier to test</label>
              <input className="input font-mono" required value={form.resource_id}
                onChange={(e) => setForm({ ...form, resource_id: e.target.value })}
                placeholder="e.g. 101" />
            </div>
            <div>
              <label className="label">Resource owner (account)</label>
              <select className="input" required value={form.owner_account_id}
                onChange={(e) => setForm({ ...form, owner_account_id: e.target.value })}>
                {accounts.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="label">Notes (optional)</label>
            <input className="input" value={form.notes}
              onChange={(e) => setForm({ ...form, notes: e.target.value })} />
          </div>
          {error && <div className="text-sm text-red-400">{error}</div>}
          <button className="btn-primary w-full justify-center" type="submit">
            <Plus size={16} /> {editing ? 'Save changes' : 'Add endpoint'}
          </button>
        </form>
      </Modal>
    </div>
  )
}
