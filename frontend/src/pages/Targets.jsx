import { useEffect, useState } from 'react'
import { Plus, Trash2, Crosshair, ShieldCheck, Pencil } from 'lucide-react'
import { api } from '../api/client'
import Modal from '../components/Modal'

const EMPTY = {
  name: '', base_url: '', authorization_confirmed: false,
  allow_localhost: false, notes: '',
}

export default function Targets() {
  const [targets, setTargets] = useState([])
  const [modal, setModal] = useState(false)
  const [form, setForm] = useState(EMPTY)
  const [error, setError] = useState('')

  const load = () => api.get('/targets').then(setTargets).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  const submit = async (ev) => {
    ev.preventDefault()
    setError('')
    try {
      await api.post('/targets', form)
      setModal(false)
      setForm(EMPTY)
      load()
    } catch (e) {
      setError(e.message)
    }
  }

  const remove = async (t) => {
    if (!window.confirm(`Delete target "${t.name}" and all its accounts/endpoints/scans?`)) return
    await api.del(`/targets/${t.id}`)
    load()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Crosshair size={24} className="text-indigo-400" /> Targets
          </h1>
          <p className="text-sm text-slate-400">
            Only APIs you own or are explicitly authorised to test.
          </p>
        </div>
        <button className="btn-primary" onClick={() => setModal(true)}>
          <Plus size={16} /> Add Target
        </button>
      </div>

      {error && !modal && <div className="card p-3 text-red-400 text-sm">{error}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {targets.map((t) => (
          <div key={t.id} className="card p-5 space-y-3">
            <div className="flex items-start justify-between">
              <div>
                <div className="font-semibold text-white">{t.name}</div>
                <div className="text-sm font-mono text-indigo-300">{t.base_url}</div>
              </div>
              <button onClick={() => remove(t)} className="btn-danger"><Trash2 size={14} /></button>
            </div>
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                <ShieldCheck size={12} /> Authorization confirmed
              </span>
              {t.allow_localhost && (
                <span className="px-2 py-1 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/30">
                  Local development mode
                </span>
              )}
              <span className="px-2 py-1 rounded bg-navy-700 text-slate-300 border border-navy-600">
                {t.account_count} account(s)
              </span>
              <span className="px-2 py-1 rounded bg-navy-700 text-slate-300 border border-navy-600">
                {t.endpoint_count} endpoint(s)
              </span>
            </div>
            {t.notes && <p className="text-xs text-slate-400">{t.notes}</p>}
          </div>
        ))}
        {targets.length === 0 && (
          <div className="card p-10 text-center text-slate-500 col-span-full">
            No targets configured yet. Add an authorised API target to begin.
          </div>
        )}
      </div>

      <Modal title="Add Authorised Target" open={modal} onClose={() => setModal(false)}>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="label">Target name</label>
            <input className="input" required value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="e.g. My Shop API (staging)" />
          </div>
          <div>
            <label className="label">Base URL</label>
            <input className="input font-mono" required type="url" value={form.base_url}
              onChange={(e) => setForm({ ...form, base_url: e.target.value })}
              placeholder="http://127.0.0.1:8011" />
            <p className="text-xs text-slate-500 mt-1">
              All scan requests are locked to this host. Redirects and other destinations are blocked (SSRF policy).
            </p>
          </div>
          <label className="flex items-start gap-2 text-sm text-slate-300 cursor-pointer">
            <input type="checkbox" className="mt-1 accent-indigo-500" required
              checked={form.authorization_confirmed}
              onChange={(e) => setForm({ ...form, authorization_confirmed: e.target.checked })} />
            <span>
              I confirm I <b>own this API or have explicit written authorisation</b> to security-test it.
            </span>
          </label>
          <label className="flex items-start gap-2 text-sm text-slate-300 cursor-pointer">
            <input type="checkbox" className="mt-1 accent-indigo-500"
              checked={form.allow_localhost}
              onChange={(e) => setForm({ ...form, allow_localhost: e.target.checked })} />
            <span>
              Local development target (allows loopback/private IPs — required for the mock APIs).
            </span>
          </label>
          <div>
            <label className="label">Notes (optional)</label>
            <textarea className="input" rows={2} value={form.notes}
              onChange={(e) => setForm({ ...form, notes: e.target.value })} />
          </div>
          {error && <div className="text-sm text-red-400">{error}</div>}
          <button className="btn-primary w-full justify-center" type="submit">
            <ShieldCheck size={16} /> Register authorised target
          </button>
        </form>
      </Modal>
    </div>
  )
}
