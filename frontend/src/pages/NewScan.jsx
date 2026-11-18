import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ScanSearch, AlertTriangle, Loader2, CheckCircle2 } from 'lucide-react'
import { api } from '../api/client'
import { ClassBadge } from '../components/Badges'

export default function NewScan() {
  const [targets, setTargets] = useState([])
  const [targetId, setTargetId] = useState('')
  const [detail, setDetail] = useState(null) // {accounts, endpoints}
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [scan, setScan] = useState(null)
  const [polling, setPolling] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    api.get('/targets').then((ts) => {
      setTargets(ts)
      if (ts.length) setTargetId(String(ts[0].id))
    }).catch((e) => setError(e.message))
  }, [])

  useEffect(() => {
    if (!targetId) return
    setDetail(null)
    Promise.all([
      api.get(`/targets/${targetId}/accounts`),
      api.get(`/targets/${targetId}/endpoints`),
    ]).then(([accounts, endpoints]) => setDetail({ accounts, endpoints }))
      .catch((e) => setError(e.message))
  }, [targetId])

  // Poll while scan runs
  useEffect(() => {
    if (!scan || !['pending', 'running'].includes(scan.status)) return
    setPolling(true)
    const t = setInterval(async () => {
      try {
        const s = await api.get(`/scans/${scan.id}`)
        setScan(s)
        if (['completed', 'failed'].includes(s.status)) clearInterval(t)
      } catch { /* transient */ }
    }, 700)
    return () => clearInterval(t)
  }, [scan?.id])

  const start = async () => {
    setError('')
    setBusy(true)
    try {
      const s = await api.post('/scans', { target_id: Number(targetId), name: name || null })
      setScan(s)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const t = targets.find((x) => String(x.id) === targetId)
  const ready = detail && detail.accounts.length >= 2 && detail.endpoints.length >= 1

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <ScanSearch size={24} className="text-indigo-400" /> New BOLA/IDOR Scan
        </h1>
        <p className="text-sm text-slate-400">
          Each endpoint is tested in both directions: owner baseline, then cross-account
          access, with evidence-based response comparison. Only GET requests, only the approved host.
        </p>
      </div>

      {scan ? (
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-white text-lg">Scan #{scan.id} — {scan.name}</h2>
            <span className={`text-sm ${
              scan.status === 'completed' ? 'text-emerald-400' :
              scan.status === 'failed' ? 'text-red-400' : 'text-indigo-300'}`}>
              {scan.status === 'completed' && <CheckCircle2 size={16} className="inline mr-1" />}
              {scan.status === 'failed' && <AlertTriangle size={16} className="inline mr-1" />}
              {['pending', 'running'].includes(scan.status) && <Loader2 size={16} className="inline mr-1 animate-spin" />}
              {scan.status}
            </span>
          </div>
          {scan.error_message && <div className="text-sm text-red-400">{scan.error_message}</div>}
          {scan.status === 'completed' ? (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-center">
                {[
                  ['Confirmed', scan.confirmed_count, 'text-red-400'],
                  ['Potential', scan.potential_count, 'text-orange-400'],
                  ['Blocked', scan.blocked_count, 'text-emerald-400'],
                  ['Authorized', scan.authorized_count, 'text-sky-400'],
                  ['Inconclusive', scan.inconclusive_count, 'text-slate-300'],
                ].map(([l, v, c]) => (
                  <div key={l} className="bg-navy-900 rounded-lg p-3 border border-navy-600/50">
                    <div className={`text-2xl font-bold ${c}`}>{v}</div>
                    <div className="text-xs text-slate-400">{l}</div>
                  </div>
                ))}
              </div>
              {scan.results?.length > 0 && (
                <div className="text-sm text-slate-300 space-y-1 max-h-64 overflow-y-auto">
                  {scan.results.map((r) => (
                    <div key={r.id} className="flex items-center justify-between bg-navy-900/60 rounded px-3 py-2">
                      <span className="font-mono text-xs">{r.direction} {r.method} {r.path}</span>
                      <ClassBadge value={r.classification} />
                    </div>
                  ))}
                </div>
              )}
              <div className="flex gap-3 pt-2">
                <button className="btn-primary" onClick={() => navigate(`/history?scan=${scan.id}`)}>View full results</button>
                <button className="btn-ghost" onClick={() => navigate('/findings')}>Open findings</button>
              </div>
            </>
          ) : (
            <div className="text-sm text-slate-400 flex items-center gap-2">
              <Loader2 className="animate-spin text-indigo-400" size={16} />
              Engine is issuing cross-account requests… {polling && ''}
            </div>
          )}
        </div>
      ) : (
        <div className="card p-6 space-y-5">
          <div>
            <label className="label">Target</label>
            <select className="input" value={targetId} onChange={(e) => setTargetId(e.target.value)}>
              {targets.length === 0 && <option value="">No targets — authorise one first</option>}
              {targets.map((x) => <option key={x.id} value={x.id}>{x.name} — {x.base_url}</option>)}
            </select>
          </div>
          <div>
            <label className="label">Scan name (optional)</label>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)}
              placeholder={`BOLA assessment of ${t?.name || 'target'}`} />
          </div>

          {detail && (
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div className="bg-navy-900 rounded-lg p-4 border border-navy-600/50">
                <div className="label">Test accounts</div>
                {detail.accounts.map((a) => (
                  <div key={a.id} className="flex justify-between py-0.5">
                    <span className="text-slate-200">{a.name}</span>
                    <span className="font-mono text-xs text-slate-500">{a.token_masked}</span>
                  </div>
                ))}
                {detail.accounts.length < 2 && (
                  <div className="text-yellow-400 text-xs mt-2">⚠ needs ≥ 2 accounts</div>
                )}
              </div>
              <div className="bg-navy-900 rounded-lg p-4 border border-navy-600/50">
                <div className="label">Endpoints in scope</div>
                {detail.endpoints.filter((e) => e.enabled).map((e) => (
                  <div key={e.id} className="py-0.5">
                    <span className="text-slate-200">{e.name}</span>
                    <div className="font-mono text-xs text-indigo-300">{e.method} {e.path_template}</div>
                  </div>
                ))}
                {detail.endpoints.length === 0 && (
                  <div className="text-yellow-400 text-xs mt-2">⚠ configure at least one endpoint</div>
                )}
              </div>
            </div>
          )}

          {error && <div className="text-sm text-red-400">{error}</div>}

          <button className="btn-primary w-full justify-center" onClick={start}
            disabled={!ready || busy || !t?.authorization_confirmed}>
            {busy ? <Loader2 size={16} className="animate-spin" /> : <ScanSearch size={16} />}
            Start authorised scan
          </button>
          {!ready && detail && (
            <p className="text-xs text-slate-500 text-center">
              Scans require at least two accounts and one endpoint on the selected target.
            </p>
          )}
        </div>
      )}
    </div>
  )
}
