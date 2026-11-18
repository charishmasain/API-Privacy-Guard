import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { History as HistoryIcon, RefreshCw, ShieldCheck, Loader2, FileDown, ArrowLeftRight } from 'lucide-react'
import { api } from '../api/client'
import { ClassBadge, StatusBadge } from '../components/Badges'

const STATE_STYLES = {
  fixed: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
  still_vulnerable: 'bg-red-500/15 text-red-400 border-red-500/40',
  regressed: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
  unchanged: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
}
const STATE_LABELS = {
  fixed: 'Fixed',
  still_vulnerable: 'Still vulnerable',
  regressed: 'Regressed',
  unchanged: 'Unchanged',
}

export default function History() {
  const [params, setParams] = useSearchParams()
  const [scans, setScans] = useState([])
  const [scan, setScan] = useState(null)
  const [verification, setVerification] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const selectedId = params.get('scan')

  useEffect(() => {
    const load = async () => {
      try {
        const ss = await api.get('/scans')
        setScans(ss)
        const id = selectedId ? Number(selectedId) : ss[0]?.id
        if (id) await selectScan(id)
      } catch (e) { setError(e.message) }
    }
    load()
  }, [])

  // Poll while the selected scan is still running
  useEffect(() => {
    if (!scan || !['pending', 'running'].includes(scan.status)) return
    const t = setInterval(async () => {
      try {
        const s = await api.get(`/scans/${scan.id}`)
        setScan(s)
        if (['completed', 'failed'].includes(s.status)) {
          clearInterval(t)
          setScans(await api.get('/scans'))
        }
      } catch { /* transient */ }
    }, 700)
    return () => clearInterval(t)
  }, [scan?.id, scan?.status])

  const selectScan = async (id) => {
    setError('')
    setVerification(null)
    setParams({ scan: String(id) })
    try {
      setScan(await api.get(`/scans/${id}`))
    } catch (e) { setError(e.message) }
  }

  const rescan = async () => {
    setBusy(true)
    setError('')
    try {
      const res = await api.post(`/scans/${scan.id}/rescan`)
      setScans(await api.get('/scans'))
      setParams({ scan: String(res.id) })
      setScan(res)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const verify = async () => {
    setVerifying(true)
    setError('')
    try {
      setVerification(await api.get(`/scans/${scan.id}/verification`))
      setScan(await api.get(`/scans/${scan.id}`)) // findings status may have changed
    } catch (e) { setError(e.message) }
    finally { setVerifying(false) }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <HistoryIcon size={24} className="text-indigo-400" /> Scan History & Fix Verification
        </h1>
        <p className="text-sm text-slate-400">
          Every assessment stored in SQLite. Rescan vulnerable endpoints and compare with the
          previous completed scan to confirm fixes.
        </p>
      </div>

      {error && <div className="card p-3 text-sm text-red-400">{error}</div>}

      <div className="grid lg:grid-cols-[20rem_1fr] gap-6 items-start">
        {/* Scan list */}
        <div className="card p-2 space-y-1 max-h-[70vh] overflow-y-auto">
          {scans.length === 0 && (
            <p className="text-sm text-slate-500 p-3">No scans yet. Start one from New Scan.</p>
          )}
          {scans.map((s) => (
            <button key={s.id} onClick={() => selectScan(s.id)}
              className={`w-full text-left rounded-lg px-3 py-2 text-sm transition ${
                scan?.id === s.id ? 'bg-navy-600/60 ring-1 ring-indigo-500/40' : 'hover:bg-navy-700/40'}`}>
              <div className="flex items-center justify-between">
                <span className="font-medium text-white truncate">#{s.id} {s.name}</span>
                <StatusBadge value={s.status} />
              </div>
              <div className="text-xs text-slate-400 mt-0.5 flex items-center gap-2">
                <span>{s.target_name}</span>·
                <span className="text-red-400">{s.confirmed_count} conf</span>
                <span className="text-orange-400">{s.potential_count} pot</span>
                <span className="text-emerald-400">{s.blocked_count} blk</span>
              </div>
            </button>
          ))}
        </div>

        {/* Selected scan detail */}
        <div className="space-y-6">
          {scan && (
            <>
              <div className="card p-5">
                <div className="flex items-center justify-between flex-wrap gap-3">
                  <div>
                    <h2 className="font-semibold text-white text-lg">Scan #{scan.id} — {scan.name}</h2>
                    <p className="text-xs text-slate-400">
                      Target: {scan.target_name} · {scan.endpoints_tested} endpoints tested ·{' '}
                      started {scan.started_at ? new Date(scan.started_at).toLocaleString() : '–'}
                      {scan.finished_at && ` · finished ${new Date(scan.finished_at).toLocaleString()}`}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <StatusBadge value={scan.status} />
                    {scan.status === 'completed' && (
                      <>
                        <button className="btn-ghost" onClick={verify} disabled={verifying}>
                          {verifying ? <Loader2 size={14} className="animate-spin" /> : <ArrowLeftRight size={14} />}
                          Verify fixes
                        </button>
                        {(scan.confirmed_count + scan.potential_count) > 0 && (
                          <button className="btn-primary" onClick={rescan} disabled={busy}>
                            {busy ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                            Rescan vulnerable
                          </button>
                        )}
                        <a className="btn-ghost" href={api.reportUrl(scan.id)} download>
                          <FileDown size={14} /> PDF
                        </a>
                      </>
                    )}
                  </div>
                </div>
                {scan.error_message && <div className="text-sm text-red-400 mt-2">{scan.error_message}</div>}
              </div>

              {/* Fix verification comparison (Feature I) */}
              {verification && (
                <div className="card p-5 space-y-3">
                  <h3 className="font-semibold text-white flex items-center gap-2">
                    <ShieldCheck size={16} className="text-emerald-400" />
                    Comparison with previous scan
                    {verification.previous_scan_id
                      ? <> #{verification.previous_scan_id}</>
                      : <span className="text-xs text-slate-500 font-normal ml-2">— no earlier completed scan for this target</span>}
                  </h3>
                  {verification.previous_scan_id && (
                    <>
                      <div className="flex gap-3 text-xs flex-wrap">
                        {Object.entries(STATE_LABELS).map(([k, label]) => (
                          <span key={k} className={`px-2 py-1 rounded-md border font-semibold ${STATE_STYLES[k]}`}>
                            {label}: {verification.summary[k] ?? 0}
                          </span>
                        ))}
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead>
                            <tr className="border-b border-navy-600/50">
                              <th className="table-th">Endpoint / resource</th>
                              <th className="table-th">Requester → Owner</th>
                              <th className="table-th">Previous</th>
                              <th className="table-th">Current</th>
                              <th className="table-th">State</th>
                            </tr>
                          </thead>
                          <tbody>
                            {verification.comparisons.map((c, i) => (
                              <tr key={i} className="border-b border-navy-700/40">
                                <td className="table-td">
                                  <div className="text-white text-xs">{c.endpoint_name}</div>
                                  <div className="font-mono text-[11px] text-indigo-300">{c.path} <span className="text-slate-500">(res {c.resource_id})</span></div>
                                </td>
                                <td className="table-td text-xs text-slate-300">{c.requester_name} → {c.owner_name}</td>
                                <td className="table-td"><ClassBadge value={c.previous_classification} /></td>
                                <td className="table-td"><ClassBadge value={c.current_classification} /></td>
                                <td className="table-td">
                                  <span className={`px-2 py-0.5 rounded-md border text-xs font-semibold ${STATE_STYLES[c.state]}`}>
                                    {STATE_LABELS[c.state]}
                                  </span>
                                </td>
                              </tr>
                            ))}
                            {verification.comparisons.length === 0 && (
                              <tr><td colSpan={5} className="table-td text-center text-slate-500 py-6 text-sm">
                                No overlapping results to compare.
                              </td></tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* Results table */}
              <div className="card overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-navy-600/50">
                      <th className="table-th">Endpoint</th>
                      <th className="table-th">Direction</th>
                      <th className="table-th">Resource</th>
                      <th className="table-th">Baseline</th>
                      <th className="table-th">Cross</th>
                      <th className="table-th">Sim.</th>
                      <th className="table-th">Classification</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(scan.results || []).map((r) => (
                      <tr key={r.id} className="border-b border-navy-700/40 hover:bg-navy-700/20">
                        <td className="table-td">
                          <div className="text-white text-xs">{r.endpoint_name}</div>
                          <div className="font-mono text-[11px] text-indigo-300">{r.method} {r.path}</div>
                        </td>
                        <td className="table-td text-xs text-slate-300">{r.requester_name} → {r.owner_name}<div className="text-[10px] text-slate-500">{r.direction}</div></td>
                        <td className="table-td font-mono text-xs">{r.resource_id}</td>
                        <td className="table-td font-mono">{r.baseline_status ?? '–'}</td>
                        <td className="table-td font-mono">{r.cross_status ?? '–'}</td>
                        <td className="table-td font-mono text-xs">{r.similarity != null ? `${Math.round(r.similarity * 100)}%` : '–'}</td>
                        <td className="table-td"><ClassBadge value={r.classification} /></td>
                      </tr>
                    ))}
                    {(scan.results || []).length === 0 && (
                      <tr><td colSpan={7} className="table-td text-center text-slate-500 py-8 text-sm">
                        {['pending', 'running'].includes(scan.status) ? 'Results will stream in as the engine tests each endpoint…' : 'No results recorded for this scan.'}
                      </td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {!scan && !error && (
            <div className="card p-10 text-center text-slate-500 text-sm">Select a scan from the list.</div>
          )}
        </div>
      </div>
    </div>
  )
}
