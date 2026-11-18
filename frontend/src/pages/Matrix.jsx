import { useEffect, useState } from 'react'
import { Grid3X3, Info } from 'lucide-react'
import { api } from '../api/client'
import { CLASS_LABELS } from '../components/Badges'

// Solid cell colors per classification (Feature G colour legend)
const CELL_STYLES = {
  OWNER: 'bg-sky-500/25 text-sky-300 border-sky-500/40',
  AUTHORIZED: 'bg-sky-500/25 text-sky-300 border-sky-500/40',
  BLOCKED: 'bg-emerald-500/25 text-emerald-300 border-emerald-500/40',
  CONFIRMED_BOLA: 'bg-red-500/30 text-red-300 border-red-500/50',
  POTENTIAL_BOLA: 'bg-orange-500/25 text-orange-300 border-orange-500/40',
  INCONCLUSIVE: 'bg-slate-500/25 text-slate-300 border-slate-500/40',
  UNTESTED: 'bg-navy-700/40 text-slate-500 border-navy-600',
}

export default function Matrix() {
  const [scans, setScans] = useState([])
  const [scanId, setScanId] = useState('') // '' = latest
  const [matrix, setMatrix] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/scans').then((ss) => setScans(ss.filter((s) => s.status === 'completed')))
      .catch((e) => setError(e.message))
  }, [])

  useEffect(() => {
    const path = scanId ? `/matrix/${scanId}` : '/matrix/latest'
    api.get(path).then((m) => { setMatrix(m); setError('') })
      .catch((e) => { setMatrix(null); setError(e.message) })
  }, [scanId])

  const cellFor = (accountId, endpointId) =>
    matrix?.cells.find((c) => c.account_id === accountId && c.endpoint_id === endpointId)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Grid3X3 size={24} className="text-indigo-400" /> Access-Control Matrix
          </h1>
          <p className="text-sm text-slate-400">
            Rows = test accounts, columns = endpoints/resources. Colours show actual scan outcomes.
          </p>
        </div>
        <select className="input !w-64" value={scanId} onChange={(e) => setScanId(e.target.value)}>
          <option value="">Latest completed scan</option>
          {scans.map((s) => <option key={s.id} value={s.id}>#{s.id} — {s.name}</option>)}
        </select>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-2 text-xs">
        {['OWNER', 'BLOCKED', 'CONFIRMED_BOLA', 'POTENTIAL_BOLA', 'INCONCLUSIVE', 'UNTESTED'].map((k) => (
          <span key={k} className={`px-2 py-1 rounded-md border font-semibold ${CELL_STYLES[k]}`}>
            {CLASS_LABELS[k]}
          </span>
        ))}
      </div>

      {error && (
        <div className="card p-4 text-sm text-slate-400 flex items-center gap-2">
          <Info size={16} className="text-indigo-400 shrink-0" />
          {error === 'No completed scan yet'
            ? 'No completed scan yet — configure a target, accounts and endpoints, then run a scan from New Scan.'
            : error}
        </div>
      )}

      {matrix && (
        <div className="card overflow-x-auto">
          <div className="px-4 pt-4 text-sm text-slate-400">
            Scan <b className="text-white">#{matrix.scan_id}</b> — {matrix.scan_name} · target{' '}
            <span className="font-mono text-indigo-300">{matrix.target.base_url}</span>
          </div>
          <table className="w-full mt-3">
            <thead>
              <tr>
                <th className="table-th sticky left-0 bg-navy-800">Account \ Resource</th>
                {matrix.endpoints.map((ep) => (
                  <th key={ep.id} className="table-th text-center min-w-[9rem]">
                    <div className="text-white text-xs">{ep.name}</div>
                    <div className="font-mono text-[10px] text-indigo-300 font-normal">{ep.method} {ep.path_template}</div>
                    <div className="text-[10px] text-slate-500 font-normal">res {ep.resource_id} · owner {ep.owner_name}</div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {matrix.accounts.map((acct) => (
                <tr key={acct.id}>
                  <td className="table-td sticky left-0 bg-navy-800 font-medium text-white">
                    {acct.name}
                    <div className="text-[10px] text-slate-500">home res {acct.home_resource_id || '–'}</div>
                  </td>
                  {matrix.endpoints.map((ep) => {
                    const c = cellFor(acct.id, ep.id)
                    const cls = c?.classification || 'UNTESTED'
                    return (
                      <td key={ep.id} className="p-1.5 text-center">
                        <div className={`rounded-md border py-2 px-1 text-xs font-semibold ${CELL_STYLES[cls] || CELL_STYLES.INCONCLUSIVE}`}>
                          {CLASS_LABELS[cls] || cls}
                          {c?.cross_status ? <div className="font-mono font-normal text-[10px] opacity-80">HTTP {c.cross_status}</div> : null}
                          {c?.similarity != null && cls.includes('BOLA') ? (
                            <div className="font-normal text-[10px] opacity-80">sim {Math.round(c.similarity * 100)}%</div>
                          ) : null}
                        </div>
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
