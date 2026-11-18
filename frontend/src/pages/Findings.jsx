import { useEffect, useState } from 'react'
import { Bug, FileDown } from 'lucide-react'
import { api } from '../api/client'
import Modal from '../components/Modal'
import { SeverityBadge, ClassBadge, StatusBadge } from '../components/Badges'

const SEVERITIES = ['', 'Critical', 'High', 'Medium', 'Low', 'Informational']

export default function Findings() {
  const [findings, setFindings] = useState([])
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState('')

  const load = () => {
    const params = new URLSearchParams()
    if (severity) params.set('severity', severity)
    if (status) params.set('status', status)
    api.get(`/findings?${params}`).then(setFindings).catch((e) => setError(e.message))
  }
  useEffect(load, [severity, status])

  const evidence = selected ? safeParse(selected.evidence) : null
  const cats = selected?.exposed_categories ? JSON.parse(selected.exposed_categories) : []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Bug size={24} className="text-red-400" /> Vulnerability Findings
          </h1>
          <p className="text-sm text-slate-400">Evidence-based BOLA/IDOR findings from actual scan results.</p>
        </div>
        <div className="flex gap-3">
          <select className="input !w-40" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s || 'All severities'}</option>)}
          </select>
          <select className="input !w-36" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            <option value="open">Open</option>
            <option value="fixed">Fixed</option>
          </select>
        </div>
      </div>

      {error && <div className="card p-3 text-red-400 text-sm">{error}</div>}

      <div className="card overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-navy-600/50">
              <th className="table-th">Severity</th>
              <th className="table-th">Finding</th>
              <th className="table-th">Endpoint</th>
              <th className="table-th">Requester → Owner</th>
              <th className="table-th">HTTP</th>
              <th className="table-th">Exposed data</th>
              <th className="table-th">Status</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} className="border-b border-navy-700/40 hover:bg-navy-700/20 cursor-pointer"
                onClick={() => setSelected(f)}>
                <td className="table-td"><SeverityBadge value={f.severity} /></td>
                <td className="table-td text-white max-w-xs">
                  <div className="truncate font-medium">{f.name}</div>
                  <div className="text-xs text-slate-500">scan #{f.scan_id} · {f.classification.replace('_', ' ')}</div>
                </td>
                <td className="table-td">
                  <span className="font-mono text-xs text-indigo-300">{f.method} {f.path}</span>
                </td>
                <td className="table-td text-slate-300">{f.requester_name} → <b>{f.owner_name}</b> <span className="text-slate-500">(res {f.resource_id})</span></td>
                <td className="table-td font-mono">{f.http_status ?? '–'}</td>
                <td className="table-td">
                  <div className="flex flex-wrap gap-1">
                    {(f.exposed_categories ? JSON.parse(f.exposed_categories) : []).map((c) => (
                      <span key={c} className="px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 text-[10px] font-semibold">
                        {c}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="table-td"><StatusBadge value={f.status} /></td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr><td colSpan={7} className="table-td text-center text-slate-500 py-10">
                No findings match the current filter. Run a scan against a target to populate findings.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal title={selected?.name || ''} open={!!selected} onClose={() => setSelected(null)} wide>
        {selected && (
          <div className="space-y-4 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge value={selected.severity} />
              <ClassBadge value={selected.classification} />
              <StatusBadge value={selected.status} />
              <span className="ml-auto text-xs text-slate-500">
                first seen {new Date(selected.first_seen_at).toLocaleString()}
              </span>
            </div>

            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 bg-navy-900 rounded-lg p-4 border border-navy-600/50">
              <Row k="Affected endpoint" v={`${selected.method} ${selected.path}`} mono />
              <Row k="Resource id" v={selected.resource_id} mono />
              <Row k="Requesting account" v={selected.requester_name} />
              <Row k="Actual resource owner" v={selected.owner_name} />
              <Row k="HTTP response status" v={selected.http_status ?? '–'} />
              <Row k="Exposed categories" v={cats.join(', ') || 'none detected'} />
            </dl>

            <Section title="Technical explanation">{selected.technical_explanation}</Section>
            <Section title="Potential impact">{selected.potential_impact}</Section>
            <Section title="Recommended remediation">{selected.remediation}</Section>
            <div>
              <div className="label">Sanitized evidence (PII masked)</div>
              <pre className="bg-navy-950 border border-navy-600/50 rounded-lg p-3 text-xs font-mono text-emerald-300 overflow-x-auto max-h-64">
{evidence ? JSON.stringify(evidence, null, 2) : 'no evidence recorded'}
              </pre>
            </div>
            <a className="btn-ghost" href={api.reportUrl(selected.scan_id)} download>
              <FileDown size={14} /> Download full scan report (PDF)
            </a>
          </div>
        )}
      </Modal>
    </div>
  )
}

function Row({ k, v, mono }) {
  return (
    <>
      <dt className="text-slate-400">{k}</dt>
      <dd className={mono ? 'font-mono text-indigo-300' : 'text-slate-200'}>{v}</dd>
    </>
  )
}

function Section({ title, children }) {
  return (
    <div>
      <div className="label">{title}</div>
      <p className="text-slate-300 leading-relaxed">{children}</p>
    </div>
  )
}

function safeParse(s) {
  try { return JSON.parse(s) } catch { return null }
}
