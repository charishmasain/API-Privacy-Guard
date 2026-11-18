import { useEffect, useState } from 'react'
import { FileText, FileDown, Loader2 } from 'lucide-react'
import { api } from '../api/client'
import { StatusBadge } from '../components/Badges'

export default function Reports() {
  const [scans, setScans] = useState([])
  const [error, setError] = useState('')
  const [downloading, setDownloading] = useState(null)

  useEffect(() => {
    api.get('/scans')
      .then((ss) => setScans(ss.filter((s) => ['completed', 'failed'].includes(s.status))))
      .catch((e) => setError(e.message))
  }, [])

  // PDF is served directly by the backend; trigger download via a temporary link
  const download = (scan) => {
    setDownloading(scan.id)
    const a = document.createElement('a')
    a.href = api.reportUrl(scan.id)
    a.download = `privacyguard-report-scan-${scan.id}.pdf`
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => setDownloading(null), 800)
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <FileText size={24} className="text-indigo-400" /> PDF Reports
        </h1>
        <p className="text-sm text-slate-400">
          Assessment summary, target information, endpoints tested, vulnerability findings with
          sanitized evidence, severity, impact and remediation — generated with ReportLab from
          real scan data.
        </p>
      </div>

      {error && <div className="card p-3 text-sm text-red-400">{error}</div>}

      <div className="card overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-navy-600/50">
              <th className="table-th">Scan</th>
              <th className="table-th">Target</th>
              <th className="table-th">Status</th>
              <th className="table-th">Date</th>
              <th className="table-th">Findings</th>
              <th className="table-th text-right">Report</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id} className="border-b border-navy-700/40 hover:bg-navy-700/20">
                <td className="table-td">
                  <div className="text-white font-medium">#{s.id} {s.name}</div>
                  <div className="text-xs text-slate-500">{s.endpoints_tested} endpoints tested</div>
                </td>
                <td className="table-td text-slate-300">{s.target_name}</td>
                <td className="table-td"><StatusBadge value={s.status} /></td>
                <td className="table-td text-xs text-slate-400">
                  {new Date(s.created_at).toLocaleString()}
                </td>
                <td className="table-td text-sm">
                  <span className="text-red-400 font-semibold">{s.confirmed_count}</span>
                  <span className="text-slate-500"> conf · </span>
                  <span className="text-orange-400 font-semibold">{s.potential_count}</span>
                  <span className="text-slate-500"> pot</span>
                </td>
                <td className="table-td text-right">
                  <button className="btn-primary !py-1.5" onClick={() => download(s)} disabled={downloading === s.id}>
                    {downloading === s.id ? <Loader2 size={14} className="animate-spin" /> : <FileDown size={14} />}
                    Download PDF
                  </button>
                </td>
              </tr>
            ))}
            {scans.length === 0 && (
              <tr><td colSpan={6} className="table-td text-center text-slate-500 py-10">
                No finished scans yet — reports become available once a scan completes.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
