import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ScanSearch,
  Route as RouteIcon,
  ShieldAlert,
  ShieldCheck,
  ArrowRight,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid,
} from 'recharts'
import { api } from '../api/client'
import { StatusBadge } from '../components/Badges'

const SEVERITY_COLORS = {
  Critical: '#dc2626',
  High: '#ea580c',
  Medium: '#ca8a04',
  Low: '#2563eb',
  Informational: '#64748b',
}

function StatCard({ icon: Icon, label, value, tone }) {
  return (
    <div className="card p-5 flex items-start gap-4">
      <div className={`p-3 rounded-lg ${tone}`}>
        <Icon size={22} />
      </div>
      <div>
        <div className="text-3xl font-bold text-white">{value ?? '–'}</div>
        <div className="text-sm text-slate-400">{label}</div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/dashboard/stats').then(setStats).catch((e) => setError(e.message))
  }, [])

  if (error) {
    return (
      <div className="card p-6 text-red-400">
        Backend unreachable: {error}. Start it with
        <code className="ml-1 text-indigo-300">python -m uvicorn app.main:app --app-dir backend</code>.
      </div>
    )
  }
  if (!stats) return <div className="text-slate-400 animate-pulse p-6">Loading dashboard…</div>

  const chartData = stats.severity_chart.filter((b) => b.count > 0)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Overview</h1>
          <p className="text-sm text-slate-400">Live results from authorised BOLA/IDOR assessments</p>
        </div>
        <Link to="/scan" className="btn-primary">
          <ScanSearch size={16} /> New Scan
        </Link>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          icon={ScanSearch} label="Total Scans" value={stats.total_scans}
          tone="bg-blue-500/15 text-blue-400 border border-blue-500/30"
        />
        <StatCard
          icon={RouteIcon} label="Endpoints Tested" value={stats.endpoints_tested}
          tone="bg-indigo-500/15 text-indigo-400 border border-indigo-500/30"
        />
        <StatCard
          icon={ShieldAlert} label="Confirmed Vulnerabilities" value={stats.confirmed_vulnerabilities}
          tone="bg-red-500/15 text-red-400 border border-red-500/30"
        />
        <StatCard
          icon={ShieldCheck} label="Protected Endpoints" value={stats.protected_endpoints}
          tone="bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
        />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-slate-200 mb-4">
            Vulnerability Severity Distribution (open findings)
          </h2>
          {chartData.length === 0 ? (
            <div className="h-64 flex items-center justify-center text-slate-500 text-sm">
              No open findings yet — run a scan to populate chart data.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="severity" stroke="#64748b" fontSize={12} />
                <YAxis allowDecimals={false} stroke="#64748b" fontSize={12} />
                <Tooltip
                  contentStyle={{ background: '#0f1320', border: '1px solid #2c3547', borderRadius: 6, fontSize: 12 }}
                />
                <Bar dataKey="count" name="Findings" radius={[4, 4, 0, 0]}>
                  {chartData.map((d) => (
                    <Cell key={d.severity} fill={SEVERITY_COLORS[d.severity]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-200">Recent Scan Activity</h2>
            <Link to="/history" className="text-xs text-slate-400 hover:text-indigo-300 flex items-center gap-1">
              All scans <ArrowRight size={12} />
            </Link>
          </div>
          {stats.recent_scans.length === 0 ? (
            <div className="h-64 flex items-center justify-center text-slate-500 text-sm">
              No scans recorded yet. Configure a target, accounts and endpoints, then start a scan.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-navy-600/50">
                    <th className="table-th">Scan</th>
                    <th className="table-th">Target</th>
                    <th className="table-th">Status</th>
                    <th className="table-th">Confirmed</th>
                    <th className="table-th">Potential</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recent_scans.map((s) => (
                    <tr key={s.id} className="border-b border-navy-700/40 hover:bg-navy-700/20">
                      <td className="table-td">
                        <Link to={`/history?scan=${s.id}`} className="text-indigo-300 hover:underline">
                          #{s.id} {s.name}
                        </Link>
                      </td>
                      <td className="table-td text-slate-300">{s.target_name}</td>
                      <td className="table-td"><StatusBadge value={s.status} /></td>
                      <td className="table-td text-red-400 font-semibold">{s.confirmed_count}</td>
                      <td className="table-td text-orange-400 font-semibold">{s.potential_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
