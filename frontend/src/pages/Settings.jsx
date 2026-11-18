import { useEffect, useState } from 'react'
import { Settings as SettingsIcon, Shield, Lock, Server, Terminal } from 'lucide-react'
import { api } from '../api/client'

export default function Settings() {
  const [policy, setPolicy] = useState(null)
  const [health, setHealth] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/policy').then(setPolicy).catch((e) => setError(e.message))
    api.get('/health').then(setHealth).catch(() => setHealth({ status: 'unreachable' }))
  }, [])

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <SettingsIcon size={24} className="text-indigo-400" /> Settings & Safety Policy
        </h1>
        <p className="text-sm text-slate-400">
          Live enforcement configuration read from the running backend. These guardrails are hard
          limits inside the detection engine and cannot be relaxed from the UI.
        </p>
      </div>

      {error && <div className="card p-3 text-sm text-red-400">{error}</div>}

      <div className="card p-5 space-y-3">
        <h2 className="font-semibold text-white flex items-center gap-2">
          <Server size={16} className="text-indigo-400" /> Backend
        </h2>
        <div className="text-sm text-slate-300">
          Status:{' '}
          <span className={health?.status === 'ok' ? 'text-emerald-400' : 'text-red-400'}>
            {health ? health.status : 'checking…'}
          </span>
          {health?.app && <span className="text-slate-500"> · {health.app}</span>}
        </div>
      </div>

      {policy && (
        <>
          <div className="card p-5 space-y-3">
            <h2 className="font-semibold text-white flex items-center gap-2">
              <Shield size={16} className="text-indigo-400" /> Request safety
            </h2>
            <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-2 text-sm">
              <dt className="text-slate-400">Allowed HTTP methods</dt>
              <dd className="font-mono text-emerald-300">{policy.allowed_methods.join(', ')} (read-only)</dd>
              <dt className="text-slate-400">Request timeout</dt>
              <dd className="text-slate-200">{policy.request_timeout_seconds}s</dd>
              <dt className="text-slate-400">Max response size</dt>
              <dd className="text-slate-200">{Math.round(policy.max_response_bytes / 1024)} KB (truncated)</dd>
              <dt className="text-slate-400">Redirects</dt>
              <dd className="text-slate-200">{policy.redirects_followed ? 'followed' : 'never followed (SSRF guard)'}</dd>
            </dl>
          </div>

          <div className="card p-5 space-y-3">
            <h2 className="font-semibold text-white flex items-center gap-2">
              <Lock size={16} className="text-indigo-400" /> Data protection
            </h2>
            <div className="text-sm text-slate-300 space-y-2">
              <p><span className="text-slate-400">SSRF protection:</span> {policy.ssrf_protection}</p>
              <p><span className="text-slate-400">Token storage:</span> {policy.token_encryption}</p>
              <p className="text-slate-400 text-xs">
                Tokens are masked in all UI views and reports (first-4 + last-4). Sensitive PII in
                evidence is detected and masked before storage. Full credentials are never logged.
              </p>
            </div>
          </div>

          <div className="card p-5 space-y-3">
            <h2 className="font-semibold text-white flex items-center gap-2">
              <Terminal size={16} className="text-indigo-400" /> Local mock API environment
            </h2>
            <p className="text-xs text-slate-400">
              Isolated practice APIs (Alice/Bob, resources 101/202) for validating the engine.
              Start them, then authorise <span className="font-mono text-indigo-300">http://127.0.0.1:8011</span>{' '}
              and <span className="font-mono text-indigo-300">http://127.0.0.1:8012</span> as targets with allow-localhost enabled.
            </p>
            {policy.mock_api_commands.map((cmd) => (
              <pre key={cmd} className="bg-navy-950 border border-navy-600/50 rounded-lg px-3 py-2 text-xs font-mono text-emerald-300">
                {cmd}
              </pre>
            ))}
          </div>
        </>
      )}

      <p className="text-xs text-slate-500">
        Legal notice: only scan APIs you own or have explicit written authorization to test.
        The Targets page requires this confirmation before any scan can start.
      </p>
    </div>
  )
}
