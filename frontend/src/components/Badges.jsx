// Classification / severity / status badges shared across pages.

const CLASS_STYLES = {
  CONFIRMED_BOLA: 'bg-red-500/15 text-red-400 border-red-500/40',
  POTENTIAL_BOLA: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
  BLOCKED: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
  AUTHORIZED: 'bg-sky-500/15 text-sky-400 border-sky-500/40',
  OWNER: 'bg-sky-500/15 text-sky-400 border-sky-500/40',
  INCONCLUSIVE: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
  UNTESTED: 'bg-navy-700/40 text-slate-500 border-navy-600',
}

export const CLASS_LABELS = {
  CONFIRMED_BOLA: 'Confirmed BOLA',
  POTENTIAL_BOLA: 'Potential BOLA',
  BLOCKED: 'Blocked',
  AUTHORIZED: 'Authorized',
  OWNER: 'Owner (baseline)',
  INCONCLUSIVE: 'Inconclusive',
  UNTESTED: 'Untested',
}

const SEVERITY_STYLES = {
  Critical: 'bg-red-600/20 text-red-400 border-red-500/50',
  High: 'bg-orange-600/20 text-orange-400 border-orange-500/50',
  Medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40',
  Low: 'bg-blue-500/15 text-blue-400 border-blue-500/40',
  Informational: 'bg-slate-500/15 text-slate-400 border-slate-500/40',
}

const STATUS_STYLES = {
  open: 'bg-red-500/15 text-red-400 border-red-500/40',
  fixed: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
  reopened: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
  completed: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
  running: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/40',
  pending: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
  failed: 'bg-red-500/15 text-red-400 border-red-500/40',
}

export function ClassBadge({ value }) {
  return (
    <span className={`inline-flex px-2 py-0.5 rounded-md border text-xs font-semibold ${CLASS_STYLES[value] || CLASS_STYLES.INCONCLUSIVE}`}>
      {CLASS_LABELS[value] || value}
    </span>
  )
}

export function SeverityBadge({ value }) {
  return (
    <span className={`inline-flex px-2 py-0.5 rounded-md border text-xs font-bold ${SEVERITY_STYLES[value] || SEVERITY_STYLES.Informational}`}>
      {value}
    </span>
  )
}

export function StatusBadge({ value }) {
  const cls = STATUS_STYLES[value] || STATUS_STYLES.pending
  return (
    <span className={`inline-flex px-2 py-0.5 rounded-md border text-xs font-semibold capitalize ${cls}`}>
      {value}
    </span>
  )
}
