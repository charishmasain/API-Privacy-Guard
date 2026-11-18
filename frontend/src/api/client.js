// Thin fetch wrapper around the FastAPI backend (proxied at /api by Vite).
const BASE = '/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (res.status === 204) return null
  let body = null
  try {
    body = await res.json()
  } catch {
    body = null
  }
  if (!res.ok) {
    const detail = body?.detail
    const msg = Array.isArray(detail)
      ? detail.map((d) => d.msg).join('; ')
      : detail || `HTTP ${res.status}`
    throw new Error(msg)
  }
  return body
}

export const api = {
  get: (p) => request(p),
  post: (p, data) => request(p, { method: 'POST', body: JSON.stringify(data) }),
  put: (p, data) => request(p, { method: 'PUT', body: JSON.stringify(data) }),
  del: (p) => request(p, { method: 'DELETE' }),
  reportUrl: (scanId) => `${BASE}/reports/${scanId}/pdf`,
}
