/**
 * CSRF Protection — Client Module
 *
 * Provides helpers for the Double-Submit Cookie pattern.
 * Auto-discovered by the framework via import.meta.glob.
 */

const COOKIE_NAME = 'XSRF-TOKEN'
const HEADER_NAME = 'X-CSRF-Token'

/** Token injetado pelo SSR no <meta name="csrf-token"> (se houver). */
function getMetaToken(): string | undefined {
  if (typeof document === 'undefined') return undefined
  const meta = document.querySelector('meta[name="csrf-token"]')
  return meta?.getAttribute('content') ?? undefined
}

function getCookieToken(): string | undefined {
  if (typeof document === 'undefined') return undefined
  const match = document.cookie.split('; ').find(c => c.startsWith(`${COOKIE_NAME}=`))
  return match ? match.slice(COOKIE_NAME.length + 1) : undefined
}

/** Lê o token CSRF: cookie primeiro, depois o <meta> injetado pelo SSR. */
export function getToken(): string | undefined {
  return getCookieToken() ?? getMetaToken()
}

/** Build headers object with the CSRF token (if available). */
export function getHeaders(): Record<string, string> {
  const token = getToken()
  return token ? { [HEADER_NAME]: token } : {}
}

/** Ensure the CSRF cookie exists. Fetches a token if missing (e sem meta). */
export async function ensureToken(): Promise<void> {
  if (getToken()) return
  await fetch('/api/__csrf', { credentials: 'include' })
}

// Auto-init: só faz fetch se NÃO houver token nem no cookie nem no <meta> do SSR.
// Com SSR injetando o token, esse round-trip é eliminado.
if (typeof document !== 'undefined') {
  if (!getToken()) {
    fetch('/api/__csrf', { credentials: 'include' })
  }
}
