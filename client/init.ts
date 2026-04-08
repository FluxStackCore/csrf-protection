/**
 * CSRF Protection — Client Module
 *
 * Provides helpers for the Double-Submit Cookie pattern.
 * Auto-discovered by the framework via import.meta.glob.
 */

const COOKIE_NAME = 'XSRF-TOKEN'
const HEADER_NAME = 'X-CSRF-Token'

/** Read the CSRF cookie value. */
export function getToken(): string | undefined {
  if (typeof document === 'undefined') return undefined
  const match = document.cookie.split('; ').find(c => c.startsWith(`${COOKIE_NAME}=`))
  return match ? match.slice(COOKIE_NAME.length + 1) : undefined
}

/** Build headers object with the CSRF token (if available). */
export function getHeaders(): Record<string, string> {
  const token = getToken()
  return token ? { [HEADER_NAME]: token } : {}
}

/** Ensure the CSRF cookie exists. Fetches a token if missing. */
export async function ensureToken(): Promise<void> {
  if (getToken()) return
  await fetch('/api/__csrf', { credentials: 'include' })
}

// Auto-init: pre-fetch CSRF token on module load if cookie not set
if (typeof document !== 'undefined') {
  if (!document.cookie.split('; ').some(c => c.startsWith(`${COOKIE_NAME}=`))) {
    fetch('/api/__csrf', { credentials: 'include' })
  }
}
