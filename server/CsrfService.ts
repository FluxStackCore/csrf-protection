/**
 * CSRF Token Service
 * Handles token generation and validation using the Double-Submit Cookie pattern.
 */

import { randomBytes, timingSafeEqual } from 'crypto'

export interface CsrfServiceOptions {
  tokenLength: number
}

export class CsrfService {
  private tokenLength: number

  constructor(options: CsrfServiceOptions) {
    this.tokenLength = options.tokenLength
  }

  /** Generate a cryptographically random hex token. */
  generateToken(): string {
    return randomBytes(this.tokenLength).toString('hex')
  }

  /** Timing-safe comparison of cookie token vs header token. */
  validateToken(cookieValue: string | undefined, headerValue: string | undefined): boolean {
    if (!cookieValue || !headerValue) return false
    if (cookieValue.length !== headerValue.length) return false

    try {
      const a = Buffer.from(cookieValue, 'utf-8')
      const b = Buffer.from(headerValue, 'utf-8')
      return timingSafeEqual(a, b)
    } catch {
      return false
    }
  }

  /** Build the Set-Cookie header value for a CSRF token. */
  buildCookieHeader(
    token: string,
    cookieName: string,
    options: { sameSite: string; secure: boolean; path: string }
  ): string {
    const parts = [
      `${cookieName}=${token}`,
      `Path=${options.path}`,
      `SameSite=${options.sameSite}`,
    ]
    if (options.secure) parts.push('Secure')
    // NOT httpOnly — client JS must be able to read the cookie
    return parts.join('; ')
  }
}
