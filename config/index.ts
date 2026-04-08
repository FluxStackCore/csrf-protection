/**
 * CSRF Protection Plugin Configuration
 * Uses @fluxstack/plugin-sdk declarative config system
 */

import { defineConfig, config } from '@fluxstack/sdk/config'

// Auto-detect production environment for secure cookie default
const isProduction = typeof process !== 'undefined'
  && (process.env.NODE_ENV === 'production' || process.env.BUN_ENV === 'production')

const csrfConfigSchema = {
  enabled: config.boolean('CSRF_ENABLED', true),
  cookieName: config.string('CSRF_COOKIE_NAME', 'XSRF-TOKEN'),
  headerName: config.string('CSRF_HEADER_NAME', 'X-CSRF-Token'),
  tokenLength: config.number('CSRF_TOKEN_LENGTH', 32),
  safeMethods: config.array('CSRF_SAFE_METHODS', ['GET', 'HEAD', 'OPTIONS']),
  excludePaths: config.array('CSRF_EXCLUDE_PATHS', ['/api/health', '/api/auth/info', '/swagger']),
  sameSite: config.enum('CSRF_SAME_SITE', ['strict', 'lax', 'none'] as const, 'strict'),
  secure: config.boolean('CSRF_SECURE', isProduction),
  path: config.string('CSRF_PATH', '/'),
} as const

export const csrfConfig = defineConfig(csrfConfigSchema)

export type CsrfConfig = typeof csrfConfig
export default csrfConfig
