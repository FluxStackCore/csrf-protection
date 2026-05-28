/**
 * FluxStack CSRF Protection Plugin
 * Double-Submit Cookie pattern — stateless, no server-side storage needed.
 */

import type { Plugin, PluginContext, ValidationContext } from '@fluxstack/plugin-kit'

import { Elysia, t } from 'elysia'
import { CsrfService } from './server/CsrfService'
import { csrfConfig } from './config'

// Resolved config values with fallbacks
const COOKIE_NAME = csrfConfig.cookieName ?? 'XSRF-TOKEN'
const HEADER_NAME = (csrfConfig.headerName ?? 'X-CSRF-Token').toLowerCase()
const TOKEN_LENGTH = csrfConfig.tokenLength ?? 32
const SAFE_METHODS = csrfConfig.safeMethods ?? ['GET', 'HEAD', 'OPTIONS']
const EXCLUDE_PATHS = csrfConfig.excludePaths ?? ['/api/health', '/api/auth/info', '/swagger']
const SAME_SITE = csrfConfig.sameSite ?? 'strict'
const SECURE = csrfConfig.secure ?? false
const COOKIE_PATH = csrfConfig.path ?? '/'

let csrfService: CsrfService

/** Parse a specific cookie value from the Cookie header string. */
function parseCookie(cookieHeader: string | undefined, name: string): string | undefined {
  if (!cookieHeader) return undefined
  const match = cookieHeader.split('; ').find(c => c.startsWith(`${name}=`))
  return match ? match.slice(name.length + 1) : undefined
}

export const csrfProtectionPlugin: Plugin = {
  name: 'csrf-protection',
  version: '1.0.0',
  description: 'CSRF protection using the Double-Submit Cookie pattern',
  author: 'FluxStack Team',
  priority: 90,
  category: 'security',
  tags: ['csrf', 'security', 'middleware'],
  dependencies: [],

  setup: async (context: PluginContext) => {
    if (!csrfConfig.enabled) {
      context.logger.info('CSRF protection disabled by configuration')
      return
    }

    csrfService = new CsrfService({ tokenLength: TOKEN_LENGTH })

    ;(global as Record<string, unknown>).csrfService = csrfService

    if (!(global as Record<string, unknown>).__fluxstackPlugins) {
      (global as Record<string, unknown>).__fluxstackPlugins = []
    }
    ;((global as Record<string, unknown>).__fluxstackPlugins as Array<Record<string, string>>).push({
      name: 'CSRF Protection',
      status: 'Active',
      details: `cookie=${COOKIE_NAME} header=${HEADER_NAME}`,
    })

    // Register client-side hook to auto-inject CSRF token on every Eden request
    const clientHooks = (context as any).clientHooks as { register(hook: string, code: string): void } | undefined
    if (clientHooks) {
      clientHooks.register('onEdenInit', `
        // CSRF Protection: auto-inject token header on state-changing requests
        (async function() {
          var COOKIE_NAME = '${COOKIE_NAME}';
          var HEADER_NAME = '${HEADER_NAME}';

          function getMetaToken() {
            var m = document.querySelector('meta[name="csrf-token"]');
            return m ? m.getAttribute('content') : null;
          }
          function getCsrfToken() {
            var match = document.cookie.split('; ').find(function(c) { return c.startsWith(COOKIE_NAME + '='); });
            if (match) return match.slice(COOKIE_NAME.length + 1);
            // Fallback: token injetado pelo SSR no <meta> (zero round-trip).
            return getMetaToken();
          }

          // Só busca um token se não houver nem no cookie nem no <meta> do SSR.
          if (!getCsrfToken()) {
            try { await fetch('/api/__csrf', { credentials: 'include' }); } catch(e) {}
          }

          // Patch global fetch to auto-add CSRF header on POST/PUT/DELETE
          var originalFetch = window.fetch;
          window.fetch = function(input, init) {
            var method = (init && init.method || 'GET').toUpperCase();
            if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
              var token = getCsrfToken();
              if (token) {
                init = init || {};
                init.headers = new Headers(init.headers || {});
                init.headers.set(HEADER_NAME, token);
              }
            }
            return originalFetch.call(this, input, init);
          };
        })();
      `)
      context.logger.info('CSRF client hook registered — fetch will auto-inject token')
    }

  },

  // Elysia sub-app: GET /api/__csrf to issue a CSRF token
  // @ts-ignore - plugin property is supported by the framework
  plugin: new Elysia({ prefix: '/api', tags: ['Security'] })
    .get('/__csrf', ({ cookie }) => {
      if (!csrfService) {
        return { token: '' }
      }

      const existing = cookie[COOKIE_NAME]?.value as string | undefined

      if (existing) {
        return { token: existing }
      }

      const token = csrfService.generateToken()
      cookie[COOKIE_NAME]!.set({
        value: token,
        httpOnly: false,
        sameSite: SAME_SITE,
        secure: SECURE,
        path: COOKIE_PATH,
      })

      return { token }
    }, {
      detail: {
        summary: 'Get CSRF Token',
        description: 'Returns a CSRF token and sets the XSRF-TOKEN cookie. The client should read the cookie and send its value as the X-CSRF-Token header on state-changing requests.',
        tags: ['Security', 'CSRF'],
      },
      response: t.Object({
        token: t.String(),
      }),
    }),

  // Validate CSRF token on state-changing requests
  onRequestValidation: async (context: ValidationContext) => {
    if (!csrfConfig.enabled || !csrfService) return

    const method = context.method.toUpperCase()

    // Skip safe methods
    if (SAFE_METHODS.includes(method)) return

    // Skip excluded paths
    if (EXCLUDE_PATHS.some(p => context.path.startsWith(p))) return

    // Extract tokens
    const cookieHeader = context.headers['cookie']
    const cookieToken = parseCookie(cookieHeader, COOKIE_NAME)
    const headerToken = context.headers[HEADER_NAME.toLowerCase()]

    // Validate
    if (!cookieToken || !headerToken) {
      context.isValid = false
      context.errors.push({
        field: 'csrf',
        message: 'CSRF token missing',
        code: 'CSRF_TOKEN_MISSING',
      })
      return
    }

    if (!csrfService.validateToken(cookieToken, headerToken)) {
      context.isValid = false
      context.errors.push({
        field: 'csrf',
        message: 'CSRF token invalid',
        code: 'CSRF_TOKEN_INVALID',
      })
    }
  },
}

export default csrfProtectionPlugin
