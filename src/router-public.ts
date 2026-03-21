import { LIMITS } from './config/limits';
import { DEFAULT_DEV_SECRET } from './types';
import {
  handleAccessSend,
  handleAccessSendFile,
  handleAccessSendV2,
  handleAccessSendFileV2,
  handleDownloadSendFile,
} from './handlers/sends';
import { handleKnownDevice } from './handlers/devices';
import { handleToken, handlePrelogin, handleRevocation } from './handlers/identity';
import {
  handleRegister,
  handleGetPasswordHint,
  handleRecoverTwoFactor,
} from './handlers/accounts';
import { handlePublicDownloadAttachment } from './handlers/attachments';
import { handlePublicUploadAttachment } from './handlers/attachments';
import {
  handleNotificationsHub,
  handleNotificationsNegotiate,
} from './handlers/notifications';
import { handlePublicUploadSendFile } from './handlers/sends';
import { jsonResponse } from './utils/response';
import type { Env } from './types';

type PublicRateLimiter = (category?: string, maxRequests?: number) => Promise<Response | null>;
type JwtUnsafeReason = 'missing' | 'default' | 'too_short' | null;

export interface WebBootstrapResponse {
  defaultKdfIterations: number;
  jwtUnsafeReason: JwtUnsafeReason;
  jwtSecretMinLength: number;
}

function isSameOriginWriteRequest(request: Request): boolean {
  const targetOrigin = new URL(request.url).origin;
  const origin = request.headers.get('Origin');
  if (origin) {
    return origin === targetOrigin;
  }

  const referer = request.headers.get('Referer');
  if (referer) {
    try {
      return new URL(referer).origin === targetOrigin;
    } catch {
      return false;
    }
  }

  return false;
}

function getNwIconSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96" role="img" aria-label="NW icon"><rect x="4" y="4" width="88" height="88" rx="20" fill="#111418"/><text x="48" y="60" text-anchor="middle" font-size="36" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-weight="800" letter-spacing="0.5" fill="#FFFFFF">NW</text></svg>`;
}

function handleNwFavicon(): Response {
  return new Response(getNwIconSvg(), {
    status: 200,
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': `public, max-age=${LIMITS.cache.iconTtlSeconds}`,
    },
  });
}

function buildIconServiceBase(origin: string): string {
  return `${origin}/icons`;
}

function buildIconServiceTemplate(origin: string): string {
  return `${buildIconServiceBase(origin)}/{}/icon.png`;
}

function buildIconServiceCsp(origin: string): string {
  return `img-src 'self' data: ${origin}`;
}

function normalizeIconHost(rawHost: string): string | null {
  const decoded = decodeURIComponent(String(rawHost || '').trim()).toLowerCase().replace(/\.+$/, '');
  if (!decoded || decoded.includes('/') || decoded.includes('\\')) return null;
  try {
    const parsed = new URL(`https://${decoded}`);
    return parsed.hostname === decoded ? decoded : null;
  } catch {
    return null;
  }
}

// Icons handler - Vercel 优先 + 逐级回退 + Google 兜底（最终版）
async function handleWebsiteIcon(host: string): Promise<Response> {
  const normalizedHost = normalizeIconHost(host);
  if (!normalizedHost) return handleNwFavicon();

  const cache = caches.default;
  const cacheKey = new Request(`https://nodewarden-icons.local/icons/${normalizedHost}/icon.png`, { method: 'GET' });
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  let finalResp: Response | null = null;

  // 1. Vercel 优先：逐级回退查找（sub.digitalplat.org → digitalplat.org）
  let parts = normalizedHost.split('.');
  while (parts.length >= 2) {
    const currentHost = parts.join('.');
    const vercelUrl = `https://icon-xi.vercel.app/${currentHost}/icon.png`;

    // HEAD 快速探测（只检查是否存在，不下载图片）
    const vCheck = await fetch(vercelUrl, {
      method: 'HEAD',
      headers: { 'User-Agent': 'NodeWarden/1.0' },
    });

    if (vCheck.ok) {
      finalResp = await fetch(vercelUrl, {
        headers: { 'User-Agent': 'NodeWarden/1.0' },
        cf: { cacheEverything: true, cacheTtl: LIMITS.cache.iconTtlSeconds },
      });
      break; // 找到就立即返回
    }

    parts.shift(); // 向上级域名回退
  }

  // 2. Google 兜底（Vercel 没找到才走这里）
  if (!finalResp || !finalResp.ok) {
    const googleUrl = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(normalizedHost)}&sz=64`;
    finalResp = await fetch(googleUrl, {
      headers: { 'User-Agent': 'NodeWarden/1.0' },
      redirect: 'follow',
      cf: { cacheEverything: true, cacheTtl: LIMITS.cache.iconTtlSeconds },
    });
  }

  // 3. 返回结果并缓存
  if (finalResp && finalResp.ok) {
    const body = await finalResp.arrayBuffer();
    if (body.byteLength === 0) return handleNwFavicon();

    const iconResponse = new Response(body, {
      status: 200,
      headers: {
        'Content-Type': finalResp.headers.get('Content-Type') || 'image/png',
        'Cache-Control': `public, max-age=${LIMITS.cache.iconTtlSeconds}`,
      },
    });
    await cache.put(cacheKey, iconResponse.clone());
    return iconResponse;
  }

  return handleNwFavicon();
}

export function buildWebBootstrapResponse(env: Env): WebBootstrapResponse {
  const secret = (env.JWT_SECRET || '').trim();
  const jwtUnsafeReason =
    !secret
      ? 'missing'
      : secret === DEFAULT_DEV_SECRET
        ? 'default'
        : secret.length < LIMITS.auth.jwtSecretMinLength
          ? 'too_short'
          : null;

  return {
    defaultKdfIterations: LIMITS.auth.defaultKdfIterations,
    jwtUnsafeReason,
    jwtSecretMinLength: LIMITS.auth.jwtSecretMinLength,
  };
}

export async function handlePublicRoute(
  request: Request,
  env: Env,
  path: string,
  method: string,
  enforcePublicRateLimit: PublicRateLimiter
): Promise<Response | null> {
  if (path === '/.well-known/appspecific/com.chrome.devtools.json' && method === 'GET') {
    return new Response('{}', {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
      },
    });
  }

  if ((path === '/api/web-bootstrap' || path === '/web-bootstrap') && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    return jsonResponse(buildWebBootstrapResponse(env));
  }

  const iconMatch = path.match(/^\/icons\/([^/]+)\/icon\.png$/i);
  if (iconMatch && method === 'GET') {
    return handleWebsiteIcon(iconMatch[1]);
  }

  const publicAttachmentMatch = path.match(/^\/api\/attachments\/([a-f0-9-]+)\/([a-f0-9-]+)$/i);
  if (publicAttachmentMatch && method === 'GET') {
    return handlePublicDownloadAttachment(request, env, publicAttachmentMatch[1], publicAttachmentMatch[2]);
  }

  const publicAttachmentUploadMatch = path.match(/^\/api\/ciphers\/([a-f0-9-]+)\/attachment\/([a-f0-9-]+)$/i);
  if (publicAttachmentUploadMatch && (method === 'POST' || method === 'PUT') && new URL(request.url).searchParams.has('token')) {
    return handlePublicUploadAttachment(request, env, publicAttachmentUploadMatch[1], publicAttachmentUploadMatch[2]);
  }

  const publicSendUploadMatch = path.match(/^\/api\/sends\/([^/]+)\/file\/([^/]+)\/?$/i);
  if (publicSendUploadMatch && (method === 'POST' || method === 'PUT') && new URL(request.url).searchParams.has('token')) {
    return handlePublicUploadSendFile(request, env, publicSendUploadMatch[1], publicSendUploadMatch[2]);
  }

  const sendAccessMatch = path.match(/^\/api\/sends\/access\/([^/]+)$/i);
  if (sendAccessMatch && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSend(request, env, sendAccessMatch[1]);
  }

  if (path === '/api/sends/access' && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSendV2(request, env);
  }

  const sendAccessFileV2Match = path.match(/^\/api\/sends\/access\/file\/([^/]+)\/?$/i);
  if (sendAccessFileV2Match && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSendFileV2(request, env, sendAccessFileV2Match[1]);
  }

  const sendAccessFileMatch = path.match(/^\/api\/sends\/([^/]+)\/access\/file\/([^/]+)\/?$/i);
  if (sendAccessFileMatch && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSendFile(request, env, sendAccessFileMatch[1], sendAccessFileMatch[2]);
  }

  const sendDownloadMatch = path.match(/^\/api\/sends\/([^/]+)\/([^/]+)\/?$/i);
  if (sendDownloadMatch && method === 'GET') {
    return handleDownloadSendFile(request, env, sendDownloadMatch[1], sendDownloadMatch[2]);
  }

  if (path === '/identity/connect/token' && method === 'POST') {
    return handleToken(request, env);
  }

  if (path === '/api/devices/knowndevice' && method === 'GET') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return jsonResponse(false);
    return handleKnownDevice(request, env);
  }

  if ((path === '/identity/connect/revocation' || path === '/identity/connect/revoke') && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleRevocation(request, env);
  }

  if (path === '/identity/accounts/prelogin' && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handlePrelogin(request, env);
  }

  if ((path === '/identity/accounts/recover-2fa' || path === '/api/accounts/recover-2fa') && method === 'POST') {
    return handleRecoverTwoFactor(request, env);
  }

  if (path === '/api/accounts/password-hint' && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    if (!isSameOriginWriteRequest(request)) {
      return new Response(JSON.stringify({ error: 'Forbidden origin' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return handleGetPasswordHint(request, env);
  }

  if ((path === '/config' || path === '/api/config') && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    const origin = new URL(request.url).origin;
    return jsonResponse({
      version: LIMITS.compatibility.bitwardenServerVersion,
      gitHash: 'nodewarden',
      server: null,
      environment: {
        vault: origin,
        api: origin + '/api',
        identity: origin + '/identity',
        notifications: origin + '/notifications',
        icons: origin,
        sso: '',
      },
      _icon_service_url: buildIconServiceTemplate(origin),
      _icon_service_csp: buildIconServiceCsp(origin),
      featureStates: {
        'duo-redirect': true,
        'email-verification': true,
        'pm-19051-send-email-verification': false,
        'unauth-ui-refresh': true,
      },
      object: 'config',
    });
  }

  if (path === '/api/version' && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    return jsonResponse(LIMITS.compatibility.bitwardenServerVersion);
  }

  if (path === '/api/accounts/register' && method === 'POST') {
    const blocked = await enforcePublicRateLimit('register', LIMITS.rateLimit.registerRequestsPerMinute);
    if (blocked) return blocked;
    if (!isSameOriginWriteRequest(request)) {
      return new Response(JSON.stringify({ error: 'Forbidden origin' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return handleRegister(request, env);
  }

  if (path === '/notifications/hub/negotiate' && method === 'POST') {
    return handleNotificationsNegotiate(request, env);
  }

  if (path === '/notifications/hub' && method === 'GET') {
    return handleNotificationsHub(request, env);
  }
  return null;
}
