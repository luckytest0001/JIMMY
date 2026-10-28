/**
 * =====================================================================
 * CLOUDFLARE WORKER IPTV STREAM & CORS PROXY (क्लाउडफ्लेयर प्रॉक्सी)
 * =====================================================================
 * Free Cloudflare Worker for hosting IPTV Player on Cloudflare Pages or GitHub Pages.
 * 
 * FEATURES:
 * 1. 100% Free Forever (100,000 requests per day on Cloudflare Workers free plan).
 * 2. Rewrites M3U8 playlists & encryption keys so relative TS segments stream through proxy.
 * 3. Injects custom User-Agent (VLC/MAG STB), Referer, and Stalker MAC cookies.
 * 4. Adds full CORS headers (Access-Control-Allow-Origin: *) and Range seek support.
 * 5. Works on both standalone Workers (workers.dev) and Cloudflare Pages (*.pages.dev).
 * =====================================================================
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Expose-Headers': '*',
  'Access-Control-Max-Age': '86400',
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS,
      });
    }

    // 2. Health check / probe endpoint for the web app
    if (
      url.pathname.endsWith('/probe') ||
      url.pathname.endsWith('/health') ||
      url.pathname.endsWith('/ping')
    ) {
      return new Response(
        JSON.stringify({ status: 'ok', proxy: 'cloudflare-worker', time: Date.now() }),
        {
          headers: {
            'Content-Type': 'application/json',
            ...CORS_HEADERS,
          },
        }
      );
    }

    // 3. Extract target URL from query parameter: ?url=http://... or path
    let targetUrl = url.searchParams.get('url') || url.searchParams.get('target');
    if (!targetUrl) {
      // Support path-based proxying: /api/proxy/http://... or /proxy/http://...
      const match = url.pathname.match(/^\/(?:api\/)?(?:proxy|stream|m3u8-proxy)\/(https?:\/.+)$/i);
      if (match) {
        targetUrl = match[1].replace(/^(https?:\/)(?=[^/])/, '$1/');
      }
    }

    if (!targetUrl || !/^https?:\/\//i.test(targetUrl.trim())) {
      return new Response(
        'Cloudflare Worker IPTV Proxy is running!\n\nUsage: /api/proxy?url=http://example.com/live/channel.m3u8\nor: /?url=http://example.com/live/channel.m3u8\n',
        {
          status: 200,
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            ...CORS_HEADERS,
          },
        }
      );
    }

    targetUrl = targetUrl.trim();

    // 4. Extract custom IPTV authentication parameters
    const customUa =
      url.searchParams.get('ua') ||
      url.searchParams.get('userAgent') ||
      request.headers.get('User-Agent') ||
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';
    const customRef = url.searchParams.get('ref') || url.searchParams.get('referer');
    const customMac = url.searchParams.get('mac') || url.searchParams.get('macAddress');
    const customCookie = url.searchParams.get('cookie') || url.searchParams.get('cookies');
    const customAuth = url.searchParams.get('auth') || url.searchParams.get('authToken');

    const headers = new Headers();
    headers.set('User-Agent', customUa);
    headers.set('Accept', '*/*');
    if (customRef) {
      headers.set('Referer', customRef);
    }

    // Assemble cookies for Stalker / Ministra portals
    const cookieParts = [];
    if (customMac) {
      cookieParts.push(`mac=${customMac}`);
      cookieParts.push(`stb_sn=${customMac.replace(/[^a-zA-Z0-9]/g, '')}`);
    }
    if (customAuth) {
      cookieParts.push(`token=${customAuth}`);
    }
    if (customCookie) {
      cookieParts.push(customCookie);
    }
    if (cookieParts.length > 0) {
      headers.set('Cookie', cookieParts.join('; '));
    }

    // Forward Range header for video seeking
    const range = request.headers.get('Range');
    if (range) {
      headers.set('Range', range);
    }

    try {
      const response = await fetch(targetUrl, {
        method: request.method === 'HEAD' ? 'HEAD' : 'GET',
        headers,
        redirect: 'follow',
      });

      const responseHeaders = new Headers(response.headers);
      for (const [k, v] of Object.entries(CORS_HEADERS)) {
        responseHeaders.set(k, v);
      }

      const contentType = (response.headers.get('content-type') || '').toLowerCase();
      const isM3u8 =
        targetUrl.includes('.m3u8') ||
        contentType.includes('application/vnd.apple.mpegurl') ||
        contentType.includes('application/x-mpegurl') ||
        url.pathname.includes('/m3u8-proxy');

      // 5. Rewrite M3U8 playlists so all relative chunks route through this worker
      if (isM3u8 && response.ok && request.method !== 'HEAD') {
        const text = await response.text();
        const workerOrigin = url.origin;
        const proxyPrefix = url.pathname.startsWith('/api/') ? `${workerOrigin}/api/proxy` : `${workerOrigin}/`;
        const authSuffix = [];
        if (customUa) authSuffix.push(`ua=${encodeURIComponent(customUa)}`);
        if (customRef) authSuffix.push(`ref=${encodeURIComponent(customRef)}`);
        if (customMac) authSuffix.push(`mac=${encodeURIComponent(customMac)}`);
        if (customCookie) authSuffix.push(`cookie=${encodeURIComponent(customCookie)}`);
        if (customAuth) authSuffix.push(`auth=${encodeURIComponent(customAuth)}`);
        const qsExtra = authSuffix.length > 0 ? `&${authSuffix.join('&')}` : '';

        const rewritten = text
          .split(/\r?\n/)
          .map((line) => {
            const trimmed = line.trim();
            if (!trimmed) return line;

            // Rewrite encryption key URI
            if (trimmed.startsWith('#EXT-X-KEY:')) {
              return trimmed.replace(/URI=["']([^"']+)["']/i, (_m, keyUri) => {
                try {
                  const abs = new URL(keyUri, targetUrl).href;
                  return `URI="${proxyPrefix}?url=${encodeURIComponent(abs)}${qsExtra}"`;
                } catch {
                  return `URI="${keyUri}"`;
                }
              });
            }

            // Keep comments / tags
            if (trimmed.startsWith('#')) return line;

            // Rewrite relative or absolute segment URI
            try {
              const abs = new URL(trimmed, targetUrl).href;
              return `${proxyPrefix}?url=${encodeURIComponent(abs)}${qsExtra}`;
            } catch {
              return line;
            }
          })
          .join('\n');

        responseHeaders.set('Content-Type', 'application/vnd.apple.mpegurl');
        responseHeaders.delete('content-length');
        return new Response(rewritten, {
          status: response.status,
          headers: responseHeaders,
        });
      }

      // Stream media binary directly
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (err) {
      return new Response(
        JSON.stringify({
          error: 'Proxy Error',
          message: err?.message || String(err),
          targetUrl,
        }),
        {
          status: 502,
          headers: {
            'Content-Type': 'application/json',
            ...CORS_HEADERS,
          },
        }
      );
    }
  },
};
