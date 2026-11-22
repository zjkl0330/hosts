// 域名白名单配置（仅保留需要的原生域名）
const domain_whitelist = [
  'github.com',
  'avatars.githubusercontent.com',
  'github.githubassets.com',
  'collector.github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'gist.githubusercontent.com',
  'github.io',
  'assets-cdn.github.com',
  'codeload.github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
  'cdn.jsdelivr.net',
  'securitylab.github.com',
  'www.githubstatus.com',
  'npmjs.com',
  'git-lfs.github.com',
  'githubusercontent.com',
  'github.global.ssl.fastly.net',
  'api.npms.io',
  'github.community',
  'desktop.github.com',
  'central.github.com'
];

// 模块加载时构建一次的反查表
// 原始域名 -> 代理标签（github.com 用最短的 gh，其余用 xxx-gh）
const PROXY_LABEL_BY_DOMAIN = new Map(
  domain_whitelist.map(domain => [
    domain,
    domain === 'github.com' ? 'gh' : `${domain.replace(/\./g, '-')}-gh`
  ])
);

// 代理前缀 -> 原始域名（替代每次请求线性遍历白名单）
const HOST_BY_PREFIX = new Map(
  [...PROXY_LABEL_BY_DOMAIN].map(([domain, label]) => [`${label}.`, domain])
);


// 需要重定向的路径（屏蔽海外后可以不填写）
//const redirect_paths = ['/', '/login', '/signup', '/copilot', '/search/custom_scopes', '/session'];
const redirect_paths = [];

// 中国大陆以外的地区重定向到原始GitHub域名
// 已关闭：手机流量出口 IP 常被判定为非 CN，触发重定向后会直连 github.com 导致超时
const enable_geo_redirect = false;

// 边缘缓存时长（秒）：HTML 页面较短以保证内容新鲜度，静态资源较长
// 静态资源路径含内容哈希，长缓存是安全的；缓存越久，重复访问越少打到 Worker，节省请求额度
const CACHE_TTL_HTML = 300;
const CACHE_TTL_ASSET = 30 * 24 * 60 * 60;

// 文本改写的大小上限：超大 JS/CSS/JSON 跳过改写，避免消耗过多 CPU 时间
// （HTML 不受限制，必须改写以保证站内链接走代理）
const MAX_REWRITE_BYTES = 512 * 1024;

// 合并成一条正则：原先 24 个域名 × 2 条规则 = 48 次全文扫描，
// 现在整段文本只扫描 1 次，改写 CPU 消耗下降一个数量级
const DOMAIN_ALTERNATION = domain_whitelist
  .slice()
  .sort((a, b) => b.length - a.length) // 长域名优先，避免被短域名抢先匹配
  .map(d => d.replace(/\./g, '\\.'))
  .join('|');
// 边界判定：域名后面不能紧跟字母数字、点或连字符（保证不误改 github.com.evil.com），
// 但允许 ? # / " ' ) , ; 等任意分隔符——GitHub 的语言切换链接正是 https://github.com?locale=ja 这种形式
const REWRITE_RE = new RegExp(`(https?:)?//(${DOMAIN_ALTERNATION})(?![\\w.-])`, 'g');

// ===== 访问令牌校验 =====
// 令牌值来自 Cloudflare Secret：ACCESS_TOKEN（代码内不含任何口令）
// AUTH_ENABLED 设为 false 可一键关闭全部校验（逃生开关）
// 不内置任何默认口令：ACCESS_TOKEN 必须通过 Secret 提供
const DEFAULT_TOKEN = '';
const COOKIE_NAME = 'zjkl';
const COOKIE_MAX_AGE = 400 * 24 * 60 * 60; // 400 天（主流浏览器上限）
const LOGIN_PATH = '/__zjkl_login';

// ===== 公网 IP 授权：同 IP 下所有设备免输入 =====
// 任何设备在该 IP 下通过一次校验后，记住这个 IP，同 IP 的其他设备直接放行
const IP_GRANT_PATH = '/__ipgrant/';
const DEFAULT_IP_TTL = 7 * 24 * 60 * 60; // 默认 7 天

// 取主域（Cookie 作用域与回跳校验用），兼容 dpdns.org 这类公共后缀
function parentDomain(host) {
  const h = (host || '').split(':')[0].toLowerCase();
  const parts = h.split('.');
  if (parts.length <= 2) return h;
  if (parts.slice(-2).join('.') === 'dpdns.org') return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

function getClientIp(request) {
  return request.headers.get('CF-Connecting-IP') || '';
}

// 用 Cache API 存 IP 凭证：无需新建 KV 命名空间，也不消耗请求额度
function ipGrantKey(ip, base) {
  return new Request(`https://${base}${IP_GRANT_PATH}${encodeURIComponent(ip)}`, { method: 'GET' });
}

async function hasIpGrant(ip, base) {
  if (!ip) return false;
  try {
    const r = await caches.default.match(ipGrantKey(ip, base));
    return !!r;
  } catch (e) {
    return false;
  }
}

function grantIp(ctx, ip, ttl, base) {
  if (!ip || !ctx) return;
  const resp = new Response('1', {
    headers: { 'content-type': 'text/plain', 'cache-control': `public, max-age=${ttl}` }
  });
  ctx.waitUntil(caches.default.put(ipGrantKey(ip, base), resp).catch(() => {}));
}

// 同步写入（登录时使用，便于立即校验写入是否成功）
async function grantIpNow(ip, ttl, base) {
  if (!ip) return false;
  const resp = new Response('1', {
    headers: { 'content-type': 'text/plain', 'cache-control': `public, max-age=${ttl}` }
  });
  try {
    await caches.default.put(ipGrantKey(ip, base), resp);
    return await hasIpGrant(ip, base);
  } catch (e) {
    return false;
  }
}

function getToken(env) {
  const v = env && env.ACCESS_TOKEN;
  return (v && String(v).trim()) || DEFAULT_TOKEN;
}

// 常量时间风格比较，避免逐字符提前返回
function isEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// 读取 Cookie 中的令牌
function readCookieToken(request) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)zjkl=([^;]*)/);
  return m ? decodeURIComponent(m[1]) : null;
}

function authCookie(value, base) {
  return `${COOKIE_NAME}=${encodeURIComponent(value)}; Domain=.${base}; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Lax`;
}

// 校验请求是否已授权；返回 { ok, via, stripPrefix }
function checkAuth(request, url, token) {
  // 1) 请求头（git / curl / 命令行）
  const hdr = request.headers.get('X-ZJKL') || request.headers.get('X-Zjkl-Token');
  if (hdr && isEqual(hdr.trim(), token)) return { ok: true, via: 'header' };

  // 2) Cookie（浏览器，一次授权长期有效）
  const ck = readCookieToken(request);
  if (ck && isEqual(ck, token)) return { ok: true, via: 'cookie' };

  // 3) 路径前缀 /令牌/...
  const seg = url.pathname.split('/')[1] || '';
  let decoded_seg = seg;
  try { decoded_seg = decodeURIComponent(seg); } catch (e) { decoded_seg = seg; }
  if (decoded_seg && isEqual(decoded_seg, token)) return { ok: true, via: 'path', stripPrefix: true };

  // 4) 查询参数（仅用于首次引导，避免出现在 Referer）
  const q = url.searchParams.get('zjkl');
  if (q && isEqual(q, token)) return { ok: true, via: 'query', stripQuery: true };

  // 5) 路径尾部 ≡令牌（用户习惯的快捷写法；浏览器会把 ≡ 编码成 %E2%89%A1，两种形式都认）
  let decoded_path = url.pathname;
  try { decoded_path = decodeURIComponent(url.pathname); } catch (e) { decoded_path = url.pathname; }
  if (token && decoded_path.endsWith(`≡${token}`)) return { ok: true, via: 'suffix', stripSuffix: true };

  return { ok: false };
}

// 未授权导航请求：显示登录页（记住原地址，登录后回跳）
function loginPage(next, isPostError) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>需要访问密钥</title>
<style>
body{font-family:-apple-system,system-ui,"Segoe UI",sans-serif;background:#0d1117;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
.box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:28px;width:min(90vw,360px)}
h1{font-size:18px;margin:0 0 6px}p{color:#8b949e;font-size:13px;margin:0 0 18px;line-height:1.5}
input{width:100%;box-sizing:border-box;padding:11px 12px;border-radius:8px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;font-size:15px;margin-bottom:14px}
input:focus{outline:none;border-color:#1f6feb}
button{width:100%;padding:11px;border:none;border-radius:8px;background:#238636;color:#fff;font-size:15px;font-weight:600;cursor:pointer}
button:active{background:#1f7a2f}
.err{color:#f85149;font-size:13px;margin:0 0 12px}
</style></head><body>
<div class="box">
<h1>需要访问密钥</h1>
<p>该代理已开启访问保护，输入密钥后本设备将长期免输入。</p>
${isPostError ? '<p class="err">密钥不正确，请重新输入</p>' : ''}
<form method="POST" action="${LOGIN_PATH}">
<input type="hidden" name="next" value="${next.replace(/"/g, '&quot;')}">
<input type="password" name="t" placeholder="访问密钥" autocomplete="current-password" autofocus required>
<button type="submit">进入</button>
</form>
</div></body></html>`;
  return new Response(html, {
    status: 401,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-zjkl': 'unauthorized'
    }
  });
}

// 仅允许跳回本域，防止开放重定向
function safeNext(next, fallbackHost) {
  const base = parentDomain(fallbackHost);
  if (!next || typeof next !== 'string') return `https://${fallbackHost}/`;
  try {
    const u = new URL(next, `https://${fallbackHost}`);
    if (!u.host.endsWith(base)) return `https://${fallbackHost}/`;
    return u.href;
  } catch (e) {
    return `https://${fallbackHost}/`;
  }
}

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  // 统一转小写
  const current_host = url.host.toLowerCase();
  const host_header = request.headers.get('Host');
  const effective_host = (host_header || current_host).toLowerCase();

  // ===== 令牌校验（在缓存之前，避免未授权者白嫖缓存）=====
  const authEnabled = String((env && env.AUTH_ENABLED) || 'true').toLowerCase() !== 'false';
  const token = getToken(env);
  const ipAuthEnabled = String((env && env.IP_AUTH_ENABLED) || 'true').toLowerCase() !== 'false';
  const ipTtlRaw = parseInt((env && env.IP_AUTH_TTL) || '', 10);
  const ipTtl = ipTtlRaw > 0 ? ipTtlRaw : DEFAULT_IP_TTL;
  const clientIp = getClientIp(request);
  const baseDomain = parentDomain(effective_host);

  // 未配置密钥时拒绝服务（fail-closed），避免无保护裸奔
  if (authEnabled && !token) {
    return new Response('配置错误：未设置 ACCESS_TOKEN 密钥。\n请执行 npx wrangler secret put ACCESS_TOKEN，或在 Cloudflare 面板的变量和机密中添加。\n', {
      status: 500,
      headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }
    });
  }

  // 内部凭证路径不对用户开放
  if (url.pathname.startsWith(IP_GRANT_PATH)) {
    return new Response('Not Found', { status: 404, headers: { 'cache-control': 'no-store' } });
  }

  // 登录表单提交
  if (url.pathname === LOGIN_PATH) {
    let next = '/';
    let submitted = '';
    if (request.method === 'POST') {
      const form = await request.formData();
      next = form.get('next') || '/';
      submitted = String(form.get('t') || '').trim();
    } else {
      next = url.searchParams.get('next') || '/';
      submitted = String(url.searchParams.get('t') || '').trim();
    }
    if (isEqual(submitted, token)) {
      // 登录成功：同时记住该公网 IP，让同 IP 的其他设备免输入
      const granted = ipAuthEnabled ? await grantIpNow(clientIp, ipTtl, baseDomain) : false;
      return new Response(null, {
        status: 302,
        headers: {
          location: safeNext(next, effective_host),
          'set-cookie': authCookie(submitted, baseDomain),
          'cache-control': 'no-store',
          'x-zjkl-ip': clientIp,
          'x-zjkl-grant': granted ? 'ok' : 'fail'
        }
      });
    }
    return loginPage(String(next), request.method === 'POST');
  }

  let auth = { ok: true };
  if (authEnabled) {
    auth = checkAuth(request, url, token);
    // 令牌未命中时，回退到公网 IP 授权（同 IP 的其他设备无需输入密钥）
    if (!auth.ok && ipAuthEnabled && clientIp && await hasIpGrant(clientIp, baseDomain)) {
      auth = { ok: true, via: 'ip' };
    }
    if (!auth.ok) {
      // 导航请求给登录页；子资源/git 等给 401 提示
      const dest = request.headers.get('Sec-Fetch-Dest') || '';
      const accept = request.headers.get('Accept') || '';
      const isNavigation = dest === 'document' || (accept.includes('text/html') && !dest);
      if (isNavigation) {
        const r = loginPage(url.href, false);
        r.headers.set('x-zjkl-ip', clientIp);
        r.headers.set('x-zjkl-ipauth', ipAuthEnabled ? 'on' : 'off');
        return r;
      }
      return new Response('401 Unauthorized: 需要在浏览器中先完成一次授权\n', {
        status: 401,
        headers: {
          'content-type': 'text/plain; charset=utf-8',
          'cache-control': 'no-store',
          'www-authenticate': 'ZJKL realm="gh proxy"',
          'x-zjkl-ip': clientIp
        }
      });
    }
    // 路径前缀 /令牌 剥离，避免污染缓存键和转发路径
    if (auth.stripPrefix) {
      const stripped = url.pathname.replace(/^\/[^/]+/, '') || '/';
      url.pathname = stripped;
    }
    if (auth.stripQuery) {
      url.searchParams.delete('zjkl');
    }
    if (auth.stripSuffix) {
      // 尾部记号可能是原文 ≡ 也可能被编码成 %E2%89%A1，统一按解码后的路径裁剪再写回
      let decoded = url.pathname;
      try { decoded = decodeURIComponent(url.pathname); } catch (e) { decoded = url.pathname; }
      const suffix = `≡${token}`;
      url.pathname = (decoded.endsWith(suffix) ? decoded.slice(0, -suffix.length) : decoded) || '/';
    }
    // 用一次性记号（?zjkl= 或尾部 ≡zjkl）进入时：下发 Cookie 并跳转到去掉记号的干净地址，
    // 令牌不再留在地址栏/历史里，后续导航也无需再带记号
    if (auth.via === 'query' || auth.via === 'suffix') {
      return new Response(null, {
        status: 302,
        headers: {
          location: url.href,
          'set-cookie': authCookie(token, baseDomain),
          'cache-control': 'no-store'
        }
      });
    }
    // 通过 Cookie / 路径 / 查询参数授权时，顺手把该公网 IP 登记为可信，
    // 这样同 IP 下的其他设备（没有 Cookie）也能直接进入
    if (ipAuthEnabled && clientIp && auth.via !== 'ip' && auth.via !== 'header') {
      const dest = request.headers.get('Sec-Fetch-Dest') || '';
      const accept = request.headers.get('Accept') || '';
      if (dest === 'document' || accept.includes('text/html')) {
        grantIp(ctx, clientIp, ipTtl, baseDomain);
      }
    }
  }
  
  // 检查是否需要重定向到原始GitHub（非中国用户）
  if (enable_geo_redirect) {
    const country = request.headers.get('CF-IPCountry') || '';
    // 调试：打印国家信息
    // console.log('Country:', country);
    if (country && country !== 'CN') {
      // 提取原始GitHub域名
      const host_prefix = getProxyPrefix(effective_host);
      if (host_prefix) {
        const target_host = resolveTargetHost(host_prefix);
        if (target_host) {
          const original_url = new URL(request.url);
          original_url.host = target_host;
          original_url.protocol = 'https:';
          return Response.redirect(original_url.href, 302);
        }
      }
    }
  }
  
  // 检查特殊路径，返回正常错误
  if (redirect_paths.includes(url.pathname)) {
    return new Response('Not Found', { status: 404 });
  }

  // 强制使用 HTTPS
  if (url.protocol === 'http:') {
    url.protocol = 'https:';
    return Response.redirect(url.href);
  }

  // 边缘缓存：命中直接返回，避免每次回源 GitHub
  // 缓存键使用剥离令牌后的干净 URL，保证所有授权方式共享同一份缓存
  const can_cache = request.method === 'GET';
  // 带 Range 的请求（断点续传、多线程下载器）不能走缓存：
  // Cache API 无法按范围切片，若返回缓存的完整 200 响应，续传会变成"从头重下"，
  // 分段请求也会失效，下载器的多线程加速同样用不了
  const has_range = request.headers.has('range');
  const edge_cache = caches.default;
  const cache_key = new Request(url.href, { method: 'GET' });
  if (can_cache && !has_range) {
    const cached_response = await edge_cache.match(cache_key);
    if (cached_response) {
      const hit_headers = new Headers(cached_response.headers);
      hit_headers.set('x-edge-cache', 'HIT');
      return new Response(cached_response.body, {
        status: cached_response.status,
        headers: hit_headers
      });
    }
  }

  // 从有效主机名中提取前缀
  const host_prefix = getProxyPrefix(effective_host);
  if (!host_prefix) {
    return new Response(`Domain not configured for proxy. Host: ${effective_host}, Prefix check failed`, { status: 404 });
  }

  // 根据前缀找到对应的原始域名
  const target_host = resolveTargetHost(host_prefix);
  if (!target_host) {
    return new Response(`Domain not configured for proxy. Host: ${effective_host}, Prefix: ${host_prefix}, Target lookup failed`, { status: 404 });
  }

  // 直接使用正则表达式处理最常见的嵌套URL问题
  let pathname = url.pathname;
  
  // 修复特定的嵌套URL模式 - 直接移除嵌套URL部分
  // 匹配 /xxx/xxx/latest-commit/main/https%3A//gh.xxx.xxx/ 或 /xxx/xxx/tree-commit-info/main/https%3A//gh.xxx.xxx/
  pathname = pathname.replace(/(\/[^\/]+\/[^\/]+\/(?:latest-commit|tree-commit-info)\/[^\/]+)\/https%3A\/\/[^\/]+\/.*/, '$1');
  
  // 同样处理非编码版本
  pathname = pathname.replace(/(\/[^\/]+\/[^\/]+\/(?:latest-commit|tree-commit-info)\/[^\/]+)\/https:\/\/[^\/]+\/.*/, '$1');

  // 构建新的请求URL
  const new_url = new URL(url);
  new_url.host = target_host;
  new_url.pathname = pathname;
  new_url.protocol = 'https:';

  // 设置新的请求头
  const new_headers = new Headers(request.headers);
  new_headers.set('Host', target_host);
  new_headers.set('Referer', new_url.href);
  // 强制要求源站返回未压缩的内容，确保我们可以正常修改文本
  new_headers.delete('accept-encoding');

  // 向上游转发前剔除本代理自己的授权 Cookie，避免密钥泄露给第三方
  const upstream_cookie = new_headers.get('cookie');
  if (upstream_cookie && upstream_cookie.indexOf(`${COOKIE_NAME}=`) !== -1) {
    const kept = upstream_cookie
      .split(';')
      .filter(pair => !pair.trim().startsWith(`${COOKIE_NAME}=`))
      .join(';')
      .trim();
    if (kept) new_headers.set('cookie', kept);
    else new_headers.delete('cookie');
  }
  
  try {
    // 发起请求
    let response = await fetch(new_url.href, {
      method: request.method,
      headers: new_headers,
      body: request.method !== 'GET' ? request.body : undefined,
      redirect: 'manual' // 处理重定向，避免自动跟随导致的问题
      // 注意：不使用 cf.cacheEverything，避免把源站临时的 404/错误页也缓存住
    });

    // 处理重定向
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (location) {
        // 下载加速：releases/download 等跳转目标是带签名的资源 URL（每次不同），
        // 若让浏览器跟随，签名 URL 作为缓存键将永远无法命中边缘缓存，每次下载都完整回源。
        // 这里改为在 Worker 内部跟随一次重定向，最终文件以原始稳定 URL 写入边缘缓存。
        let loc = null;
        try { loc = new URL(location); } catch (e) { loc = null; }
        if (can_cache && loc && domain_whitelist.includes(loc.host.toLowerCase())) {
          const follow_headers = new Headers(new_headers);
          follow_headers.set('Host', loc.host);
          follow_headers.set('Referer', loc.href);
          response = await fetch(loc.href, {
            method: 'GET',
            headers: follow_headers,
            redirect: 'manual'
          });
        }
        // 若内部跟随后的响应仍是重定向（多跳），按原逻辑改写 Location 交给浏览器
        if ([301, 302, 303, 307, 308].includes(response.status)) {
          const next_location = response.headers.get('location');
          if (next_location) {
            const modified_location = modifyUrl(next_location, host_prefix, effective_host);
            const new_res_headers = new Headers(response.headers);
            new_res_headers.set('location', modified_location);
            return new Response(null, {
              status: response.status,
              headers: new_res_headers
            });
          }
        }
      }
    }

    // 设置新的响应头
    const new_response_headers = new Headers(response.headers);
    new_response_headers.set('access-control-allow-origin', '*');
    new_response_headers.set('access-control-allow-credentials', 'true');
    new_response_headers.delete('content-security-policy');
    new_response_headers.delete('content-security-policy-report-only');
    new_response_headers.delete('clear-site-data');

    // 只处理 200 OK 且是文本类型的响应内容
    const content_type = response.headers.get('content-type') || '';
    const is_text = content_type.includes('text/') || 
                    content_type.includes('application/json') || 
                    content_type.includes('application/javascript') || 
                    content_type.includes('application/xml');

    // 缓存时长：HTML 5 分钟（兼顾内容新鲜度），其他静态资源 1 天
    const is_html = content_type.includes('text/html');
    if (response.status === 200) {
      new_response_headers.set('cache-control', `public, max-age=${is_html ? CACHE_TTL_HTML : CACHE_TTL_ASSET}`);
      new_response_headers.set('x-edge-cache', 'MISS');
    }

    // 已授权访问时顺带续期 Cookie（滑动过期），保证设备长期免输入
    if (authEnabled && auth.ok && auth.via === 'cookie' && is_html) {
      new_response_headers.append('set-cookie', authCookie(token, baseDomain));
    }

    // 大文件跳过文本改写以节省 CPU：HTML 必须改写，其余超过上限的直接透传
    const declared_length = parseInt(response.headers.get('content-length') || '0', 10);
    const rewrite_ok = is_html || !declared_length || declared_length <= MAX_REWRITE_BYTES;

    let final_response;
    if (response.status === 200 && is_text && rewrite_ok) {
      // 如果要修改内容，必须移除这些头，因为内容会被解压且长度会变化
      new_response_headers.delete('content-encoding');
      new_response_headers.delete('content-length');

      let text = await response.text();
      text = modifyText(text, host_prefix, effective_host);

      final_response = new Response(text, {
        status: response.status,
        headers: new_response_headers
      });
    } else {
      // 对于非文本或非 200 响应，直接返回原始流
      final_response = new Response(response.body, {
        status: response.status,
        headers: new_response_headers
      });
    }

    // 写入边缘缓存（仅缓存 GET 200；删除 Set-Cookie，避免把个人会话信息缓存给其他访客）
    if (can_cache && !has_range && response.status === 200 && ctx) {
      const cached_copy = final_response.clone();
      cached_copy.headers.delete('set-cookie');
      ctx.waitUntil(edge_cache.put(cache_key, cached_copy).catch(() => {}));
    }

    return final_response;
  } catch (err) {
    return new Response(`Proxy Error: ${err.message}`, { status: 502 });
  }
}

// 获取当前主机名的前缀，用于匹配反向映射
function getProxyPrefix(host) {
  // 短前缀模式：gh. -> github.com 主站
  if (host.startsWith('gh.')) {
    return 'gh.';
  }

  // 检查 *-gh. 模式
  const ghMatch = host.match(/^([a-z0-9-]+-gh\.)/);
  if (ghMatch) {
    return ghMatch[1];
  }

  return null;
}

// 根据主机前缀解析目标 GitHub 域名
function resolveTargetHost(host_prefix) {
  // 短前缀 gh. -> github.com，其余 *-gh. -> 对应原始域名，均为模块级查表
  return HOST_BY_PREFIX.get(host_prefix) || null;
}

// 修改文本中的域名引用
function modifyText(text, host_prefix, effective_hostname) {
  const domain_suffix = effective_hostname.substring(host_prefix.length);

  // 单次扫描完成全部域名替换
  return text.replace(REWRITE_RE, (match, scheme, domain) => {
    const label = PROXY_LABEL_BY_DOMAIN.get(domain);
    if (!label) return match;
    // 带协议的统一升级为 https，协议相对的保持相对
    return `${scheme ? 'https://' : '//'}${label}.${domain_suffix}`;
  });
}

// 修改 URL（用于重定向等）
function modifyUrl(url_str, host_prefix, effective_hostname) {
  try {
    const url = new URL(url_str);
    const label = PROXY_LABEL_BY_DOMAIN.get(url.hostname.toLowerCase());
    if (!label) return url_str;
    url.host = `${label}.${effective_hostname.substring(host_prefix.length)}`;
    return url.href;
  } catch (e) {
    return url_str;
  }
}
