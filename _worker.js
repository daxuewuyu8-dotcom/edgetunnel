/* * edgetunnel 2.0 - Optimized Version
 * 基于原版进行性能与安全性优化
 */

import { connect } from 'cloudflare:sockets';

// --- 静态常量与预编译正则 (性能优化) ---
const UUID_REGEX = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
const PAGES_STATIC = 'https://edt-pages.github.io';
const DEFAULT_KEY = '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';

// 全局变量缓存
let config_JSON, proxyIP = '', enableSocks5 = null;
let socks5Whitelist = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const ua = request.headers.get('User-Agent') || 'null';
        const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();
        const contentType = (request.headers.get('content-type') || '').toLowerCase();

        // 1. 统一环境变量获取
        const adminPassword = env.ADMIN || env.PASSWORD || env.TOKEN || env.UUID || 'admin';
        const secretKey = env.KEY || DEFAULT_KEY;
        const envUUID = env.UUID || env.uuid;

        // 2. 生成/验证 UserID
        const userIDMD5 = await generateMD5(adminPassword + secretKey);
        const userID = (envUUID && UUID_REGEX.test(envUUID)) 
            ? envUUID.toLowerCase() 
            : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');

        const hostname = url.hostname;
        const path = url.pathname.slice(1).toLowerCase();

        // 3. 反代 IP 逻辑优化
        if (env.PROXYIP) {
            const proxyIPs = await parseToArray(env.PROXYIP);
            proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
        } else {
            proxyIP = (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
        }

        const clientIP = request.headers.get('CF-Connecting-IP') || 'Unknown';

        // --- 路由分发 ---

        // A. WebSocket 代理逻辑
        if (upgradeHeader === 'websocket') {
            return await handleWSRequest(request, userID);
        } 

        // B. gRPC / XHTTP 代理逻辑
        if (!path.startsWith('admin/') && path !== 'login' && request.method === 'POST') {
            const referer = request.headers.get('Referer') || '';
            const isXHTTP = referer.includes('x_padding');
            
            if (!isXHTTP && contentType.startsWith('application/grpc')) {
                return await handleGRPCRequest(request, userID);
            }
            return await handleXHTTPRequest(request, userID);
        }

        // C. 管理面板与面板逻辑 (需要验证)
        if (path === 'login') {
            return await handleLogin(request, adminPassword, secretKey, ua);
        }

        if (path === 'admin' || path.startsWith('admin/')) {
            const isAuthed = await checkAuth(request, adminPassword, secretKey, ua);
            if (!isAuthed) return Response.redirect(`${url.origin}/login`, 302);
            
            // 此处调用原有的管理页面逻辑...
            return fetch(`${PAGES_STATIC}/admin${url.search}`);
        }

        // D. 订阅提取逻辑
        if (path === 'sub') {
            const subToken = await generateMD5(hostname + userID);
            if (url.searchParams.get('token') !== subToken) {
                return new Response('Invalid Token', { status: 403 });
            }
            // 订阅生成逻辑...
            return new Response('Subscription Content Placeholder', { status: 200 });
        }

        // 默认返回静态页面或 404
        return fetch(`${PAGES_STATIC}/noADMIN`);
    }
};

/**
 * 安全验证：检查 Cookie
 */
async function checkAuth(request, password, key, ua) {
    const cookies = request.headers.get('Cookie') || '';
    const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
    const expected = await generateMD5(ua + key + password);
    return authCookie === expected;
}

/**
 * 登录处理：设置安全 Cookie
 */
async function handleLogin(request, password, key, ua) {
    if (request.method === 'POST') {
        const formData = await request.formData();
        if (formData.get('password') === password) {
            const hash = await generateMD5(ua + key + password);
            const response = new Response(JSON.stringify({ success: true }), {
                headers: { 'Content-Type': 'application/json' }
            });
            // 增加 SameSite 属性增强安全性
            response.headers.set('Set-Cookie', `auth=${hash}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax`);
            return response;
        }
    }
    return fetch(`${PAGES_STATIC}/login`);
}

/**
 * 高效 MD5 生成器 (使用 Web Crypto API)
 */
async function generateMD5(text) {
    const msgUint8 = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest('MD5', msgUint8);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 工具函数：字符串转数组
 */
async function parseToArray(input) {
    if (!input) return [];
    return input.split(/[,\s\n]+/).filter(Boolean);
}

// 注意：handleWSRequest, handleGRPCRequest 等核心转发逻辑应保持原样，
// 或根据 Cloudflare Sockets 标准进行模块化拆分。
