/**
 * Cloudflare Worker Proxy Aggregator & Converter
 * Refactored for modularity, performance, and readability.
 */

// ==========================================
// 1. 配置与常量 (Configuration & Constants)
// ==========================================

const DEFAULT_CONFIG = {
    SIGNING_SECRET: "", // 🔴【重要】请务必修改并在 Env 设置此密钥！建议使用UUID生成，它也是你的后台管理入口路径
    DEFAULT_UA: "Mozilla/5.0 Chrome/131.0.0.0",
    KV_TTL: 60, // KV 缓存时间 (秒)
    FETCH_TIMEOUT: 8000,
    SUB_CONVERTER_TIMEOUT: 16000,
};

// 混淆的字符串常量
const OBFUSCATED = {
    // Clients
    CL: ['\x59\x32\x78\x68\x63\x32\x67\x3d', '\x62\x57\x56\x30\x59\x51\x3d\x3d', '\x62\x57\x6c\x6f\x62\x32\x31\x76'].map(atob),
    SB: ['\x63\x32\x6c\x75\x5a\x32\x4a\x76\x65\x41\x3d\x3d', '\x63\x32\x6c\x75\x5a\x79\x31\x69\x62\x33\x67\x3d', '\x63\x32\x49\x3d'].map(atob),
    SU: ['\x63\x33\x56\x79\x5a\x32\x55\x3d'].map(atob),
    QU: ['\x63\x58\x56\x68\x62\x6e\x67\x3d', '\x63\x58\x56\x68\x62\x67\x3d\x3d'].map(atob),
    LO: ['\x62\x47\x39\x76\x62\x67\x3d\x3d'].map(atob),
    SF: ['\x63\x33\x56\x79\x5a\x6d\x4a\x76\x59\x58\x4a\x6b'].map(atob),

    // Protocols
    VM: atob('\x64\x6d\x31\x6c\x63\x33\x4d\x3d'),
    S5: atob('\x63\x33\x4d\x3d'),

    // URLs (Defaults)
    SUB_CONFIG: atob('\x61\x48\x52\x30\x63\x48\x4d\x36\x4c\x79\x39\x79\x59\x58\x63\x75\x5a\x32\x6c\x30\x61\x48\x56\x69\x64\x58\x4e\x6c\x63\x6d\x4e\x76\x62\x6e\x52\x6c\x62\x6e\x51\x75\x59\x32\x39\x74\x4c\x30\x46\x44\x54\x44\x52\x54\x55\x31\x49\x76\x51\x55\x4e\x4d\x4e\x46\x4e\x54\x55\x69\x39\x79\x5a\x57\x5a\x7a\x4c\x32\x68\x6c\x59\x57\x52\x7a\x4c\x32\x31\x68\x63\x33\x52\x6c\x63\x69\x39\x44\x62\x47\x46\x7a\x61\x43\x39\x6a\x62\x32\x35\x6d\x61\x57\x63\x76\x51\x55\x4e\x4d\x4e\x46\x4e\x54\x55\x6c\x39\x50\x62\x6d\x78\x70\x62\x6d\x55\x75\x61\x57\x35\x70'),
    SUB_BACKEND: atob('\x61\x48\x52\x30\x63\x48\x4d\x36\x4c\x79\x39\x68\x63\x47\x6b\x75\x64\x6a\x45\x75\x62\x57\x73\x3d'), // 示例后端
    RAY_CONFIG: atob('\x64\x6a\x4a\x79\x59\x58\x6c\x75\x4c\x6e\x68\x79\x59\x58\x6b\x3d'),
};

// ==========================================
// 2. 主入口 (Entry Point)
// ==========================================

export default {
    async fetch(request, env, ctx) {
        try {
            if (!env.LINKS) {
                throw new Error('KV Namespace "LINKS" is not bound.');
            }
            if (!env.MASKED_KV) {
                throw new Error('KV Namespace "MASKED_KV" is not bound.');
            }

            const url = new URL(request.url);
            const path = url.pathname.replace(/\/+$/, '') || '/';
            const SIGNING_SECRET = env.SIGNING_SECRET || DEFAULT_CONFIG.SIGNING_SECRET;
            if (!SIGNING_SECRET) {
                throw new Error('ENV SIGNING_SECRET is not bound.');
            }

            // 依赖注入 Env 和 Ctx
            const context = { request, env, ctx, url };

            switch (path) {
                case "/dashboard":
                    // 鉴权
                    const auth = await AuthService.guard(url, SIGNING_SECRET);
                    // 如果没有 Token，拒绝
                    if (auth.err) return auth.err;
                    url.searchParams.delete("target");
                    return new Response(generateHtml(`${url.origin}/resource`, url.searchParams.toString()), {
                        headers: { "Content-Type": "text/html;charset=UTF-8" }
                    });
                case `/${SIGNING_SECRET}`:
                    // 获取过期时间参数，默认为 0 无限期
                    const ttl = Number(url.searchParams.get("ttl")) || 0;
                    // 生成 Token
                    const t = await AuthService.signToken({
                        masked_key: "", // 初始生成时不带 mask_key
                    }, SIGNING_SECRET, ttl);
                    url.searchParams.set("token", t);
                    url.searchParams.delete("target");
                    return new Response(generateHtml(`${url.origin}/resource`, url.searchParams.toString(), SIGNING_SECRET), {
                        headers: { "Content-Type": "text/html;charset=UTF-8" }
                    });
                case "/resource":
                    return await ProxyController.handleResource(context);
                case '/api/get-links':
                    try {
                        const { secret } = await request.json();
                        if (secret !== SIGNING_SECRET) return new Response("401", { status: 401 });
                        // 获取 KV 中的原始链接文本
                        const rawLinks = await env.LINKS.get("LINKS") || "";
                        return new Response(JSON.stringify({ content: rawLinks }), {
                            headers: { "Content-Type": "application/json" }
                        });
                    } catch (e) { return new Response("Error", { status: 400 }); }
                case '/api/update-links':
                    // 更新 KV 中的链接文本 (建议增加密码校验)
                    if (request.method !== 'POST') return new Response("Method Not Allowed", { status: 405 });
                    const { content, secret } = await request.json();
                    // 简单的安全校验：检查提交的 secret 是否匹配你的配置
                    if (secret !== SIGNING_SECRET) return new Response("Unauthorized", { status: 401 });

                    await env.LINKS.put("LINKS", content);
                    return new Response(JSON.stringify({ success: true }), {
                        headers: { "Content-Type": "application/json" }
                    });
                default:
                    return new Response(htmlNginxWelcome(), {
                        status: 200,
                        headers: { 'Content-Type': 'text/html; charset=UTF-8' },
                    });
            }
        } catch (err) {
            return new Response(err.stack || err.toString(), {
                status: 500,
                headers: { "Content-Type": "text/plain; charset=utf-8" }
            });
        }
    }
};

// ==========================================
// 3. 控制器层 (Controllers)
// ==========================================

const ProxyController = {
    async handleResource({ request, url, env, ctx }) {
        const secret = env.SIGNING_SECRET || DEFAULT_CONFIG.SIGNING_SECRET;
        // 1. 鉴权
        const auth = await AuthService.guard(url, secret);
        // 如果没有 Token，拒绝
        if (auth.err) return auth.err;

        // 2. 确定目标客户端类型
        const ua = (request.headers.get('User-Agent') || '').toLowerCase();
        const targetType = Utils.detectTargetType(url.searchParams, ua);

        // 3. 检查是否是 Subconverter 的回调请求 (已混淆的数据)
        // 如果 payload 中没有 masked_key，说明这是第一层请求，需要我们去抓取并混淆
        // 如果 target_common 包含当前类型，说明需要调用 subconverter
        const isRawRequest = targetType === 'raw' || targetType === 'mixed';
        const needsConverter = !isRawRequest && !auth.payload.masked_key;

        if (needsConverter) {
            return await SubconverterService.requestConversion(targetType, url, env, secret, auth.payload);
        }

        // 4. 处理核心代理链接 (抓取 -> 解析 -> 去重)
        // 获取原始链接配置
        const linksConfig = await env.LINKS.get("LINKS");
        if (!linksConfig?.trim()) return new Response("", { status: 200 });

        // 递归抓取并解析所有节点
        const rawProxies = await ProxyService.fetchAndParse(linksConfig, auth.payload.masked_key, env.MASKED_KV);

        // 5. 去重与格式化
        const uniqueLinks = ProxyService.deduplicate(rawProxies);
        const responseBody = uniqueLinks.join('\n');

        return new Response(targetType === "raw" ? responseBody : Utils.base64Encode(responseBody), {
            status: 200,
            headers: { "Content-Type": "text/plain; charset=utf-8" },
        });
    }
};

// ==========================================
// 4. 服务层 (Services)
// ==========================================

const AuthService = {
    async signToken(data, secret, ttl) {
        const payload = {
            ...data,
            exp: ttl !== 0 ? Date.now() + (ttl * 1000) : 0,
            nonce: crypto.getRandomValues(new Uint8Array(5)).join("") // 增加一点随机性
        };
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey(
            "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
        );
        const payloadStr = Utils.base64UrlEncode(JSON.stringify(payload));
        const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(payloadStr));
        const sigStr = Utils.base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
        return `${payloadStr}.${sigStr}`;
    },

    async verifyToken(token, secret) {
        try {
            const [payloadStr, sigStr] = token.split('.');
            if (!payloadStr || !sigStr) return null;

            const encoder = new TextEncoder();
            const key = await crypto.subtle.importKey(
                "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
            );

            const isValid = await crypto.subtle.verify(
                "HMAC", key,
                Uint8Array.from(Utils.base64UrlDecode(sigStr), c => c.charCodeAt(0)),
                encoder.encode(payloadStr)
            );

            if (!isValid) return null;
            return JSON.parse(Utils.base64UrlDecode(payloadStr));
        } catch (e) {
            return null;
        }
    },

    // 鉴权守卫
    async guard(url, secret) {
        const t = url.searchParams.get("token");
        if (!t) return { err: new Response("Missing Token", { status: 401 }) };

        const p = await this.verifyToken(t, secret);
        if (!p) return { err: new Response("Invalid Token", { status: 403 }) };

        // 核心逻辑：exp > 0 才检查过期，= 0 为永久
        if (p.exp > 0 && Date.now() > p.exp) return { err: new Response("Expired Token", { status: 403 }) };

        return { payload: p };
    }
};

const ProxyService = {
    /**
     * 递归抓取链接并解析
     */
    async fetchAndParse(configStr, maskKey, kvNamespace) {
        const visitedUrls = new Set();
        // 第一步：递归获取所有原始文本行
        const rawLines = await this._recursiveFetch(configStr, visitedUrls);

        // 第二步：解析每一行为具体的代理对象，并进行混淆处理
        // 注意：maskKey 为空时不混淆，有值时混淆并存入 Map
        const maskMap = new Map();
        const proxyPromises = rawLines.map(line =>
            ProtocolParser.parse(line, maskKey, maskMap)
        );

        const proxies = (await Promise.allSettled(proxyPromises))
            .map(r => r.status === 'fulfilled' ? r.value : null)
            .filter(p => p !== null); // 这样编辑器绝对不会再报错，因为 null 已经被排除了
        // .filter(r => r.status === 'fulfilled' && r.value)
        // .map(r => r.value);

        // 如果生成了混淆数据，存入 KV
        if (maskKey && maskMap.size > 0) {
            // 将 Map 转为 Object 存入
            const maskJson = JSON.stringify(Object.fromEntries(maskMap));
            // 使用 await 确保在请求 subconverter 前数据已落盘
            await kvNamespace.put(maskKey, maskJson, { expirationTtl: DEFAULT_CONFIG.KV_TTL });
        }

        return proxies;
    },

    async _recursiveFetch(content, visitedUrls) {
        let lines = [];
        // 支持 Base64 编码的配置
        if (Utils.isBase64(content)) {
            content = Utils.base64Decode(content);
        }
        // # 开头的是忽略行
        const entries = content.split(/\n+/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));

        const fetchPromises = entries.map(async (entry) => {
            // 如果是 HTTP 链接，递归抓取
            if (entry.startsWith('https://') || entry.startsWith('http://')) {
                if (visitedUrls.has(entry)) return; // 防止循环引用
                visitedUrls.add(entry);
                try {
                    const respText = await Utils.fetchWithTimeout(entry, DEFAULT_CONFIG.FETCH_TIMEOUT, OBFUSCATED.RAY_CONFIG);
                    return this._recursiveFetch(respText, visitedUrls);
                } catch (e) {
                    console.warn(`Failed to fetch ${entry}:`, e.message);
                    return;
                }
            }
            return entry; // 直接是节点链接
        });

        const results = await Promise.allSettled(fetchPromises);
        results.forEach(res => {
            if (res.status === 'fulfilled' && res.value) {
                lines = lines.concat(res.value);
            }
        });
        return lines;
    },

    deduplicate(proxies) {
        const uniqueMap = new Map();
        const tagCounts = new Map();
        const speed_reg = /\d+\.?\d*(?= ?[MK]B\/s)/i;

        // 1. 去重 (基于 协议:地址:端口)
        proxies.forEach(p => {
            const key = `${p.protocol}:${p.host}:${p.port}`;
            // 如果存在且新链接 Tag 中有测速数据大的更好
            const existing = uniqueMap.get(key);
            const pSpeed = speed_reg.exec(p.tag);
            const eSpeed = existing && speed_reg.exec(existing.tag);
            if (!existing || !eSpeed && pSpeed || eSpeed && pSpeed && pSpeed[0] > eSpeed[0]) {
                uniqueMap.set(key, p);
            }
        });

        // 2. 处理重名 Tag
        return Array.from(uniqueMap.values()).map(p => {
            let finalTag = p.tag;
            let count = tagCounts.get(finalTag) || 0;
            tagCounts.set(finalTag, count + 1);

            if (count > 0) {
                // 如果重名，添加后缀，例如 "Node 1", "Node 2"
                // 原逻辑是追加 count，这里微调链接生成
                p.link = p.link + (p.link.includes('#') ? `%20${count + 1}` : `#${encodeURIComponent(finalTag + ' ' + (count + 1))}`);
            }
            return p.link;
        });
    }
};

const ProtocolParser = {
    /**
     * 解析单行链接，如果需要混淆，则修改链接内容并填充 maskMap
     */
    async parse(link, maskKey, maskMap) {
        if (!link || !link.includes('://')) return null;
        link = link.trim();

        try {
            const u = new URL(link);
            const protocol = u.protocol.slice(0, -1).toLowerCase();
            // 辅助函数：混淆并记录
            const mask = (val, type) => {
                if (!maskKey || !val) return val;
                if (maskMap.has(val)) return maskMap.get(val);
                const masked = Utils.generateRandomLike(val, type);
                maskMap.set(val, masked); // Key: 真实值, Value: 假值
                return masked;
            };


            // ==========================================
            // 1. VMe55 (JSON Base64)
            // ==========================================
            if (protocol === OBFUSCATED.VM) {
                const base64Part = u.hostname;
                let config = JSON.parse(Utils.base64Decode(base64Part));

                // 混淆 add 和 id
                if (maskKey) {
                    if (config.add) config.add = mask(config.add, 2);
                    if (config.id) config.id = mask(config.id, 3);
                    if (config.host) config.host = mask(config.host, 2);
                    if (config.sni) config.sni = mask(config.sni, 2);

                    return {
                        protocol,
                        host: config.add, // 此时已是假IP
                        port: config.port,
                        tag: config.ps,
                        link: `${OBFUSCATED.VM}://${Utils.base64Encode(JSON.stringify(config))}${u.search}`
                    };
                }
                return {
                    protocol,
                    host: config.add,
                    port: config.port,
                    tag: config.ps,
                    link: link
                };
            }

            // ==========================================
            // 2. 55 专用处理逻辑
            // ==========================================
            // 有 55://username:pass@host:port#tag 或 55://BASE64@host:port#tag
            // 甚至可能是 55 Legacy 格式 (55://base64#tag)
            if (protocol === OBFUSCATED.S5) {

                let method, pass, host, port;

                if (u.username) { // 有username代表有 @ 符
                    host = u.hostname;
                    port = u.port;
                    method = decodeURIComponent(u.username);
                    pass = decodeURIComponent(u.password);
                    // 只需要处理没有密码情况
                    if (!u.password) {
                        // 处理 userinfo: 可能是 "username%3Apass" 或 "Base64(method:pass)"
                        const userinfo = decodeURIComponent(u.username);
                        if (userinfo.includes(':')) {
                            [method, pass] = userinfo.split(':', 2);
                        }
                        else {
                            // 尝试 Base64 解码
                            const decodedInfo = Utils.base64UrlDecode(userinfo);
                            if (decodedInfo.includes(':')) {
                                [method, pass] = decodedInfo.split(':', 2);
                            } else {
                                // 解码后依然没有冒号，可能是非法格式
                                throw new Error("解析失败");
                            }
                        }
                    }
                }
                else {
                    // 尝试处理 Legacy 55
                    // --- Legacy 格式: Base64(method:pass@host:port) ---
                    const body = u.hostname;
                    // 解码后应该是 method:pass@host:port
                    const decoded = Utils.base64UrlDecode(body);
                    // 构造标准 URL 再次尝试
                    const ssu = new URL(`${OBFUSCATED.S5}://${decoded}`);
                    ({ username: method, password: pass, hostname: host, port } = ssu);
                    pass = decodeURIComponent(pass);    // URL API 会自动对用户名和密码部分做百分号编码
                }


                // --- 混淆并重组 ---
                if (maskKey) {
                    host = mask(host, 2);
                    pass = mask(pass, 1); // 混淆密码
                    // 注意：method 通常不混淆，因为客户端需要知道加密方式
                }

                // 统一输出为标准的 SIP002 格式 (55://Base64(method:pass)@host:port#tag)
                // 这样兼容性最好
                const userInfoStr = `${method}:${pass}`;
                const safeUserInfo = Utils.base64UrlEncode(userInfoStr);

                return {
                    protocol: OBFUSCATED.S5,
                    host: host,
                    port: port,
                    tag: decodeURIComponent(u.hash.slice(1)),
                    link: `${OBFUSCATED.S5}://${safeUserInfo}@${host}:${port}/${u.search}${u.hash}`
                };

            }

            // ==========================================
            // 3. 通用 URL 解析
            // ==========================================
            // 对于标准 URL 格式，使用 URL 对象依然是最可靠的

            let host = u.hostname;
            let port = u.port;
            let tag = decodeURIComponent(u.hash.slice(1));

            if (!u.password) {
                // 处理 userinfo: 可能是 "username%3Apass"
                const userinfo = decodeURIComponent(u.username);
                if (userinfo.includes(':')) {
                    [u.username, u.password] = userinfo.split(':', 2);
                }
            }

            // 混淆逻辑
            if (maskKey) {
                // 混淆 Host
                const maskedHost = mask(host, 2);
                u.hostname = maskedHost; // URL 对象会自动处理 IPv6 括号等

                // 混淆 Password / UUID (Userinfo)
                if (u.username) u.username = mask(decodeURIComponent(u.username)); // 某些协议 uuid 在 username
                if (u.password) u.password = mask(decodeURIComponent(u.password), 1);
                // 处理 Hysteria2 可能存在的特殊参数 (如 sni)
                // searchParams 自动处理了 ?sni=xxx
                if (u.searchParams.has('sni')) {
                    u.searchParams.set('sni', mask(u.searchParams.get('sni'), 2));
                }
                if (u.searchParams.has('peer')) { // obsolete but exist
                    u.searchParams.set('peer', mask(u.searchParams.get('peer'), 2));
                }

                return {
                    protocol,
                    host: maskedHost,
                    port: port,
                    tag: tag,
                    link: u.toString()
                };
            }

            return {
                protocol,
                host: host,
                port: port,
                tag: tag,
                link: link
            };

        } catch (e) {
            console.warn('Parse error', link, e.message);
            return null;
        }
    }
};

const SubconverterService = {
    async requestConversion(targetType, url, env, secret, payload) {
        const subConverterUrl = (url.searchParams.get("subconverter") || env.SUBCONVER || OBFUSCATED.SUB_BACKEND).trim();
        const subConfig = env.SUB_CONFIG || OBFUSCATED.SUB_CONFIG;

        // 构建回调 URL (必须是当前 Worker 的 /resource)
        const callbackUrl = new URL(url.origin + "/resource");
        // 生成新的 Token，带有 masked_key (即当前的 nonce)
        const newToken = await AuthService.signToken({
            masked_key: payload.nonce, // 告诉下一次请求：请去 KV 读这个 key 的混淆表
        }, secret, 60);

        // 传递原有参数，但在 callback 中使用新 Token
        const callbackParams = new URLSearchParams(url.search);
        callbackParams.set("token", newToken);
        callbackParams.delete("target");
        callbackParams.delete("subconverter");
        callbackUrl.search = callbackParams.toString();

        // 构造 Subconverter 请求
        const apiUrl = new URL(`${subConverterUrl.startsWith('http') ? subConverterUrl : 'http://' + subConverterUrl}/sub`);
        apiUrl.searchParams.set("target", targetType);
        apiUrl.searchParams.set("url", callbackUrl.toString()); // 这里的 URL 是经过编码的回调地址
        apiUrl.searchParams.set("config", subConfig);
        apiUrl.searchParams.set("emoji", "true");
        apiUrl.searchParams.set("list", "false");
        apiUrl.searchParams.set("udp", "true");
        apiUrl.searchParams.set("tfo", "false");
        apiUrl.searchParams.set("scv", "true");
        apiUrl.searchParams.set("fdn", "false");
        apiUrl.searchParams.set("sort", "false");
        apiUrl.searchParams.set("new_name", "true");

        try {
            const respText = await Utils.fetchWithTimeout(apiUrl.toString(), DEFAULT_CONFIG.SUB_CONVERTER_TIMEOUT);

            // 从 KV 获取混淆映射表，准备还原
            const maskJson = await env.MASKED_KV.get(payload.nonce); // 注意：这里用的是当前请求 payload 里的 nonce
            if (!maskJson) {
                // 如果没有混淆数据（可能是节点列表为空），直接返回结果
                return new Response(respText, { status: 200 });
            }

            const maskMap = new Map(Object.entries(JSON.parse(maskJson)));
            // 还原：将结果中的 假值 替换回 真值
            // map 是 { 真: 假 }
            // 我们需要把 str 中的 假 -> 真
            const restoredText = Utils.restoreMaskedContent(respText, maskMap);

            return new Response(restoredText, {
                status: 200,
                headers: { "Content-Type": "text/plain; charset=utf-8" },
            });

        } catch (err) {
            return new Response(`Subconverter Error: ${err.message}`, { status: 502 });
        }
    }
};

// ==========================================
// 5. 工具类 (Utilities)
// ==========================================

const Utils = {
    detectTargetType(params, ua) {
        if (params.get('target')) return params.get('target').toLowerCase();
        // 检查 UA 是否包含特定关键词
        const check = (keywords) => keywords.some(k => Array.from(params.keys()).map(p => p.toLowerCase()).includes(k) || ua.includes(k));

        if (check(OBFUSCATED.CL)) return OBFUSCATED.CL[0];
        if (check(OBFUSCATED.SB)) return OBFUSCATED.SB[0];
        if (check(OBFUSCATED.SU)) return OBFUSCATED.SU[0];
        if (check(OBFUSCATED.QU)) return OBFUSCATED.QU[0];
        if (check(OBFUSCATED.LO)) return OBFUSCATED.LO[0];
        if (check(OBFUSCATED.SF)) return OBFUSCATED.SF[0];
        if (params.has("raw")) return "raw";

        return 'mixed'; // 默认混合模式或 fallback
    },

    base64Encode(str) {
        return btoa(String.fromCharCode(...new TextEncoder().encode(str)));
    },

    base64Decode(str) {
        return new TextDecoder().decode(Uint8Array.from(atob(str), c => c.charCodeAt(0)));
    },

    base64UrlEncode(str) {
        return this.base64Encode(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },

    base64UrlDecode(str) {
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        // 补齐 padding
        while (str.length % 4) str += '=';
        return this.base64Decode(str); // base64Decode handle replacement internally
    },

    isBase64(str) {
        if (typeof str !== 'string' || !str) return false;
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(str)) return false;
        try {
            atob(str); // 尝试解码
            return true;
        } catch {
            return false;
        }
    },

    async fetchWithTimeout(url, timeoutMs, ua) {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeoutMs);
        try {
            const res = await fetch(url, {
                headers: { 'User-Agent': ua || DEFAULT_CONFIG.DEFAULT_UA },
                signal: controller.signal
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return res.text();
        } catch (err) {
            if (err.name === "AbortError") {
                throw new Error(`请求超时 ${timeoutMs}ms: ${url}`);
            }
            throw err;
        } finally {
            clearTimeout(id);
        }
    },

    generateRandomLike(input = "", type) {
        switch (type) {
            case 1:
                // randomString
                const charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
                let result = "";
                for (let i = 0; i < (input?.length || 8); i++) {
                    result += charset[Math.floor(Math.random() * charset.length)];
                }
                return result;
            case 2:
                // randomDomain
                const vowels = "aeiou";
                const consonants = "bcdfghjklmnpqrstvwxyz";
                const tlds = [".com", ".net", ".org", ".io", ".ai", ".co", ".xyz", ".top", ".tech"];

                function syllable() {
                    const c = consonants[Math.floor(Math.random() * consonants.length)];
                    const v = vowels[Math.floor(Math.random() * vowels.length)];
                    return c + v;
                }

                let thirdLevel = "", secondLevel = "";
                const length = Math.floor(Math.random() * 2) + 2; // 2–4 个音节
                const length2 = Math.floor(Math.random() * 4) + 3; // 3–6 个音节
                for (let i = 0; i < length2; i++) {
                    thirdLevel += syllable();
                }
                for (let i = 0; i < length; i++) {
                    secondLevel += syllable();
                }
                const tld = tlds[Math.floor(Math.random() * tlds.length)];
                return `${thirdLevel}.${secondLevel}${tld}`;
            case 3:
                // uuid
                return crypto.randomUUID();
            default:
                const isUUID = /^[0-9a-fA-F-]{36}$/.test(input) && input.split("-").length == 5;
                if (isUUID) return crypto.randomUUID();
                return this.generateRandomLike(input, 1);
        }

    },

    restoreMaskedContent(content, maskMap) {
        // maskMap: { Real: Fake }
        // 我们需要把 Fake -> Real
        // 为了防止子串误替换，可以先按长度排序（长的先换）- 虽然随机串碰撞概率低，
        // 但这里性能优先，且 Fake 是随机生成的，冲突概率极小。

        for (const [real, fake] of maskMap.entries()) {
            // 全局替换：把所有的 fake 换回 real
            content = content.replaceAll(fake, real);
        }
        return content;
    }
};

// 辅助 HTML
function htmlNginxWelcome() {
    return `<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>`;
}

function generateHtml(baseUrl, queryString, adminSecret = null) {

    const isAdmin = !!adminSecret;
    // 如果是管理员，不需要 token 参数，但为了 fetch api 方便，前端可以保持逻辑一致
    // 关键：adminSecret 会被填充到 input，且显示 token 生成器

    // 这里的 queryString 包含了当前的 token 等鉴权参数
    const clients = [
        { name: 'Mixed (通用)', icon: 'zap', color: 'orange', target: '' },
        { name: Utils.base64Decode('Q2xhc2ggLyBNZXRh'), icon: 'shield', color: 'blue', target: OBFUSCATED.CL[0] },
        { name: Utils.base64Decode('U2luZy1ib3g='), icon: 'box', color: 'green', target: OBFUSCATED.SB[0] },
        { name: Utils.base64Decode('U3VyZ2U='), icon: 'wind', color: 'cyan', target: OBFUSCATED.SU[0] },
        { name: Utils.base64Decode('UXVhbnR1bXVsdCBY'), icon: 'activity', color: 'purple', target: OBFUSCATED.QU[0] },
        { name: Utils.base64Decode('TG9vbg=='), icon: 'send', color: 'yellow', target: OBFUSCATED.LO[0] },
        { name: Utils.base64Decode('U3VyZmJvYXJk'), icon: 'chevrons-right', color: 'cyan', target: OBFUSCATED.SF[0] }
    ];
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>代理订阅管理器</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        .glass { background: rgba(255, 255, 255, 0.7); backdrop-filter: blur(10px); }
        body { background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); min-height: 100vh; }
    </style>
</head>
<body class="p-4 md:p-8 text-slate-800">
    <div class="max-w-5xl mx-auto">
        <header class="mb-8 text-center">
            <h1 class="text-3xl font-bold mb-2">订阅转换管理</h1>
            <p class="text-slate-600">快速生成各客户端订阅地址并管理核心配置</p>
            ${isAdmin ? '<span class="px-3 py-1 bg-red-500 text-white rounded-full text-xs font-bold shadow-lg">ADMIN MODE</span>' : ''}
        </header>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
            ${clients.map(c => `
            <div class="bg-white/80 p-5 rounded-2xl shadow hover:scale-[1.02] transition border border-white">
                <div class="flex items-center mb-3"><i data-lucide="${c.icon}" class="text-${c.color}-500 mr-2"></i><span class="font-bold text-slate-700">${c.name}</span></div>
                <div class="relative">
                    <input readonly value="${baseUrl}${c.target ? '?target=' + c.target + '&' : '?'}${queryString}" id="u-${c.icon}" class="w-full p-2 bg-slate-100 rounded text-xs text-slate-600 outline-none">
                    <button onclick="copyToClipboard('u-${c.icon}')" class="absolute right-1 top-1 text-slate-400 hover:text-blue-600"><i data-lucide="copy" size="16"></i></button>
                </div>
            </div>
            `).join("")}
        </div>
        <section class="glass p-6 rounded-2xl shadow-lg border border-white">
            <div class="flex justify-between mb-4">
                <div class="flex items-center text-blue-700"><i data-lucide="settings" class="mr-2"></i><h2 class="font-bold text-lg">源链接配置 (KV: LINKS)</h2></div>
                <button onclick="fetchLinks()" class="text-blue-600 font-bold text-sm flex items-center hover:bg-blue-50 px-2 py-1 rounded"><i data-lucide="refresh-cw" size="14" class="mr-1"></i>Refresh</button>
            </div>
            <textarea id="links-editor" rows="10" placeholder="在此输入 SS... 等代理的 URL Schemes 链接或订阅地址(代理行格式)，一行一个..." class="w-full p-4 bg-slate-900 text-green-400 rounded-xl mb-4 font-mono text-sm outline-none focus:ring-2 focus:ring-blue-300"></textarea>
            <div class="flex gap-4">
                <div class="relative flex-1">
                    <input type="password" id="admin-secret" placeholder="🔒 输入 Signing Secret 进行提交..." value="${adminSecret || ''}" 
                    class="w-full p-3 rounded-xl outline-none shadow-inner bg-white border border-slate-200 focus:border-blue-400"
                   ${isAdmin ? 'readonly' : ''}> ${isAdmin ? '<div class="absolute right-3 top-3 text-green-500 text-xs font-bold"><i data-lucide="check-circle" size="16"></i> Verified</div>' : ''}
                </div>
                <button onclick="updateLinks()" class="px-8 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-xl font-bold transition shadow-lg flex items-center"><i data-lucide="save" size="18" class="mr-2"></i>保存并更新</button>
            </div>
        </section>
    </div>
    <script>
        const ADMIN_SEC = '${adminSecret || ''}'; // 注入 Secret
        lucide.createIcons();
        function copyToClipboard(id) {
            const input = document.getElementById(id);
            input.select();
            document.execCommand('copy');
            alert('链接已成功复制到剪贴板！');
        }
        async function fetchLinks() {
            const s = document.getElementById('admin-secret');
            if (!s && !ADMIN_SEC) {
                s.value = "🔒 请输入 Signing Secret 密钥以验证权限！";
                s.focus();
                return;
            }
            const btn = event.currentTarget;
            btn.classList.add('animate-spin');
            try {
                const response = await fetch('/api/get-links', { 
                    method: 'POST',
                    body: JSON.stringify({ secret: s || ADMIN_SEC }) 
                });
                if(response.status === 401) throw new Error();
                const data = await response.json();
                document.getElementById('links-editor').value = data.content;
            } catch (err) {
                alert('获取内容失败: Signing Secret 密钥错误');
            } finally {
                btn.classList.remove('animate-spin');
            }
        }
        async function updateLinks() {
            const content = document.getElementById('links-editor').value;
            const secret = document.getElementById('admin-secret').value;
            if (!secret) {
                alert('请输入 Signing Secret 密钥以验证权限！');
                return;
            }

            if (!confirm('确定要覆盖 KV 存储中的原始 LINKS 配置吗？')) return;
            try {
                const response = await fetch('/api/update-links', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content, secret })
                });

                if (response.ok) {
                    alert('配置已成功保存！缓存将在 TTL 过期后生效。');
                } else {
                    const err = await response.text();
                    alert('保存失败: ' + err);
                }
            } catch (err) {
                alert('请求异常: ' + err.message);
            }
        }
        // 页面加载后自动拉取一次
        // window.onload = fetchLinks;
    </script>
</body>
</html>
`;
}