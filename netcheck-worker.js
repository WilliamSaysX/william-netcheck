// ================================================================
// netcheck-worker.js — 网络分流检测 · 网页版（独立 Worker，不影响主 Worker）
//
// 【探针全部使用第三方真实站点，不再自建探针域名】
// 旧版靠自建域名 + "域名关键字诱饵" 来探线路，依赖的是"未命中规则 → 兜底走
// 机场"这一前提；新版配置已改成 MATCH → DIRECT（省流量），该前提不再成立，
// 自建探针会全部掉进直连，判定必然误报"未检测到代理"。
//
// 新方案改测四条线路的真实出口，每个探针都是「本身就会命中对应规则」的真站点：
//   🏠 AI 专线      claude.ai/cdn-cgi/trace       命中 DOMAIN-KEYWORD,claude → 住宅IP
//   ✈️ 国际中转      api.ipify.org/cdn-cgi/trace   在 gfw.txt → RULE-SET,overseas → 机场
//   🔗 未分类境外    ipinfo.io/json                不命中任何规则 → MATCH,DIRECT → 本地
//   🇨🇳 国内直连     myip.ipip.net                 GEOIP,CN → 本地
//
// 比诱饵域名更可信：测的是真实业务站点走哪条线，而不只是"规则能不能匹配"。
// 三条线路出口 IP 互不相同 = 三线分流生效；中转出口塌陷到本地 = 境外规则集失效
// （安卓 FlClash 上出现过的故障：除国内与 AI 站点外全部打不开）。
//
// Cloudflare 站点的 /cdn-cgi/trace 会回显 ip/loc/colo 且响应带
// access-control-allow-origin: *，浏览器可直接跨域读取（claude.ai 与
// api.ipify.org 均已实测）。ipinfo.io 额外给出城市与运营商。
//
// check.williamsays.uk 现仅用于托管本检测页；claude-check / googlevideo-check
// 两个 Custom Domain 已无用途，可随时下线。
//
// 路由：GET /probe → 回显出口 IP + 地理信息（保留兼容，页面已不再调用）；其余 → 检测页
// ================================================================

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': '*',
};

function handleProbe(request) {
  const cf = request.cf || {};
  const body = JSON.stringify({
    ip: request.headers.get('cf-connecting-ip') || '',
    cc: cf.country || '',
    city: cf.city || '',
    region: cf.region || '',
    colo: cf.colo || '',
    org: cf.asOrganization || '',
    asn: cf.asn || 0,
  });
  return new Response(body, {
    headers: {
      ...CORS_HEADERS,
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }
    if (url.pathname === '/probe') {
      return handleProbe(request);
    }
    return new Response(PAGE_HTML, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
      },
    });
  },
};

// ================================================================
// 检测页（移动端优先；页内脚本刻意不用模板字符串，避免嵌套反引号）
// ================================================================
const PAGE_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="robots" content="noindex">
<title>网络分流检测 · 威廉的 AI Club</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌐</text></svg>">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif;
  background-image:
    radial-gradient(circle at 10% 20%, rgba(0, 168, 255, 0.15), transparent 45%),
    radial-gradient(circle at 90% 85%, rgba(255, 23, 68, 0.1), transparent 45%),
    linear-gradient(150deg, #090c1f 0%, #060813 100%);
  background-attachment: fixed;
  color: #e0e0e6;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  padding: 20px 16px calc(24px + env(safe-area-inset-bottom));
  max-width: 560px;
  margin: 0 auto;
  width: 100%;
}
.head { margin-bottom: 16px; }
h1 { font-size: 19px; color: #fff; display: flex; align-items: center; gap: 8px; }
.sub { font-size: 12px; color: #8b95ab; margin-top: 6px; }
.card {
  border: 1px solid rgba(97, 175, 239, 0.22);
  border-radius: 12px;
  background: rgba(97, 175, 239, 0.08);
  padding: 12px 14px;
  font-size: 13px;
  line-height: 1.6;
  color: #d5e4f8;
  margin-bottom: 14px;
}
.summary {
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.04);
  padding: 12px 14px;
  margin-bottom: 14px;
}
.headline { font-size: 14px; font-weight: 700; line-height: 1.5; }
.headline.ok { color: #7ed99a; }
.headline.warn { color: #ffd27a; }
.dot { flex-shrink: 0; width: 8px; height: 8px; border-radius: 50%; background: rgba(255,255,255,0.12); }
.dot.on { box-shadow: 0 0 6px currentColor; }
.groups { margin-bottom: 16px; }
.group {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 12px;
  padding: 4px 14px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2), inset 0 1px 1px rgba(255, 255, 255, 0.08);
  margin-bottom: 12px;
}
.group:last-child { margin-bottom: 0; }
.item { display: flex; align-items: center; gap: 10px; padding: 12px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
.item:last-child { border-bottom: none; }
/* 固定行高：待检测/检测中/出结果三种状态高度一致，重新检测时页面不跳动 */
/* 128px 实测能装下最长的结论文案换行成2行的情况（21字"✓ 走直连，既不
   消耗中转流量也不消耗住宅IP流量"实测 121px）；四张卡片头部固定同一高度，
   不管结论文字是 1 行还是 2 行都不会撑破对齐 */
.item.parent { min-height: 128px; }
/* 68px 而不是看起来够用的 52px：子探针成功时 .result 是空的（下面
   :empty 规则隐藏），52px 由 min-height 下限撑住；一旦探针失败会显示
   "✕ 超时"文字，实际需要 68px，超过下限就会比同卡片其他行更高，
   卡片间也会跟着错位。统一按失败态的高度定，成功/失败都不会变形 */
.item.child { min-height: 68px; }
.item.child { margin-left: 14px; padding-left: 14px; border-left: 2px solid rgba(97, 175, 239, 0.22); }
.item.child .name { font-size: 13px; }
.info { flex: 1; min-width: 0; }
.name { font-size: 14px; font-weight: 600; color: #c0c0d0; display: flex; align-items: baseline; gap: 6px; flex-wrap: wrap; }
.host { font-size: 10px; font-weight: 400; color: #6b6b80; }
.result { margin-top: 4px; font-size: 12px; line-height: 1.5; display: flex; flex-wrap: wrap; align-items: center; gap: 4px 8px; }
.result:empty { display: none; }
.pending { color: #6b6b80; }
.ipv { font-family: 'SF Mono', Menlo, Consolas, monospace; color: #9fd2ff; }
/* 地区/ISP 单行省略，长运营商名不折行 */
/* flex-basis: 100% 强制它永远自己占一行，不再跟 .ipv 抢同一行空间——
   之前用 flex: 1 1 auto，能不能挤下同一行完全看这次的运营商名字长不
   长、卡片这次多宽，同一类"内容决定行数"的问题在这挨个卡片身上反复
   冒出来（这已经是第三处了：父行高度、note高度、现在是这里），干脆
   从结构上让行数固定，不再让任何一处依赖内容长度去猜 */
.geo { color: #aab4cc; flex: 1 1 100%; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.item.parent .name { font-size: 15px; color: #e0e0e6; }
.item.parent .ipv { font-size: 14px; }
.okonly { color: #8b95ab; }
.fail { color: #ffb4aa; }
/* 固定 2 行的高度（实测 line-height 18px，2 行=36px），不管这次的结论
   文字够不够长到自然换行都占住这份空间——之前只给 .item.parent 设
   min-height 试图"猜一个够用的高度"，结果四张卡片里文字最短的那句刚好
   在某个宽度下只占 1 行，其余 3 句占 2 行，行数不一样卡片就跟着不一样高。
   直接固定 .note 自己的高度，从根上让行数不再有差异，不用再猜任何数字 */
.note { width: 100%; min-height: 36px; font-size: 11px; color: #7b8499; }
.note.ok { color: #7ed99a; }
.note.warn { color: #ffd27a; }
.lat { flex-shrink: 0; font-size: 12px; font-family: 'SF Mono', Menlo, Consolas, monospace; }
.lat.fast { color: #66bb6a; } .lat.mid { color: #f0c040; } .lat.slow { color: #e8a030; }
.btn {
  border: none; cursor: pointer; flex-shrink: 0;
  background: linear-gradient(135deg, #FF1744, #D50000);
  color: #fff; padding: 10px 20px; border-radius: 9px;
  font-size: 14px; font-weight: 700; white-space: nowrap;
}
.btn:disabled { opacity: 0.6; }
/* 「重新检测」跟打码开关放一行，紧挨着结果区上方——不再单独待在页头，
   跟它实际影响的内容（下面的卡片）离得更近 */
.mask-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
.mask-toggle {
  display: flex; align-items: center; gap: 8px; cursor: pointer;
  color: #8b95ab; font-size: 12px; white-space: nowrap; user-select: none;
}
.mask-toggle:hover { color: #c7cbe0; }
.mask-toggle input { display: none; }
.mask-toggle .slider {
  position: relative; width: 34px; height: 18px; flex-shrink: 0;
  background: #3a3a55; border-radius: 999px; transition: background .2s;
}
.mask-toggle .slider::before {
  content: ''; position: absolute; left: 2px; top: 2px;
  width: 14px; height: 14px; background: #fff; border-radius: 50%;
  transition: transform .2s;
}
.mask-toggle input:checked + .slider { background: #34c759; }
.mask-toggle input:checked + .slider::before { transform: translateX(16px); }
.foot { margin-top: auto; padding-top: 28px; font-size: 11px; color: #6b6b80; line-height: 1.7; text-align: center; }
.foot a { color: #61afef; text-decoration: none; }
.foot-pc { display: none; } /* 插件推荐仅在电脑端显示 */
/* 平板：加宽版心、放大字号（布局仍为单列） */
@media (min-width: 768px) {
  body { max-width: 760px; padding: 44px 36px; }
  h1 { font-size: 26px; }
  .sub { font-size: 14px; margin-top: 8px; }
  .head { margin-bottom: 22px; }
  .btn { padding: 12px 26px; font-size: 15px; }
  .card { font-size: 14px; padding: 16px 20px; line-height: 1.7; }
  .summary { padding: 16px 20px; }
  .headline { font-size: 16px; }
  .group { padding: 6px 18px; }
  .item { padding: 14px 0; }
  .name { font-size: 15px; }
  .item.child .name { font-size: 14px; }
  .host { font-size: 11px; }
  .result { font-size: 13px; }
  .note { font-size: 12px; }
  .lat { font-size: 13px; }
  .foot { font-size: 12px; }
  .foot-pc { display: block; }
}
/* 桌面：四条线路排成 2×2 等高卡片；卡片本身已含全部线路信息，
   汇总区只保留一句结论，不再重复线路明细 */
@media (min-width: 1000px) {
  body { max-width: 1160px; padding: 48px 44px; }
  .groups {
    display: grid;
    /* minmax(0,1fr) 强制各列严格等宽：长地区/ISP 文本收缩省略，而不是撑宽所在列 */
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px;
  }
  .group { margin-bottom: 0; padding: 8px 20px; }
  .item.child { margin-left: 8px; padding-left: 14px; }
  .summary { margin-bottom: 18px; }
}
/* 超宽屏：四条线路一行排开，便于横向对比出口 IP */
@media (min-width: 1500px) {
  body { max-width: 1560px; }
  .groups { grid-template-columns: repeat(4, minmax(0, 1fr)); }
}
</style>
</head>
<body>
<div class="head">
  <h1>🌐 网络分流检测</h1>
  <div class="sub">威廉的 AI Club · 手机 / 电脑 / 软路由下的任意设备均可检测</div>
</div>
<div class="card">从当前设备直接访问各真实站点，完整经过你的分流规则。<br>增强版应为四段分流：AI 站点走「静态住宅IP」，被墙站点走「中转」，其余境外站点与国内网站均走直连（省流量）。</div>
<div class="summary" id="summary"><div class="headline">检测中…</div></div>
<div class="mask-row">
  <button class="btn" id="run">开始检测</button>
  <label class="mask-toggle"><span>隐藏 IP/地区</span><input type="checkbox" id="maskToggle"><span class="slider"></span></label>
</div>
<div class="groups" id="list"></div>
<div class="foot">
  <div>检测基于「威廉的 AI Club」配置规则，第三方配置仅供参考</div>
  <div class="foot-pc">电脑端可安装 <a href="https://chromewebstore.google.com/search/%E5%A8%81%E5%BB%89%E7%9A%84%20AI%20Club" target="_blank">AI 工具箱浏览器插件</a>，一键生成分流配置</div>
</div>
<script>
var TIMEOUT = 10000;
// 四条线路各用一个「本身就会命中对应规则」的真实第三方站点做出口探针，
// 不再使用自建诱饵域名（原理见文件头注释）。父行读出口 IP，子行测连通性。
var TARGETS = [
  // 🏠 静态住宅IP：claude.ai 命中 DOMAIN-KEYWORD,claude → 住宅IP。父行本身就是
  // claude.ai，但 Claude 封号风险最受关注，额外加一行子探针让结果更直白。
  // 卡片名跟"国际中转"/"国内直连"一样按连接方式命名（而不是"AI专线"这种
  // 按用途命名），还能跟客户端里真实的策略组名「🏠 静态住宅IP」对上
  { id: 'ai',      name: '静态住宅IP出口',    host: 'claude.ai',       type: 'trace',   url: 'https://claude.ai/cdn-cgi/trace' },
  { id: 'claude',  name: 'Claude',           host: 'claude.ai',       parent: 'ai',    type: 'ping', url: 'https://claude.ai/cdn-cgi/trace' },
  { id: 'chatgpt', name: 'ChatGPT',          host: 'chatgpt.com',     parent: 'ai',    type: 'ping', url: 'https://chatgpt.com/cdn-cgi/trace' },
  { id: 'gemini',  name: 'Google / Gemini',  host: 'google.com',      parent: 'ai',    type: 'ping', url: 'https://www.google.com/generate_204' },

  // ✈️ 国际中转：api.ipify.org 在 gfw.txt 清单内 → 命中 RULE-SET,overseas → 机场
  // 这一行同时是「境外规则集健康度」探测器：规则集拉不下来时它会塌陷回本地出口
  //
  // ⚠️ 这条线的子探针必须选"只会被 gfw.txt 通用规则集命中、不会被用户自己
  // 勾选的服务规则单独接管"的域名——proxy-config.json 里 twitter/reddit/
  // discord/tiktok/facebook 等一整个社交类目都是可勾选的，勾了就会单独走
  // DOMAIN-SUFFIX 规则命中住宅IP，不会落到这条通用中转线上，用它们做探针
  // 会跟卡片实际语义对不上（x.com 就在这类目下，已经踩过一次，别再选中）。
  // wikipedia.org / googlevideo.com / bbc.com 都不在 proxy-config.json 的
  // 可选清单里，只会被 gfw.txt 兜底，才是这条线真正安全的探针
  { id: 'relay',   name: '被墙站点出口',      host: 'api.ipify.org',   type: 'trace',   url: 'https://api.ipify.org/cdn-cgi/trace' },
  // 探测 URL（功能性）用 www.googlevideo.com 这个固定域名：裸域名
  // googlevideo.com 没有 DNS 记录，而 rr1---sn-xxx 这类主机名是 YouTube
  // 动态分配的 CDN 节点，硬编码会失效——这条不能改。host 只是展示文案，
  // 写成 "youtube.com/googlevideo.com" 是为了让用户看得懂这条测的是
  // YouTube（单独 googlevideo.com 大多数人不知道是什么）
  { id: 'youtube', name: 'YouTube',  host: 'youtube.com/googlevideo.com', parent: 'relay', type: 'ping', url: 'https://www.googlevideo.com/generate_204' },
  { id: 'wiki',    name: '维基百科',          host: 'wikipedia.org',   parent: 'relay', type: 'ping', url: 'https://www.wikipedia.org/static/favicon/wikipedia.ico' },
  // 不用 Netflix（对机房/代理IP主动限速检测，实测经常超时）；不用 x.com
  // （见上方警告，它是用户可勾选的社交类目，不能保证走这条线）。BBC 不在
  // 可勾选清单、也不像 Netflix 那样限速代理IP，实测稳定 76ms 左右
  { id: 'bbc',     name: 'BBC',               host: 'bbc.com',         parent: 'relay', type: 'ping', url: 'https://www.bbc.com/favicon.ico' },

  // 🇨🇳 国内直连
  { id: 'cn',      name: '国内直连出口',      host: 'myip.ipip.net',   type: 'cn' },
  { id: 'baidu',   name: '百度',              host: 'baidu.com',       parent: 'cn',    type: 'ping', url: 'https://www.baidu.com/favicon.ico' },
  { id: 'taobao',  name: '淘宝',              host: 'taobao.com',      parent: 'cn',    type: 'ping', url: 'https://www.taobao.com/favicon.ico' },
  { id: 'bili',    name: '哔哩哔哩',          host: 'bilibili.com',    parent: 'cn',    type: 'ping', url: 'https://www.bilibili.com/favicon.ico' },

  // 🔗 未分类站点：ipinfo.io 不在 gfw.txt、也不在任何分流规则里 → 落 MATCH,DIRECT
  // 走直连才是新版配置的正确行为（省流量的直接证据），不再当作异常。
  // 排在最后一组：这是这次架构升级新增的兜底出口，放最后更能体现它是
  // "前面三条线都没接住时的兜底"，而不是跟前面平级的第四条常规线路。
  // 子行选直连实测稳定可达的站点；少数清单外站点（如 stackoverflow / npmjs）
  // 直连会被干扰，那属于清单覆盖范围的问题，不是分流配置错误
  { id: 'direct',  name: '未分类站点出口',    host: 'ipinfo.io',       type: 'ipinfo',  url: 'https://ipinfo.io/json' },
  { id: 'amazon',  name: '亚马逊',            host: 'amazon.com',      parent: 'direct', type: 'ping', url: 'https://www.amazon.com/favicon.ico' },
  { id: 'mozilla', name: 'Mozilla',           host: 'mozilla.org',     parent: 'direct', type: 'ping', url: 'https://www.mozilla.org/favicon.ico' },
  // 规范站点域名是裸域。www 曾遗留到停放页，测速它会把 SSL/源站错误误显示成
  // “网站延迟”；这里必须直接测实际服务域名。
  { id: 'wsays',   name: '威廉的 AI Club',    host: 'williamsays.com', parent: 'direct', type: 'ping', url: 'https://williamsays.com/favicon.ico' }
];
var COLORS = ['#61afef', '#66bb6a', '#f0c040', '#e06c75', '#c678dd', '#56b6c2'];
var running = false;

function $(id) { return document.getElementById(id); }
var regionNames = null;
try { regionNames = new Intl.DisplayNames(['zh-CN'], { type: 'region' }); } catch (e) {}
function flagEmoji(cc) {
  if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return '';
  var u = cc.toUpperCase();
  return String.fromCodePoint(0x1F1E6 + u.charCodeAt(0) - 65, 0x1F1E6 + u.charCodeAt(1) - 65);
}
function regionLabel(cc) {
  if (!cc) return '';
  var name = cc;
  try { name = (regionNames && regionNames.of(cc.toUpperCase())) || cc; } catch (e) {}
  return (flagEmoji(cc) + ' ' + name).trim();
}
function lineKey(ip) {
  if (ip.indexOf(':') >= 0) return ip.toLowerCase().split(':').slice(0, 4).join(':');
  return ip.split('.').slice(0, 3).join('.');
}
// 判断"这是不是同一条线路"，境内和境外要用不同标准：
// 境外线路（AI专线/中转）要精确比 IP 网段，证明确实是两条不同基础设施；
// 境内线路（未分类境外/国内直连）不能直接比 IP——同一条本地宽带，两次
// 探测可能一次出 IPv4 一次出 IPv6（双栈网络下 DNS 解析走了不同协议栈），
// 这种情况下按 IP 比会误判成"不同线路"。境内场景下真正该问的是"这是不是
// 国内出口"，不是"字节级别是不是同一个地址"，所以退化成按国家码归并
function exitKey(r) {
  if (r.cc === 'CN') return 'CN-LOCAL';
  return lineKey(r.ip);
}
function fetchT(url, opt, ms) {
  var c = new AbortController();
  var t = setTimeout(function () { c.abort(); }, ms || TIMEOUT);
  opt = opt || {};
  opt.cache = 'no-store';
  opt.signal = c.signal;
  return fetch(url, opt).finally(function () { clearTimeout(t); });
}

// 预热：先发一次不计时的请求把 TCP/TLS 连接建好（长链路首连要 2-3 秒），
// 正式测量复用连接，显示的延迟即线路的稳定往返速度
async function warm(url, opt) {
  try { await fetchT(url, opt, 8000); } catch (e) {}
}
async function probeEcho(url) {
  await warm(url);
  var t0 = performance.now();
  var r = await fetchT(url);
  var lat = Math.round(performance.now() - t0);
  if (!r.ok) return { ok: true, limited: true, latency: lat };
  var d = await r.json();
  if (!d.ip) return { ok: true, limited: true, latency: lat };
  return {
    ok: true, ip: d.ip, latency: lat, cc: (d.cc || '').toUpperCase(),
    region: (regionLabel(d.cc) + ' ' + (d.city || '')).trim(),
    detail: d.org || ''
  };
}
async function probePing(url) {
  await warm(url, { mode: 'no-cors' });
  var t0 = performance.now();
  await fetchT(url, { mode: 'no-cors' });
  return { ok: true, pingOnly: true, latency: Math.round(performance.now() - t0) };
}
// Cloudflare 站点通用的 /cdn-cgi/trace：纯文本 key=value，回显 ip / loc(国家码) /
// colo(就近机房)，且响应带 access-control-allow-origin:*，浏览器可直接跨域读
async function probeTrace(url) {
  await warm(url);
  var t0 = performance.now();
  var r = await fetchT(url);
  var lat = Math.round(performance.now() - t0);
  if (!r.ok) return { ok: true, limited: true, latency: lat };
  var txt = await r.text();
  var o = {};
  txt.split('\\n').forEach(function (line) {
    var i = line.indexOf('=');
    if (i > 0) o[line.slice(0, i)] = line.slice(i + 1);
  });
  if (!o.ip) return { ok: true, limited: true, latency: lat };
  return {
    ok: true, ip: o.ip, latency: lat, cc: (o.loc || '').toUpperCase(),
    region: regionLabel(o.loc),
    detail: o.colo ? 'Cloudflare ' + o.colo : ''
  };
}
// ipinfo.io：未分类境外线路的探针，顺带给出城市与运营商（比 trace 更详细）
async function probeIpinfo(url) {
  await warm(url);
  var t0 = performance.now();
  var r = await fetchT(url);
  var lat = Math.round(performance.now() - t0);
  if (!r.ok) return { ok: true, limited: true, latency: lat };
  var d = await r.json();
  if (!d.ip) return { ok: true, limited: true, latency: lat };
  return {
    ok: true, ip: d.ip, latency: lat, cc: (d.country || '').toUpperCase(),
    region: (regionLabel(d.country) + ' ' + (d.city || '')).trim(),
    detail: (d.org || '').replace(/^AS\\d+\\s+/, '')
  };
}
async function probeCn() {
  var NON_MAINLAND = ['香港', '澳门', '台湾'];
  try {
    var t0 = performance.now();
    var r = await fetchT('https://myip.ipip.net/json', {}, 5000);
    var lat = Math.round(performance.now() - t0);
    if (r.ok) {
      var d = await r.json();
      var loc = (d.data && d.data.location) || [];
      var mainland = loc[0] === '中国' && NON_MAINLAND.indexOf(loc[1]) < 0;
      if (d.data && d.data.ip) {
        return {
          ok: true, ip: d.data.ip, latency: lat,
          cc: loc[0] ? (mainland ? 'CN' : 'OTHER') : '',
          region: (mainland ? '🇨🇳 ' : '') + [loc[0], loc[1], loc[2]].filter(Boolean).join(' '),
          detail: loc[4] || ''
        };
      }
    }
  } catch (e) {}
  var t1 = performance.now();
  var r2 = await fetchT('https://api-v3.speedtest.cn/ip');
  var lat2 = Math.round(performance.now() - t1);
  if (!r2.ok) return { ok: true, limited: true, latency: lat2 };
  var j = await r2.json();
  var dd = j.data || {};
  if (!dd.ip) return { ok: true, limited: true, latency: lat2 };
  var mainland2 = (dd.countryCode || '').toUpperCase() === 'CN' && NON_MAINLAND.indexOf(dd.province) < 0;
  return {
    ok: true, ip: dd.ip, latency: lat2,
    cc: dd.countryCode ? (mainland2 ? 'CN' : 'OTHER') : '',
    region: (mainland2 ? '🇨🇳 ' : '') + [dd.country, dd.province, dd.city].filter(Boolean).join(' '),
    detail: dd.operator || dd.isp || ''
  };
}
async function probe(t) {
  try {
    if (t.type === 'echo') return await probeEcho(t.url);
    if (t.type === 'trace') return await probeTrace(t.url);
    if (t.type === 'ipinfo') return await probeIpinfo(t.url);
    if (t.type === 'cn') return await probeCn();
    return await probePing(t.url);
  } catch (e) {
    return { ok: false, error: e.name === 'AbortError' ? '超时' : '无法连接' };
  }
}

function latCls(ms) { return ms < 200 ? 'fast' : ms < 500 ? 'mid' : 'slow'; }
function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }

function renderRows() {
  // 每个无 parent 的目标开启一个线路分组卡片，其子目标归入同组
  var html = '';
  var opened = false;
  TARGETS.forEach(function (t) {
    if (!t.parent) {
      if (opened) html += '</div>';
      html += '<div class="group">';
      opened = true;
    }
    // 父行不展示探针域名（内部实现细节）；子行展示真实站点域名
    html += '<div class="item' + (t.parent ? ' child' : ' parent') + '"><span class="dot" id="dot-' + t.id + '"></span><div class="info">'
      + '<div class="name">' + esc(t.name) + (t.parent ? '<span class="host">' + esc(t.host) + '</span>' : '') + '</div>'
      + '<div class="result" id="res-' + t.id + '"></div>'
      + '</div><span class="lat" id="lat-' + t.id + '"></span></div>';
  });
  if (opened) html += '</div>';
  $('list').innerHTML = html;
}

function setPending(t) {
  // 清空态不放文字行（避免比完成态更高导致行高变化），「检测中」由汇总条统一表达
  $('res-' + t.id).innerHTML = '';
  $('lat-' + t.id).textContent = '';
  var d = $('dot-' + t.id);
  d.style.background = '';
  d.classList.remove('on');
  // 新一轮检测开始，把上一轮缓存的结论清掉——不然 setResult() 会在
  // verdict() 算出新结论之前，先把上一轮的旧结论重新贴回去，等 verdict()
  // 再贴一条新的，就会看到同一条结论重复两遍。
  delete lastNotes[t.id];
}

// 截图隐藏开关：只打码 IP 和地区这类可定位到人的信息，延迟/连通性等结论保留。
// 全部打成星号看着像一坨乱码，反而不像"脱敏"——改成常见的部分脱敏：
// IP 留前两段（能看出是个 IP，看不出具体是谁），地区留国旗+国家（够看
// 分流对不对），城市/ISP 这些更具体的信息才打码。
var MASKED = false;
var lastResults = {};
function maskIp(ip) {
  if (!MASKED) return ip;
  var s = String(ip);
  if (s.indexOf(':') !== -1) {
    // IPv6：按冒号分组，前两组原样保留，其余每组打码（"::" 缩写产生的
    // 空分组原样保留，不然会破坏地址结构）
    return s.split(':').map(function (grp, i) {
      return (i < 2 || grp === '') ? grp : grp.replace(/./g, '*');
    }).join(':');
  }
  var segs = s.split('.');
  if (segs.length !== 4) return s.replace(/[0-9A-Za-z]/g, '*');
  return segs.map(function (seg, i) { return i < 2 ? seg : seg.replace(/./g, '*'); }).join('.');
}
function maskGeo(s) {
  if (!MASKED) return s;
  // 前两个词（国旗 emoji + 国家名）保留，后面的城市/ISP 才打码
  return String(s).split(' ').map(function (tok, i) {
    return i < 2 ? tok : tok.replace(/[0-9A-Za-z一-龥]/g, '*');
  }).join(' ');
}

// setResult 每次都会用 innerHTML 整段重建 .result（要重新塞打码后的
// IP/地区文本），如果 addNote() 已经往里面挂了一条结论，会被这次重建
// 直接冲掉。切换打码开关时会对已有结果重新调一遍 setResult，之前这里
// 没重新挂 note，导致一开打码结论文字就全没了——用 lastNotes 缓存住每个
// id 最后一条结论，setResult 重建完 innerHTML 后自己再补回去。
var lastNotes = {};

function clearNote(id) {
  var el = $('res-' + id);
  if (!el) return;
  el.querySelectorAll('.note').forEach(function (n) { n.remove(); });
}

function appendCachedNote(id) {
  var note = lastNotes[id];
  if (!note) return;
  clearNote(id);
  var el = $('res-' + id);
  if (!el) return;
  var n = document.createElement('div');
  n.className = 'note' + (note.cls ? ' ' + note.cls : '');
  n.textContent = note.text;
  el.appendChild(n);
}

function setResult(t, r) {
  lastResults[t.id] = r;
  var el = $('res-' + t.id);
  var latEl = $('lat-' + t.id);
  // 新结果就位，解除清空阶段冻结的行高
  var row = el.closest('.item');
  if (row) row.style.minHeight = '';
  if (!r.ok) {
    el.innerHTML = '<span class="fail">\\u2715 ' + esc(r.error) + '</span>';
    appendCachedNote(t.id);
    return;
  }
  if (r.latency !== undefined) {
    latEl.textContent = r.latency + 'ms';
    latEl.className = 'lat ' + latCls(r.latency);
  }
  if (r.ip) {
    var parts = [r.region, r.detail].filter(Boolean).join(' \\u00b7 ');
    el.innerHTML = '<span class="ipv">' + esc(maskIp(r.ip)) + '</span><span class="geo">' + esc(maskGeo(parts)) + '</span>';
  } else if (r.limited) {
    el.innerHTML = '<span class="okonly">\\u5df2\\u8fde\\u901a\\uff08\\u8bfb\\u53d6\\u53d7\\u9650\\uff09</span>';
  } else {
    // 连通性子行：绿色圆点 + 延迟已足够表达成功，不再堆「已连通」文字
    el.innerHTML = '';
  }
  appendCachedNote(t.id);
}

function addNote(id, text, cls) {
  lastNotes[id] = { text: text, cls: cls };
  clearNote(id);
  var el = $('res-' + id);
  if (!el) return;
  var n = document.createElement('div');
  n.className = 'note' + (cls ? ' ' + cls : '');
  n.textContent = text;
  el.appendChild(n);
}

function verdict(byId) {
  var summary = $('summary');
  var ai     = byId.ai     && byId.ai.ip     ? byId.ai     : null;  // 住宅IP 线
  var relay  = byId.relay  && byId.relay.ip  ? byId.relay  : null;  // 机场中转线
  var direct = byId.direct && byId.direct.ip ? byId.direct : null;  // 未分类境外（应直连）
  var cn     = byId.cn     && byId.cn.ip     ? byId.cn     : null;  // 国内直连
  var aiK = ai && exitKey(ai), relayK = relay && exitKey(relay);
  var directK = direct && exitKey(direct), cnK = cn && exitKey(cn);
  // 出口 IP 偶发读不到时，用同线路子站点的连通性兜底推断该线路死活
  var aiOk = ['claude', 'chatgpt', 'gemini'].some(function (id) { return byId[id] && byId[id].ok && !byId[id].error; });
  var relayOk = ['wiki', 'bbc', 'youtube'].some(function (id) { return byId[id] && byId[id].ok && !byId[id].error; });

  // 线路汇总——用于给各行圆点按线路配色。境外线路按 /24 网段区分，
  // 境内线路按国家码归并（同一条本地宽带 IPv4/IPv6 双栈不算两条线，
  // 原因见 exitKey 定义处的注释）
  var exits = {}; var order = [];
  [['ai', ai], ['relay', relay], ['direct', direct], ['cn', cn]].forEach(function (p) {
    if (!p[1]) return;
    var k = exitKey(p[1]);
    if (!exits[k]) { exits[k] = 1; order.push(k); }
  });

  // 本地出口基准：国内直连读到的最可信，其次用未分类境外那条
  var localK = cnK || directK;
  // 未开代理：AI 站点都走到了国内出口
  var noProxy = (ai && ai.cc === 'CN') || (!ai && !aiOk && relay && relay.cc === 'CN');
  // 国内网站没直连（客户端开了全局，或配置有问题）
  var cnProxied = cn && cn.cc && cn.cc !== 'CN';
  // 锁定境外出口模式：三条境外线路收敛到同一出口，国内仍直连
  var lockMode = aiK && relayK && aiK === relayK && cnK && aiK !== cnK;
  // 🚨 境外规则集失效：中转线塌陷回本地出口 → 部分境外站点会打不开（AI 线仍正常，
  // 所以症状是"只有国内和 AI 站点能用"，安卓 FlClash 上真实出现过）
  var rulesetDown = relayK && localK && relayK === localK && aiK && aiK !== relayK;
  // 旧版配置：未分类境外也被送去中转（新版应走直连以省流量）。锁定模式下
  // 三条境外线本来就同出口，不能算旧版，必须先排除
  var legacyMode = !lockMode && directK && relayK && directK === relayK && cnK && directK !== cnK;
  var headline, cls;

  if (order.length === 0) {
    headline = (cn || (byId.cn && byId.cn.ok))
      ? '⚠ 未能读取到出口 IP，请稍后重试'
      : '⚠ 检测失败：连国内网站都无法访问。请检查设备网络，或代理客户端是否卡死';
    cls = 'warn';
  } else if (noProxy) {
    headline = '⚠ 未检测到代理：AI 站点走的是国内出口，无法正常使用。请先开启代理客户端再检测';
    cls = 'warn';
  } else if (cnProxied) {
    headline = '⚠ 国内网站没有直连（出口在境外），流量与速度都会被浪费。请确认客户端处于「规则」模式';
    cls = 'warn';
  } else if (lockMode) {
    headline = '✓ 「锁定境外出口」模式生效中：境外流量统一走静态住宅IP，国内直连';
    cls = 'ok';
  } else if (rulesetDown) {
    headline = '⚠ 境外规则集未生效：部分境外站点会打不开（只有国内和 AI 站点可用）。请检查网络后重新载入配置，或重新生成';
    cls = 'warn';
  } else if (legacyMode) {
    headline = '! 检测到旧版配置：未分类流量也走了中转，会持续消耗机场流量。建议重新生成配置';
    cls = 'warn';
  } else if (aiK && relayK && aiK !== relayK && directK && cnK && directK === cnK) {
    headline = '✓ 分流完全正常：AI 走住宅IP、被墙站点走中转、其余境外与国内均直连（省流量）';
    cls = 'ok';
  } else if (!relayK && relayOk && aiK && cnK && aiK !== cnK) {
    // 中转出口读取失败但被墙站点连通：降级判定
    headline = '✓ 分流工作正常：AI 专线与被墙站点均连通，国内直连（中转出口读取失败，可重试）';
    cls = 'ok';
  } else if (!aiK && aiOk && relayK && cnK && relayK !== cnK) {
    // AI 出口读取失败但 AI 站点连通：降级判定
    headline = '✓ 分流工作正常：中转与国内直连均正常，AI 站点连通（AI 出口读取失败，可重试）';
    cls = 'ok';
  } else if (order.length > 1) {
    headline = '✓ 检测到 ' + order.length + ' 个不同出口，分流已生效';
    cls = 'ok';
  } else {
    headline = '! 所有可读取的站点走同一出口，未检测到分流';
    cls = 'warn';
  }

  function rank(k) { return k === aiK ? 0 : k === relayK ? 1 : k === directK ? 2 : 3; }

  // 汇总只展示一句结论；线路明细由下方三张卡片承载，这里只负责给圆点按线路上色
  order.sort(function (a, b) { return rank(a) - rank(b); }).forEach(function (k, i) {
    [['ai', ai], ['relay', relay], ['direct', direct], ['cn', cn]].forEach(function (p) {
      if (p[1] && exitKey(p[1]) === k) {
        var d = $('dot-' + p[0]);
        d.style.background = COLORS[i % COLORS.length];
        d.classList.add('on');
      }
    });
  });
  summary.innerHTML = '<div class="headline ' + cls + '">' + headline + '</div>';
  summary.style.display = 'block';

  // 子行圆点继承父行线路颜色（连通性子行本身不带 IP）
  TARGETS.forEach(function (t) {
    if (!t.parent || !byId[t.id] || !byId[t.id].ok) return;
    var pd = $('dot-' + t.parent);
    var d = $('dot-' + t.id);
    if (pd && d && pd.classList.contains('on') && pd.style.background) {
      d.style.background = pd.style.background;
      d.classList.add('on');
    }
  });

  // 行级标注（未开代理 / 国内被代理属全局性异常，此时不再逐行解释）。
  // 四张卡片都配一条结论，行数、行高对齐，视觉上不会有的卡片矮一截
  if (!noProxy && !cnProxied) {
    if (!ai && aiOk) {
      addNote('ai', 'AI 出口读取失败（不影响站点使用），可点「重新检测」重试', 'warn');
    } else if (aiK) {
      addNote('ai', '✓ 走静态住宅IP，AI 账号更不容易被风控或封禁', 'ok');
    }
    if (!relay && relayOk) {
      addNote('relay', '被墙站点出口读取失败，但被墙站点连通正常，可点「重新检测」重试', 'warn');
    } else if (rulesetDown) {
      addNote('relay', '⚠ 塌陷到本地出口：境外规则集没生效，部分境外站点会打不开', 'warn');
    } else if (lockMode && relayK && aiK && relayK === aiK) {
      addNote('relay', '✓ 锁定模式下，同样统一走住宅IP', 'ok');
    } else if (lockMode) {
      addNote('relay', '⚠ 开着锁定模式，但这次测出的出口跟住宅IP不一致，建议重新生成配置', 'warn');
    } else if (relayK && aiK && relayK !== aiK) {
      addNote('relay', '✓ 与住宅IP分开走，被墙站点不消耗住宅IP流量', 'ok');
    }
    if (lockMode && directK && aiK && directK === aiK) {
      addNote('direct', '✓ 锁定模式下，境外流量统一走住宅IP', 'ok');
    } else if (lockMode) {
      addNote('direct', '⚠ 开着锁定模式，但这次测出的出口跟住宅IP不一致，建议重新生成配置', 'warn');
    } else if (directK && cnK && directK === cnK) {
      addNote('direct', '✓ 走直连，既不消耗中转流量也不消耗住宅IP流量', 'ok');
    } else if (legacyMode) {
      addNote('direct', '⚠ 走了中转：旧版配置会让未分类流量持续消耗机场流量', 'warn');
    }
    if (cnK) {
      addNote('cn', '✓ 走直连，不占用任何代理流量，速度最快', 'ok');
    }
  }
}

async function runCheck() {
  if (running) return;
  running = true;
  var btn = $('run');
  btn.disabled = true;
  btn.textContent = '\\u68c0\\u6d4b\\u4e2d\\u2026';
  // 汇总区不隐藏（避免页面高度跳动），显示检测中占位
  var s = $('summary');
  s.innerHTML = '<div class="headline">检测中…</div>';
  // 清空前把每行高度冻结在当前值，新结果填入时再解冻——重新检测全程零跳动
  document.querySelectorAll('.item').forEach(function (el) {
    el.style.minHeight = el.getBoundingClientRect().height + 'px';
  });
  TARGETS.forEach(setPending);
  var byId = {};
  await Promise.all(TARGETS.map(async function (t) {
    var r = await probe(t);
    byId[t.id] = r;
    setResult(t, r);
  }));
  // 未分类站点出口用 ipinfo.io（通用境外地理库），国内直连用 ipip.net
  // （专攻中国 IP、城市级精度更高）——两边巧合命中同一个 IP 时（未分类
  // 流量这次也走了直连、跟国内直连是同一个出口），ipinfo.io 对国内 IP
  // 的地区粒度经常比 ipip.net 粗（例如只能查到注册城市"广州"，查不出
  // 实际使用城市"深圳"），会让用户看到同一个 IP 却显示两个不同地区、
  // 误以为是检测出错。这里改成直接复用 ipip.net 那份更准的结果重新渲染，
  // 真的是两个不同 IP 的正常情况（未分类流量确实是境外出口）不受影响。
  if (byId.direct && byId.cn && byId.direct.ip && byId.direct.ip === byId.cn.ip) {
    byId.direct.region = byId.cn.region;
    byId.direct.detail = byId.cn.detail;
    var directTarget = TARGETS.filter(function (t) { return t.id === 'direct'; })[0];
    if (directTarget) setResult(directTarget, byId.direct);
  }
  verdict(byId);
  btn.disabled = false;
  btn.textContent = '\\u91cd\\u65b0\\u68c0\\u6d4b';
  running = false;
}

renderRows();
$('run').addEventListener('click', runCheck);
$('maskToggle').addEventListener('change', function () {
  MASKED = this.checked;
  // 不重新检测，只用已有结果重新渲染，打码/取消打码瞬间完成
  TARGETS.forEach(function (t) {
    if (lastResults[t.id] !== undefined) setResult(t, lastResults[t.id]);
  });
});
setTimeout(runCheck, 50);
</script>
</body>
</html>`;
