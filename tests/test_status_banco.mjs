// Testes do STATUS DO BANCO (Bloco 4): apiFetch + banner #db-status + checkServer/visibilitychange + meta tags
// Uso: node test_status_banco.mjs /caminho/para/app/index.html
//
// Mesmo harness de test_paginacao.mjs (script inline real em vm + DOM stub),
// com fetch, setTimeout e document.addEventListener controláveis.


import vm from 'node:vm';
import fs from 'node:fs';
import path from 'node:path';
import { TextEncoder, TextDecoder } from 'node:util';
import { webcrypto } from 'node:crypto';

const htmlPath = process.argv[2];
if (!htmlPath) { console.error('Informe o caminho do HTML.'); process.exit(2); }
const html = fs.readFileSync(htmlPath, 'utf8');
// Bloco 5: o JS mora em app/app.js, ao lado do index.html recebido
const jsPath = path.join(path.dirname(htmlPath), 'app.js');
if (!fs.existsSync(jsPath)) { console.error('app.js não encontrado ao lado do HTML.'); process.exit(2); }
const scriptSource = fs.readFileSync(jsPath, 'utf8');

// ---------- stubs ----------
class NodeStub {}
const escText = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escAttr = (s) => escText(s).replace(/"/g, '&quot;');
const VOID_TAGS = new Set(['input', 'br', 'hr', 'img']);

function serializeNode(node) {
    if (node._isText) return escText(node.textContent || '');
    if (node._explicitHtml !== null) return node._explicitHtml;
    const attrs = Object.assign({}, node._attrs);
    if (node.id) attrs.id = node.id;
    if (node.className) attrs.class = node.className;
    const tag = node.tagName;
    if ((tag === 'input' || tag === 'textarea' || tag === 'select') && node.value !== '') attrs.value = node.value;
    const attrStr = Object.keys(attrs).map((k) => ` ${k}="${escAttr(attrs[k])}"`).join('');
    if (VOID_TAGS.has(tag)) return `<${tag}${attrStr}>`;
    const inner = node.children.map(serializeNode).join('') + escText(node.textContent || '');
    return `<${tag}${attrStr}>${inner}</${tag}>`;
}

function makeDocument() {
    const elements = new Map();
    const doc = {
        _register(id, el) { elements.set(id, el); },
        _unregister(id) { elements.delete(id); },
        getElementById(id) {
            if (elements.has(id)) return elements.get(id);
            if (id === 'modal-overlay') return null;
            const el = makeEl('div', doc);
            el.id = id;
            elements.set(id, el);
            return el;
        },
        createElement(tag) { return makeEl(tag, doc); },
        createTextNode(text) {
            const n = new NodeStub();
            n._isText = true; n._explicitHtml = null; n._attrs = {}; n.children = [];
            n.textContent = String(text);
            return n;
        },
        querySelectorAll() { return []; },
        getElementsByClassName() { return []; },
        addEventListener() {},
        body: null,
    };
    doc.body = makeEl('body', doc);
    return doc;
}

function makeEl(tag = 'div', doc = null) {
    const el = new NodeStub();
    Object.assign(el, {
        tagName: tag, value: '', innerText: '', textContent: '',
        checked: false, className: '', title: '', style: {}, dataset: {},
        children: [], _removed: false, _parent: null,
        _explicitHtml: null, _attrs: {}, _isText: false,
        classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
        appendChild(c) {
            if (c._parent && typeof c._parent.removeChild === 'function') c._parent.removeChild(c);
            this.children.push(c); c._parent = this; return c;
        },
        removeChild(c) {
            const i = this.children.indexOf(c);
            if (i >= 0) this.children.splice(i, 1);
            c._parent = null; return c;
        },
        setAttribute(k, v) { if (k === 'id') { this.id = v; return; } this._attrs[k] = String(v); },
        getAttribute(k) { return k in this._attrs ? this._attrs[k] : null; },
        addEventListener() {},
        remove() { this._removed = true; if (this._parent) this._parent.removeChild(this); if (doc && this.id) doc._unregister(this.id); },
        getContext() { return {}; },
        querySelectorAll() { return []; },
    });
    let _html = null;
    Object.defineProperty(el, 'innerHTML', {
        get() { return _html !== null ? _html : serializeNode(el); },
        set(v) { _html = String(v); if (_html === '') el.children = []; },
    });
    let _id = '';
    Object.defineProperty(el, 'id', {
        get() { return _id; },
        set(v) { _id = String(v); if (doc) doc._register(_id, el); },
    });
    return el;
}

const documentStub = makeDocument();
const docHandlers = {};
documentStub.addEventListener = (ev, fn) => { (docHandlers[ev] = docHandlers[ev] || []).push(fn); };
documentStub.visibilityState = 'visible';

// fetch controlável: fetchMode = 'ok' | 'throw' | 'defer' | número (status HTTP)
let fetchMode = 'ok';
const fetchCalls = [];
const deferred = [];
const timers = new Map();   // timers vivos (clearTimeout remove)
let timerSeq = 0;
const TIMEOUT_SIGNAL = { probe: true };
const jsonByUrl = {};   // resposta JSON por URL (padrão: kv vazio)
const respond = (status, url) => ({ ok: status < 400, status, json: async () => jsonByUrl[url] || { ok: true, value: null } });
const sandbox = {
    document: documentStub,
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    fetch: (url, opts) => {
        fetchCalls.push({ url: String(url), opts: opts || {} });
        if (fetchMode === 'throw') return Promise.reject(new TypeError('Failed to fetch'));
        if (fetchMode === 'defer') return new Promise((resolve) => deferred.push(resolve));
        return Promise.resolve(respond(fetchMode === 'ok' ? 200 : fetchMode, String(url)));
    },
    AbortSignal: { timeout: (ms) => (TIMEOUT_SIGNAL.ms = ms, TIMEOUT_SIGNAL) },
    Node: NodeStub, TextEncoder, TextDecoder, crypto: webcrypto,
    btoa: globalThis.btoa, atob: globalThis.atob,
    console, Date, Math, JSON, parseInt, parseFloat, isNaN, String, Number, Array, Object, RegExp, Error, TypeError,
    setTimeout: (fn, ms) => { timers.set(++timerSeq, { fn, ms }); return timerSeq; },
    clearTimeout: (id) => { timers.delete(id); }, setInterval: () => 1, clearInterval: () => {},
};
sandbox.window = sandbox;
vm.createContext(sandbox);
vm.runInContext(scriptSource, sandbox, { filename: 'sistema_inline.js' });

const run = (code) => vm.runInContext(code, sandbox);
run('var __toasts = []; showToast = function (m, t) { __toasts.push({ msg: String(m), type: t || "error" }); };');

const banner = () => documentStub.getElementById('db-status');
const liveTimers = (ms) => [...timers.values()].filter((t) => t.ms === ms);
const tick = () => new Promise((r) => setImmediate(r));
function reset(online) {
    fetchMode = 'ok'; fetchCalls.length = 0; deferred.length = 0; timers.clear();
    run(`__toasts.length = 0; dbOnline = ${online}; dbRetryTimer = null; system = {};`);
    banner().hidden = online;
}
const toasts = () => run('__toasts');
const probes = () => fetchCalls.filter((c) => c.url === '/api/kv/bpa_ping');

let passed = 0, failed = 0;
async function test(name, fn) {
    try { await fn(); console.log(`  ✔ ${name}`); passed++; }
    catch (e) { console.log(`  ✘ ${name}\n    -> ${e.message}`); failed++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

console.log('Testes do STATUS DO BANCO (Bloco 4)\n');

await test('1. fetch lança (servidor fora) → apiFetch relança e o banner aparece', async () => {
    reset(true);
    fetchMode = 'throw';
    let threw = false;
    try { await run('apiFetch("/api/kv/x")'); } catch (_) { threw = true; }
    assert(threw, 'apiFetch deveria relançar o erro de rede');
    assert(banner().hidden === false, 'banner deveria estar visível');
    assert(run('dbOnline') === false, 'dbOnline deveria ser false');
});

await test('2. HTTP 500 (servidor não grava) → banner; HTTP 400 → sem banner', async () => {
    reset(true);
    fetchMode = 400;
    await run('apiFetch("/api/kv/x")');
    assert(banner().hidden === true, '400 não é queda — banner deveria seguir oculto');
    fetchMode = 500;
    await run('apiFetch("/api/kv/x")');
    assert(banner().hidden === false, '500 deveria mostrar o banner');
});

await test('3. offline → resposta ok: banner some e "reconectado" aparece UMA vez', async () => {
    reset(false);
    await run('apiFetch("/api/kv/x")');
    await run('apiFetch("/api/kv/x")');
    assert(banner().hidden === true, 'banner deveria sumir');
    const ok = toasts().filter((t) => t.type === 'success' && /reconectado/.test(t.msg));
    assert(ok.length === 1, 'esperado 1 toast de reconexão, veio ' + ok.length);
});

await test('3b. reconexão sem dados carregados (system = null) → aviso pede F5', async () => {
    reset(false);
    run('system = null;');
    await run('apiFetch("/api/kv/x")');
    assert(toasts().some((t) => /F5/.test(t.msg)), 'aviso deveria pedir F5: ' + JSON.stringify(toasts()));
});

await test('4. visibilitychange: aba visível dispara a sonda; aba oculta não; sonda de 10 s ligada', async () => {
    reset(true);
    run('bindServerWatch()');
    assert(liveTimers(10000).length === 1, 'bindServerWatch deveria ligar a sonda de 10 s');
    const h = (docHandlers.visibilitychange || []).slice(-1)[0];
    assert(h, 'handler de visibilitychange não registrado');
    documentStub.visibilityState = 'hidden';
    await h();
    assert(probes().length === 0, 'aba oculta não deveria sondar o servidor');
    documentStub.visibilityState = 'visible';
    await h();
    assert(probes().length === 1, 'aba visível deveria sondar o servidor');
});

await test('5. sonda a cada 10 s online E offline, sem empilhar timers', async () => {
    reset(true);
    fetchMode = 'throw';
    await run('checkServer()');
    await run('checkServer()');
    assert(liveTimers(10000).length === 1, 'esperado 1 timer vivo de 10 s, veio ' + liveTimers(10000).length);
    fetchMode = 'ok';
    liveTimers(10000)[0].fn();
    await tick();
    assert(banner().hidden === true, 'servidor voltou: banner deveria sumir');
    assert(liveTimers(10000).length === 1 && timers.size === 1, 'online: segue 1 sonda de 10 s (run.py depende disso)');
});

await test('6. HTML: meta tags do Bloco 4, tema escuro nos controles nativos e banner acessível', () => {
    const must = [
        /<meta name="description" content="[^"]+">/,
        /<meta name="robots" content="noindex, nofollow">/,
        /<meta name="theme-color" content="#2c3e50">/,
        /body\.dark-mode \{\s*color-scheme: dark;/,
        /<div id="db-status" class="db-status" role="status"[^>]*hidden>/,
    ];
    const missing = must.filter((re) => !re.test(html));
    assert(missing.length === 0, 'ausentes: ' + missing.join(' | '));
    assert(!/<meta name="color-scheme"/.test(html), 'meta color-scheme deixaria o SO decidir o tema dos controles');
});

await test('7. disco cheio: sonda é uma GRAVAÇÃO — 500 persistente mantém o banner (não usa /api/health)', async () => {
    reset(true);
    fetchMode = 500;
    await run('checkServer()');
    assert(banner().hidden === false, '500 deveria mostrar o banner');
    await run('checkServer()');
    assert(banner().hidden === false, 'ainda 500: banner não pode sumir');
    assert(probes().length === 2 && probes()[0].opts.method === 'PUT', 'sonda deveria ser PUT em bpa_ping');
    assert(!fetchCalls.some((c) => c.url === '/api/health'), '/api/health não toca o banco — não serve de prova');
    fetchMode = 'ok';
    await run('checkServer()');
    assert(banner().hidden === true, 'gravação voltou: banner deveria sumir');
});

await test('8. resposta atrasada de antes da queda NÃO apaga o banner', async () => {
    reset(true);
    fetchMode = 'defer';
    const a = run('apiFetch("/api/kv/a")');       // pedido A sai antes da queda
    fetchMode = 'throw';
    try { await run('apiFetch("/api/kv/b")'); } catch (_) {}  // B falha: servidor caiu
    assert(banner().hidden === false, 'B falhou: banner deveria aparecer');
    deferred[0](respond(200));                    // A chega depois, com 200
    await a;
    assert(banner().hidden === false, 'resposta velha de A não pode marcar online');
    assert(liveTimers(10000).length === 1, 're-checagem de 10 s deveria seguir agendada');
});

await test('9. servidor travado: sonda usa timeout de 5 s (AbortSignal)', async () => {
    reset(true);
    await run('checkServer()');
    assert(probes()[0].opts.signal === TIMEOUT_SIGNAL && TIMEOUT_SIGNAL.ms === 5000, 'sonda deveria ter signal com timeout de 5000 ms');
});

await test('10. CSS: banner acima da tela de senha (.auth-overlay) e fora do topo (não cobre abas/tema)', () => {
    const z = (sel) => Number((html.match(new RegExp('\\.' + sel + ' \\{[^}]*z-index: (\\d+)')) || [])[1]);
    assert(z('db-status') > z('auth-overlay'), `z-index do banner (${z('db-status')}) deveria superar .auth-overlay (${z('auth-overlay')})`);
    const rule = (html.match(/\.db-status \{[^}]*\}/) || [''])[0];
    assert(/position: fixed/.test(rule) && /bottom: 0/.test(rule) && !/sticky/.test(rule), 'banner deveria ser rodapé fixo: ' + rule);
});

await test('11. Aba Segurança: status do backup mostra data/hora do último e quantos estão guardados', async () => {
    reset(true);
    jsonByUrl['/api/backup/status'] = { ultimo: '2026-10-24T18:00:00', arquivo: 'backup_2026-10-24.db', total: 3, erro: null };
    await run('loadBackupStatus()');
    const t = documentStub.getElementById('backup-status').textContent;
    assert(/Último backup automático: 24\/10\/2026/.test(t) && /3 guardados/.test(t), 'texto inesperado: ' + t);
});

await test('12. Aba Segurança: falha do backup aparece como erro (com o motivo)', async () => {
    reset(true);
    jsonByUrl['/api/backup/status'] = { ultimo: null, arquivo: null, total: 0, erro: 'Permission denied' };
    await run('loadBackupStatus()');
    const el = documentStub.getElementById('backup-status');
    assert(/Falha no backup automático/.test(el.textContent) && /Permission denied/.test(el.textContent), 'texto inesperado: ' + el.textContent);
    assert(banner().hidden === true, 'falha de backup não é queda do banco: faixa vermelha deveria seguir oculta');
});

await test('13. HTML: botão "Abrir pasta de backups" existe e a aba Segurança recarrega o status', () => {
    assert(/id="btn-open-backups"/.test(html), 'botão ausente');
    assert(/tabId === 'tab-seguranca'\) \{[^}]*loadBackupStatus\(\)/.test(scriptSource), 'openTab da aba Segurança deveria chamar loadBackupStatus()');
});

await test('14. Aba Segurança: resposta não-ok (ex.: 404) mostra "Status indisponível", não "Nenhum backup"', async () => {
    reset(true);
    fetchMode = 404;
    await run('loadBackupStatus()');
    const t = documentStub.getElementById('backup-status').textContent;
    assert(/indisponível/.test(t), 'texto inesperado: ' + t);
});

await test('15. Avisos: texto sem espaços quebra dentro do cartão (cartão e faixa urgente)', () => {
    for (const sel of ['note-card', 'urgent-banner']) {
        const rule = (html.match(new RegExp('\\.' + sel + ' \\{[^}]*\\}')) || [''])[0];
        assert(/overflow-wrap: anywhere/.test(rule), `.${sel} deveria ter overflow-wrap: anywhere: ` + rule);
    }
    assert(/\.note-card \{[^}]*min-width: 0/.test(html), '.note-card deveria ter min-width: 0 (item de grid não estica pela palavra longa)');
});

await test('16. Tabelas: só as colunas de texto livre quebram (usuário, matrícula/nome, alvo/detalhes); datas e botões não', () => {
    const rule = (html.match(/((?:#(?:users|registration|audit)-table td:nth-child\(\d\),?\s*)+)\{([^}]*)\}/) || []);
    assert(rule.length, 'regra de quebra das colunas de texto não encontrada');
    const sels = rule[1].replace(/\s+/g, ' ');
    for (const c of ['#users-table td:nth-child(1)', '#registration-table td:nth-child(1)',
                     '#registration-table td:nth-child(2)', '#audit-table td:nth-child(3)', '#audit-table td:nth-child(5)']) {
        assert(sels.includes(c), 'faltou a coluna ' + c);
    }
    assert(/overflow-wrap: anywhere/.test(rule[2]) && /min-width/.test(rule[2]), 'regra deveria ter overflow-wrap: anywhere e min-width: ' + rule[2]);
    assert(!/(?:th, td|td) \{[^}]*overflow-wrap/.test(html), 'não aplicar em TODAS as células (datas quebrariam no meio)');
});

console.log(`\nResultado: ${passed} aprovados, ${failed} reprovados.`);
process.exit(failed ? 1 : 0);
