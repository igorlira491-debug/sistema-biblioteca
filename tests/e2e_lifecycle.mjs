// E2E — ciclo de vida real contra o servidor Python + SQLite:
//   1. instalação automática (senha de fábrica) via app real;
//   2. gravação de cadastro + sessão pela camada cifrada (HTTP real);
//   3. "F5": contexto novo → bootstrap → login → dados decifrados intactos;
//   4. corte de energia: kill -9 no servidor → app degrada sem mentira
//      (persistOrWarn false, bootstrap NÃO reinstala);
//   5. servidor volta → F5 → login → tudo lá.
//
// Uso: node tests/e2e_lifecycle.mjs   (servidor é spawnado pelo próprio teste)

import vm from 'node:vm';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { TextEncoder, TextDecoder } from 'node:util';
import { webcrypto } from 'node:crypto';

const PROJ = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 8799;
const BASE = `http://127.0.0.1:${PORT}`;
const DATA = '/tmp/bpa_e2e_data';
const SENHA = '123456789';

// ---------- servidor ----------
function spawnServer() {
    const p = spawn('python3', ['run.py', '--sem-navegador', '--porta', String(PORT), '--data', DATA], {
        cwd: PROJ, stdio: ['ignore', 'pipe', 'pipe'],
    });
    p.stdout.on('data', () => {});
    p.stderr.on('data', (d) => process.stderr.write('[servidor] ' + d));
    return p;
}
async function waitForHealth(timeoutMs = 8000) {
    const t0 = Date.now();
    while (Date.now() - t0 < timeoutMs) {
        try {
            const r = await fetch(`${BASE}/api/health`);
            if (r.ok) return true;
        } catch (_) { /* servidor ainda subindo */ }
        await new Promise((r) => setTimeout(r, 150));
    }
    throw new Error('servidor não respondeu no tempo esperado');
}

// ---------- stub de DOM (mínimo para os fluxos de bootstrap/login) ----------
class NodeStub {}
function makeDocument() {
    const elements = new Map();
    const doc = {
        _register: (id, el) => elements.set(id, el),
        getElementById(id) {
            if (elements.has(id)) return elements.get(id);
            if (id === 'modal-overlay') return null;  // semântica de existência
            const el = makeEl('div', doc);
            el.id = id;
            elements.set(id, el);
            return el;
        },
        createElement: (tag) => makeEl(tag, doc),
        createTextNode(text) {
            const n = new NodeStub();
            Object.assign(n, { _isText: true, textContent: String(text), children: [] });
            return n;
        },
        querySelectorAll: () => [],
        getElementsByClassName: () => [],
        addEventListener() {},
        body: null,
    };
    doc.body = makeEl('body', doc);
    return doc;
}
function makeEl(tag, doc) {
    const el = new NodeStub();
    Object.assign(el, {
        tagName: tag, value: '', textContent: '', checked: false, className: '',
        style: {}, dataset: {}, children: [], _attrs: {}, _parent: null, _isText: false,
        innerText: '', title: '',
        classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
        appendChild(c) { this.children.push(c); c._parent = this; return c; },
        removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); return c; },
        setAttribute(k, v) { if (k === 'id') { this.id = v; return; } this._attrs[k] = String(v); },
        getAttribute(k) { return this._attrs[k] ?? null; },
        addEventListener() {},
        remove() { this._removed = true; if (doc && this.id) doc._unregister(this.id); },
        getContext: () => ({}),
        querySelectorAll: () => [],
    });
    let html = '';
    Object.defineProperty(el, 'innerHTML', { get: () => html, set(v) { html = String(v); if (html === '') el.children = []; } });
    let _id = '';
    Object.defineProperty(el, 'id', { get: () => _id, set(v) { _id = String(v); if (doc) doc._register(_id, el); } });
    return el;
}

// ---------- contexto de "página" (1 ctx = 1 F5) ----------
const scriptSource = fs.readFileSync(path.join(PROJ, 'app', 'app.js'), 'utf8');   // Bloco 5: JS fora do HTML

function makePage() {
    const documentStub = makeDocument();
    const intervals = [];
    const sandbox = {
        document: documentStub,
        localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
        fetch: (u, init) => fetch(BASE + u, init),
        Node: NodeStub, TextEncoder, TextDecoder, crypto: webcrypto,
        btoa: globalThis.btoa, atob: globalThis.atob,
        console, Date, Math, JSON, parseInt, parseFloat, isNaN,
        String, Number, Array, Object, RegExp, Error,
        setTimeout: () => 1, clearTimeout: () => {},
        setInterval: (cb) => { intervals.push(cb); return intervals.length; },
        clearInterval: () => {},
    };
    sandbox.window = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(scriptSource, sandbox, { filename: 'sistema_inline.js' });
    const run = (code) => vm.runInContext(code, sandbox);
    run('var __toasts = [];');
    run('showToast = function(msg, type) { __toasts.push({ msg: msg, type: type || "error" }); };');
    run('var __updatedMetrics = 0; updateMetrics = function() { __updatedMetrics++; };');
    return { run, getToast: () => run('__toasts[__toasts.length - 1]') };
}

// ---------- asserts ----------
let passed = 0, failed = 0;
async function step(name, fn) {
    try { await fn(); console.log(`  ✔ ${name}`); passed++; }
    catch (e) { console.log(`  ✘ ${name}\n    -> ${e.message}`); failed++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }
async function httpGet(key) {
    const r = await fetch(`${BASE}/api/kv/${key}`);
    return (await r.json()).value;
}

// ================= E2E =================
console.log('E2E — ciclo de vida (instalação → F5 → corte de energia → recuperação)\n');
fs.rmSync(DATA, { recursive: true, force: true });
let server = spawnServer();
try {
    await waitForHealth();

    await step('1. Instalação automática persiste sistema + instalação no SQLite (envelope cifrado)', async () => {
        const page = makePage();
        await page.run('bootstrap()');
        assert(page.run('system') !== null, 'system não foi criado');
        assert(page.run('installMeta') !== null, 'installMeta não foi criado');
        const sysRaw = await httpGet('bpa_system');
        assert(sysRaw, 'bpa_system ausente');
        const sys = JSON.parse(sysRaw);
        // formato previsto: JSON de metadados com DEK envelopada (iv/data) pela senha e pelo código
        assert(sys.password && sys.password.envelope && sys.password.envelope.iv && sys.password.envelope.data,
            'bpa_system sem envelope de senha: ' + String(sysRaw).slice(0, 80));
        assert(sys.recovery && sys.recovery.envelope && sys.recovery.envelope.data, 'bpa_system sem envelope de recuperação');
        const instRaw = await httpGet('bpa_install');
        assert(instRaw && JSON.parse(instRaw).schemaVersion === 2, 'bpa_install inválido');
    });

    await step('2. Cadastro e sessão gravados cifrados via HTTP (PII não aparece em claro no banco)', async () => {
        const page = makePage();
        await page.run('bootstrap()');
        const r = await page.run(`attemptLogin(${JSON.stringify(SENHA)})`);
        assert(r.ok === true, 'login de fábrica falhou: ' + (r && r.msg));
        page.run(`userBase.push({ id: 100, matricula: 'abc1', nome: 'Maria Silva', nascimento: '1990-01-01', categoria: 'Adulto', validade: '2099-12-31' });`);
        const okUser = await page.run('persistOrWarn("bpa_user_base", userBase)');
        assert(okUser === true, 'persistOrWarn(userBase) falhou');
        page.run(`sessions.push({ sessionId: 1, userId: 100, pc: 3, status: 'Inativo', entrada: '09:00:00', entradaFull: '2026-10-20T09:00:00.000Z', saida: '10:00:00', saidaFull: '2026-10-20T10:00:00.000Z' });`);
        const okSess = await page.run('persistOrWarn("bpa_sessions", sessions)');
        assert(okSess === true, 'persistOrWarn(sessions) falhou');
        const userRaw = await httpGet('bpa_user_base');
        assert(userRaw.startsWith('{"iv"'), 'userBase não cifrado no banco');
        assert(!userRaw.includes('Maria Silva'), 'PII vazou em claro no banco!');
        // exercício da reentrada sobre o servidor real
        const re = await page.run('registerReentry(1, 5)');
        assert(re.ok === true, 'registerReentry falhou: ' + re.message);
    });

    await step('3. F5: contexto novo faz bootstrap + login e lê os dados decifrados', async () => {
        const page = makePage();
        await page.run('bootstrap()');
        assert(page.run('system') !== null, 'bootstrap não recuperou o system');
        const err = await page.run(`attemptLogin("senha-errada")`);
        assert(err.ok === false, 'senha errada deveria falhar');
        const r = await page.run(`attemptLogin(${JSON.stringify(SENHA)})`);
        assert(r.ok === true, 'login falhou após F5: ' + (r && r.msg));
        const users = JSON.parse(page.run('JSON.stringify(userBase)'));
        assert(users.length === 1 && users[0].nome === 'Maria Silva', 'cadastro não sobreviveu ao F5: ' + JSON.stringify(users));
        const sess = JSON.parse(page.run('JSON.stringify(sessions)'));
        assert(sess.length === 2, 'esperado 2 sessões (original + reentrada), veio ' + sess.length);
    });

    await step('4. Corte de energia: kill -9 → app degrada sem mentira e NÃO reinstala', async () => {
        // sessão em uso com servidor vivo
        const page = makePage();
        await page.run('bootstrap()');
        const login = await page.run(`attemptLogin(${JSON.stringify(SENHA)})`);
        assert(login.ok === true, 'login pré-corte falhou');

        server.kill('SIGKILL');
        await new Promise((r) => setTimeout(r, 300));

        // sessão em uso com servidor morto: gravação falha com toast claro
        const ok = await page.run('persistOrWarn("bpa_notes_v2", [{ id: 1, title: "x", text: "y", category: "Geral" }])');
        assert(ok === false, 'persistOrWarn deveria falhar com servidor morto');
        assert(/Falha ao gravar/i.test(page.getToast().msg || ''), 'toast de falha esperado: ' + JSON.stringify(page.getToast()));

        // página NOVA com servidor morto: avisa e NÃO reinstala por cima
        const page2 = makePage();
        await page2.run('bootstrap()');
        assert(page2.run('system') === null, 'bootstrap não deveria conseguir ler sem servidor');
        assert(/indisponível/i.test(page2.getToast().msg || ''), 'toast de banco indisponível esperado, veio: ' + JSON.stringify(page2.getToast()));
    });

    await step('5. Servidor volta: dados antigos intactos e login segue funcionando', async () => {
        server = spawnServer();
        await waitForHealth();
        const page = makePage();
        await page.run('bootstrap()');
        assert(page.run('system') !== null, 'system sumiu após reinício');
        const r = await page.run(`attemptLogin(${JSON.stringify(SENHA)})`);
        assert(r.ok === true, 'login falhou após reinício: ' + (r && r.msg));
        const users = JSON.parse(page.run('JSON.stringify(userBase)'));
        assert(users.length === 1 && users[0].nome === 'Maria Silva', 'dados perdidos após corte de energia');
        const sess = JSON.parse(page.run('JSON.stringify(sessions)'));
        assert(sess.length === 2, 'sessões perdidas após corte de energia');
    });
} finally {
    try { server.kill('SIGKILL'); } catch (_) {}
    fs.rmSync(DATA, { recursive: true, force: true });
}

console.log(`\nResultado E2E: ${passed} aprovados, ${failed} reprovados.`);
process.exit(failed > 0 ? 1 : 0);
