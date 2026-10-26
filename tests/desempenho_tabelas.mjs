// Desempenho das tabelas com base sintética ~35 mil sessões (Bloco 3, item b)
// Uso: node desempenho_tabelas.mjs /caminho/para/app/index.html
//
// Contexto: as sessões são UM BLOB CIFRADO por chave no SQLite — não há CREATE INDEX
// relacional possível; a paginação é client-side sobre o array decifrado e o suporte
// de desempenho é o índice leve de renderização (buildRenderIndex, passeio único
// O(sessões + usuários)). Este teste materializa a base de 2 anos que o cliente espera
// (35.000 sessões + 3.000 usuários + 20.000 registros de auditoria) e mede os
// renderers paginados, verificando dois pontos:
//   1. cada render é limitado (o DOM só recebe uma página —25/50/50 linhas);
//   2. o tempo de render fica em ordem de linearidade (limites generosos, folgados
//      para máquina lenta — um retrocesso para O(S×U) estouraria por ordens de grandeza).
//
// Os tempos reais são impressos para inspeção manual.

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

// ---------- stubs (mesma base das demais suítes) ----------
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
const sandbox = {
    document: documentStub,
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    fetch: async () => ({ ok: true, status: 200, json: async () => ({ ok: true, value: null }) }),
    Node: NodeStub, TextEncoder, TextDecoder, crypto: webcrypto,
    btoa: globalThis.btoa, atob: globalThis.atob,
    console, Date, Math, JSON, parseInt, parseFloat, isNaN, String, Number, Array, Object, RegExp, Error,
    setTimeout: () => 1, clearTimeout: () => {}, setInterval: () => 1, clearInterval: () => {},
};
sandbox.window = sandbox;
vm.createContext(sandbox);
vm.runInContext(scriptSource, sandbox, { filename: 'sistema_inline.js' });
const run = (code) => vm.runInContext(code, sandbox);
run('var __toasts = []; showToast = function () {}; var __updatedMetrics = 0; updateMetrics = function () { __updatedMetrics++; };');

// ---------- base sintética:35 mil sessões /3 mil usuários /20 mil auditorias ----------
const N_SESSOES = 35000, N_USUARIOS = 3000, N_AUDIT = 20000;

console.log('Desempenho das tabelas — base sintética\n');
console.log(`  gerando ${N_SESSOES} sessões, ${N_USUARIOS} usuários, ${N_AUDIT} auditorias...`);
const tGen = Date.now();
run(`
    userBase = [];
    for (let i = 1; i <= ${N_USUARIOS}; i++) {
        userBase.push({
            id: i, matricula: String(10000 + (i % 89999)),
            nome: (i % 10 === 0 ? 'Ana Silva ' : 'Usuário ') + i,
            nascimento: '1990-01-01', categoria: 'Adulto', validade: '2099-12-31'
        });
    }
    sessions = [];
    const base = Date.UTC(2024, 9, 1);
    for (let i = 1; i <= ${N_SESSOES}; i++) {
        const status = i % 500 === 0 ? 'Ativo' : (i % 700 === 0 ? 'Suspenso' : 'Inativo');
        const iso = new Date(base + i * 3600000).toISOString();
        sessions.push({
            sessionId: i, userId: (i % ${N_USUARIOS}) + 1, pc: ((i - 1) % 28) + 1, status: status,
            entrada: '08:00', entradaFull: iso, saida: '09:00',
            saidaFull: status === 'Inativo' ? new Date(base + i * 3600000 + 3600000).toISOString() : undefined
        });
    }
    auditLog = [];
    for (let i = 1; i <= ${N_AUDIT}; i++) {
        auditLog.push({
            id: 'a' + i, timestamp: new Date(base + i * 60000).toISOString(),
            acao: 'sessao.status', alvo_tipo: 'session', alvo_id: String(i), resultado: 'sucesso', detalhes: 'troca de status'
        });
    }
`);
console.log(`  base gerada em ${Date.now() - tGen} ms\n`);

// filtros em estado neutro
documentStub.getElementById('filter-status').value = 'todos';
documentStub.getElementById('filter-cat').value = 'todos';
documentStub.getElementById('filter-hist').checked = true;
documentStub.getElementById('search-input').value = '';
documentStub.getElementById('reg-search-input').value = '';
documentStub.getElementById('audit-filter-start').value = '';
documentStub.getElementById('audit-filter-end').value = '';

let passed = 0, failed = 0;
async function test(name, budgetMs, fn) {
    try {
        const r = await fn();
        const ms = typeof r === 'number' ? r : null;
        const tempo = ms === null ? '' : ` — ${ms} ms (orçamento ${budgetMs} ms)`;
        if (ms !== null && ms > budgetMs) {
            console.log(`  ✘ ${name}${tempo}\n    -> estourou o orçamento`);
            failed++;
            return;
        }
        console.log(`  ✔ ${name}${tempo}`);
        passed++;
    } catch (e) { console.log(`  ✘ ${name}\n    -> ${e.message}`); failed++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }
function time(fn) { const t0 = process.hrtime.bigint(); fn(); return Number(process.hrtime.bigint() - t0) / 1e6; }

// Limites deliberadamente folgados (máquina da biblioteca é modesta; o objetivo é pegar
// regressão de complexidade — O(S×U)=105 mi de operações estouraria por muito mais).
await test(`1. renderUsers com ${N_SESSOES} sessões: rendera SÓ a página (25 linhas)`, 1200, () => {
    const ms = time(() => run('renderUsers("")'));
    const rows = documentStub.getElementById('users-list').children.filter((r) => r.dataset && r.dataset.sessionId);
    assert(rows.length === 25, `esperado25 linhas na página, veio ${rows.length}`);
    const info = documentStub.getElementById('users-pager').children.find((c) => c.className === 'pager-info');
    assert(info && info.textContent.includes(`de ${N_SESSOES}`), `pager deveria citar ${N_SESSOES}: ${info && info.textContent}`);
    return ms;
});

await test('2. renderUsers página 3 (fatiamento profundo) — só25 linhas', 1200, () => {
    run('tablePage.users = 3; tableSig.users = JSON.stringify(["", "todos", "todos", true]); renderUsers("");');
    const rows = documentStub.getElementById('users-list').children.filter((r) => r.dataset && r.dataset.sessionId);
    assert(rows.length === 25, `esperado25 linhas, veio ${rows.length}`);
    const info = documentStub.getElementById('users-pager').children.find((c) => c.className === 'pager-info');
    assert(info && info.textContent.includes('Página 3'), `pager deveria estar na página3: ${info && info.textContent}`);
    return time(() => run('renderUsers("")'));   // mede re-render já na p3
});

await test('3. Digitação na busca (filterUsers) com a base cheia', 800, () => {
    documentStub.getElementById('search-input').value = 'silva';
    const ms = time(() => run('filterUsers()'));
    documentStub.getElementById('search-input').value = '';
    run('filterUsers()');
    return ms;
});

await test(`4. renderRegistrationList com ${N_USUARIOS} usuários: só50 linhas`, 800, () => {
    const ms = time(() => run('renderRegistrationList("")'));
    const rows = documentStub.getElementById('registration-list').children;
    assert(rows.length === 50, `esperado50 linhas, veio ${rows.length}`);
    const info = documentStub.getElementById('registration-pager').children.find((c) => c.className === 'pager-info');
    assert(info && info.textContent.includes(`de ${N_USUARIOS}`), `pager deveria citar ${N_USUARIOS}: ${info && info.textContent}`);
    return ms;
});

await test(`5. renderAuditTable com ${N_AUDIT} registros: só50 linhas (sem teto de200)`, 1500, () => {
    const ms = time(() => run('renderAuditTable()'));
    const rows = documentStub.getElementById('audit-list').children;
    assert(rows.length === 50, `esperado50 linhas, veio ${rows.length}`);
    const info = documentStub.getElementById('audit-pager').children.find((c) => c.className === 'pager-info');
    assert(info && info.textContent.includes(`de ${N_AUDIT}`), `pager deveria citar ${N_AUDIT}: ${info && info.textContent}`);
    return ms;
});

await test('6. buildRenderIndex: passeio único mantém contagens corretas', 400, () => {
    const ms = time(() => {
        const o = run(`(function () {
            const idx = buildRenderIndex();
            return JSON.stringify({ u: idx.usuarios.size, e: idx.epoch.size, p: idx.pcs.size });
        })()`);
        const parsed = JSON.parse(String(o));
        assert(parsed.u === N_USUARIOS, `usuarios indexados: ${parsed.u}`);
        assert(parsed.e === N_SESSOES, `epochs indexados: ${parsed.e}`);
        // pcs:28 PCs, Ativos (i%500===0) e Suspenso (i%700===0) cobrem todos os PCs
        assert(parsed.p > 0 && parsed.p <= 28, `mapa de PCs com tamanho estranho: ${parsed.p}`);
    });
    return ms;
});

console.log(`\nResultado: ${passed} aprovados, ${failed} reprovados.`);
process.exit(failed > 0 ? 1 : 0);
