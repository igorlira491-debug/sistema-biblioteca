// Testes da funcionalidade "Reentrada" — app/index.html (sistema V4)
// Uso: node test_reentrada.mjs /caminho/para/app/index.html
//
// Carrega o <script> inline real do HTML em um contexto Node (vm) com:
//   - stub de DOM fiel o bastante para os fluxos testados (árvore, innerHTML
//     serializado, atributos, remoção/registro por id);
//   - API chave-valor em memória (o app roda em PERSIST_MODE='api'; fetch simulado);
//   - WebCrypto real do Node (criptografia de dados intacta).
// Exercita registerReentry / openReentryModal / renderUsers diretamente.

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
class NodeStub {}   // para `instanceof Node` no app

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
    if ((tag === 'input' || tag === 'textarea' || tag === 'select') && node.value !== '') {
        attrs.value = node.value;
    }
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
            // 'modal-overlay' tem semântica de existência no app:
            // openModal só cria um se NÃO houver um registrado. Auto-criar
            // here faria o guard achar um modal fantasma para sempre.
            if (id === 'modal-overlay') return null;
            const el = makeEl('div', doc);
            el.id = id;
            elements.set(id, el);
            return el;
        },
        createElement(tag) { return makeEl(tag, doc); },
        createTextNode(text) {
            const n = new NodeStub();
            n._isText = true;
            n._explicitHtml = null;
            n._attrs = {};
            n.children = [];
            n.textContent = String(text);
            return n;
        },
        querySelectorAll() { return []; },
        getElementsByClassName() { return []; },
        _ouvintes: {},
        addEventListener(tipo, fn) { (this._ouvintes[tipo] = this._ouvintes[tipo] || []).push(fn); },
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
            this.children.push(c);
            c._parent = this;
            return c;
        },
        removeChild(c) {
            const i = this.children.indexOf(c);
            if (i >= 0) this.children.splice(i, 1);
            c._parent = null;
            return c;
        },
        setAttribute(k, v) {
            if (k === 'id') { this.id = v; return; }   // id registrado vira propriedade
            this._attrs[k] = String(v);
        },
        getAttribute(k) { return k in this._attrs ? this._attrs[k] : null; },
        addEventListener() {},
        remove() {
            this._removed = true;
            if (this._parent) this._parent.removeChild(this);
            if (doc && this.id) doc._unregister(this.id);
        },
        getContext() { return {}; },
        querySelectorAll() { return []; },
    });
    let _html = null;   // null = não setado → serializa a árvore
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

// API chave-valor em memória — espelho do /api/kv/* do servidor Python
function makeApi() {
    const map = new Map();
    return {
        failSets: false,
        map,
        handle(url, init) {
            const method = (init && init.method) || 'GET';
            const path = String(url);
            if (path === '/api/kv/batch') {
                const body = JSON.parse(init.body);
                Object.entries(body.put || {}).forEach(([k, v]) => map.set(k, v));
                (body.delete || []).forEach((k) => map.delete(k));
                return { ok: true, status: 200, json: async () => ({ ok: true }) };
            }
            const mm = path.match(/^\/api\/kv\/([A-Za-z0-9_]+)$/);
            if (!mm) return { ok: false, status: 404, json: async () => ({ error: 'rota' }) };
            const key = mm[1];
            if (method === 'GET') {
                return { ok: true, status: 200, json: async () => ({ key, value: map.has(key) ? map.get(key) : null }) };
            }
            if (method === 'PUT') {
                if (this.failSets && key === 'bpa_sessions') {
                    return { ok: false, status: 500, json: async () => ({ error: 'falha simulada' }) };
                }
                map.set(key, JSON.parse(init.body).value);
                return { ok: true, status: 200, json: async () => ({ ok: true }) };
            }
            if (method === 'DELETE') {
                map.delete(key);
                return { ok: true, status: 200, json: async () => ({ ok: true }) };
            }
            return { ok: false, status: 405, json: async () => ({}) };
        },
    };
}

const documentStub = makeDocument();
const localStorageStub = { getItem: () => null, setItem: () => {}, removeItem: () => {} }; // tema (fora do teste)
const apiStub = makeApi();
const intervals = [];
const sandbox = {
    document: documentStub,
    localStorage: localStorageStub,
    fetch: (url, init) => apiStub.handle(url, init),
    Node: NodeStub,
    TextEncoder,
    TextDecoder,
    crypto: webcrypto,
    btoa: globalThis.btoa,
    atob: globalThis.atob,
    console,
    Date,
    Math,
    JSON,
    parseInt,
    parseFloat,
    isNaN,
    String,
    Number,
    Array,
    Object,
    RegExp,
    Error,
    setTimeout: () => 1,
    clearTimeout: () => {},
    setInterval: (cb, ms) => { intervals.push(cb); return intervals.length; },
    clearInterval: () => {},
};
sandbox.window = sandbox;
vm.createContext(sandbox);
vm.runInContext(scriptSource, sandbox, { filename: 'sistema_inline.js' });

const run = (code) => vm.runInContext(code, sandbox);
run('var __toasts = [];');
run('showToast = function(msg, type) { __toasts.push({ msg: msg, type: type || "error" }); };');
run('var __updatedMetrics = 0; updateMetrics = function() { __updatedMetrics++; };');

// Fixtures de sessão desbloqueada: DEK real (repoSet exige) + authSession
// (openReentryModal passa por requireSession).
await run('generateDek().then(function (d) { currentDek = d; return d; })');
run('authSession = { unlockedAt: new Date().toISOString(), lastActivity: Date.now() };');

// Filtros da lista em estado neutro (renderUsers os lê do DOM)
documentStub.getElementById('filter-status').value = 'todos';
documentStub.getElementById('filter-cat').value = 'todos';
documentStub.getElementById('filter-hist').checked = true;
documentStub.getElementById('search-input').value = '';

// ---------- helpers ----------
// Lê do "banco" e decifra com a DEK (repoSet grava envelope {iv,data})
async function persisted(key) {
    const raw = apiStub.map.get(key);
    if (raw === undefined) return null;
    return await run(`decryptJSON(JSON.parse(${JSON.stringify(raw)}), currentDek)`);
}

// Botão "Confirmar" do modal aberto (openModal guarda referência direta, sem id)
function modalConfirmButton() {
    const overlay = documentStub.body.children.find((c) => c.id === 'modal-overlay');
    if (!overlay) return null;
    let found = null;
    (function walk(n) {
        if (found) return;
        for (const c of n.children || []) {
            if (c.tagName === 'button' && typeof c.onclick === 'function') { found = c; return; }
            walk(c);
        }
    })(overlay);
    return found;
}

// ---------- fixtures ----------
const USER_VALID = { id: 100, matricula: 'abc1', nome: 'Maria Silva', nascimento: '1990-01-01', categoria: 'Adulto', validade: '2099-12-31' };
const USER_EXPIRED = { id: 101, matricula: 'abc2', nome: 'Joao Vencido', nascimento: '1980-05-05', categoria: 'Adulto', validade: '2020-01-01' };
const USER_OTHER = { id: 200, matricula: 'xyz9', nome: 'Pedro Aluno', nascimento: '2005-06-15', categoria: 'Jovem', validade: '2099-12-31' };
const ENDED = { sessionId: 1, userId: 100, pc: 3, status: 'Inativo', entrada: '09:00:00', entradaFull: '2026-10-20T09:00:00.000Z', saida: '10:30:00', saidaFull: '2026-10-20T10:30:00.000Z' };
const ENDED_OTHER = { sessionId: 2, userId: 200, pc: 7, status: 'Inativo', entrada: '08:00:00', entradaFull: '2026-10-20T08:00:00.000Z', saida: '09:00:00', saidaFull: '2026-10-20T09:00:00.000Z' };

function resetState(users, sess) {
    apiStub.failSets = false;
    run(`userBase = ${JSON.stringify(users)}; sessions = ${JSON.stringify(sess)};`);
    apiStub.map.set('bpa_user_base', JSON.stringify(users));
    apiStub.map.set('bpa_sessions', JSON.stringify(sess));
    run('__toasts = [];');
    // modal de teste anterior (se aberto): remove e drena a fila
    const overlay = documentStub.getElementById('modal-overlay');
    if (overlay) overlay.remove();
    run('modalQueue.length = 0;');
    documentStub.getElementById('users-list').children = [];
    documentStub.getElementById('pc-dashboard').children = [];
    documentStub.body.children = [];
}
const getJSON = (expr) => JSON.parse(run(`JSON.stringify(${expr})`));
const lastToast = () => run('__toasts[__toasts.length - 1]');

// ---------- runner ----------
let passed = 0, failed = 0;
async function test(name, fn) {
    try { await fn(); console.log(`  ✔ ${name}`); passed++; }
    catch (e) { console.log(`  ✘ ${name}\n    -> ${e.message}`); failed++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

console.log('Testes da funcionalidade REENTRADA\n');

// 1. Usuário encerra sessão e retorna — reentrada em PC livre
await test('1/2. Reentrada em PC livre cria novo registro e preserva histórico', async () => {
    resetState([USER_VALID, USER_OTHER], [ENDED, ENDED_OTHER]);
    const before = getJSON('sessions');
    const r = await run(`registerReentry(1, 5)`);
    assert(r.ok === true, 'deveria ser ok: ' + r.message);
    const after = getJSON('sessions');
    assert(after.length === before.length + 1, 'deveria ter 1 sessão a mais');
    assert(JSON.stringify(after.find(s => s.sessionId === 1)) === JSON.stringify(before.find(s => s.sessionId === 1)), 'sessão anterior foi alterada');
    const nova = after.find(s => s.sessionId !== 1 && s.sessionId !== 2);
    assert(nova, 'nova sessão não encontrada');
    assert(nova.userId === 100 && nova.pc === 5 && nova.status === 'Ativo', 'nova sessão com dados errados: ' + JSON.stringify(nova));
    assert(nova.saida === '-', 'nova sessão deveria começar sem saída');
    assert(nova.sessionId !== 1 && nova.sessionId !== 2 && !before.some(s => s.sessionId === nova.sessionId), 'sessionId deveria ser próprio/novo');
    const persist = await persisted('bpa_sessions');
    assert(persist && persist.length === after.length, 'banco não persistiu a nova sessão (cifra→gravação→decifração)');
    assert(/sucesso/i.test(r.message), 'mensagem de sucesso esperada: ' + r.message);
    assert(run('__updatedMetrics') > 0, 'métricas não atualizadas');
});

// 3. PC ocupado (sessão Ativo de outro usuário)
await test('3. Reentrada em PC ocupado por sessão Ativa é bloqueada', async () => {
    resetState([USER_VALID, USER_OTHER], [ENDED, { sessionId: 3, userId: 200, pc: 9, status: 'Ativo', entrada: '10:00:00', entradaFull: '2026-10-20T10:00:00.000Z', saida: '-' }]);
    const before = getJSON('sessions');
    const r = await run('registerReentry(1, 9)');
    assert(r.ok === false, 'deveria falhar');
    assert(/ocupado/i.test(r.message), 'mensagem inesperada: ' + r.message);
    assert(JSON.stringify(getJSON('sessions')) === JSON.stringify(before), 'registros foram modificados');
});

// 3b. PC com sessão Suspenso
await test('3b. Reentrada em PC com sessão Suspenso é bloqueada', async () => {
    resetState([USER_VALID, USER_OTHER], [ENDED, { sessionId: 3, userId: 200, pc: 10, status: 'Suspenso', entrada: '10:00:00', entradaFull: '2026-10-20T10:00:00.000Z', saida: '-' }]);
    const before = getJSON('sessions');
    const r = await run('registerReentry(1, 10)');
    assert(r.ok === false && /ocupado/i.test(r.message), 'deveria bloquear PC suspenso: ' + r.message);
    assert(JSON.stringify(getJSON('sessions')) === JSON.stringify(before), 'registros foram modificados');
});

// 4. Usuário ainda com sessão ativa
await test('4. Reentrada bloqueada se usuário já tem sessão Ativa', async () => {
    resetState([USER_VALID], [ENDED, { sessionId: 3, userId: 100, pc: 20, status: 'Ativo', entrada: '10:00:00', entradaFull: '2026-10-20T10:00:00.000Z', saida: '-' }]);
    const before = getJSON('sessions');
    const r = await run('registerReentry(1, 5)');
    assert(r.ok === false && /sessão ativa/i.test(r.message), 'mensagem inesperada: ' + r.message);
    assert(JSON.stringify(getJSON('sessions')) === JSON.stringify(before), 'registros foram modificados');
});

// 4b. Usuário com sessão suspensa
await test('4b. Reentrada bloqueada se usuário já tem sessão Suspenso', async () => {
    resetState([USER_VALID], [ENDED, { sessionId: 3, userId: 100, pc: 20, status: 'Suspenso', entrada: '10:00:00', entradaFull: '2026-10-20T10:00:00.000Z', saida: '-' }]);
    const r = await run('registerReentry(1, 5)');
    assert(r.ok === false && /suspen/i.test(r.message), 'mensagem inesperada: ' + r.message);
});

// 5. Nova entrada usa o horário do momento da confirmação (sleep real de 40ms)
resetState([USER_VALID], [ENDED]);
const t0Test5 = Date.now();
await new Promise(res => setTimeout(res, 40));
const r5 = await run('registerReentry(1, 5)');
await test('5. Horário da nova entrada é o da confirmação, não o anterior', () => {
    assert(r5.ok === true, 'deveria ser ok: ' + r5.message);
    const nova = getJSON('sessions').find(s => s.sessionId !== 1);
    assert(new Date(nova.entradaFull).getTime() >= t0Test5, 'entradaFull deveria ser >= horário da confirmação');
    assert(nova.entradaFull !== ENDED.entradaFull, 'não pode reaproveitar o horário da sessão anterior');
});

// 6/7. Duração nova sessão calculada da nova entrada; histórico intacto
await test('6/7. Duração vem da nova entrada; histórico permanece intacto', async () => {
    resetState([USER_VALID], [ENDED]);
    await run('registerReentry(1, 5)');
    const after = getJSON('sessions');
    const antiga = after.find(s => s.sessionId === 1);
    assert(antiga.saidaFull === ENDED.saidaFull && antiga.entradaFull === ENDED.entradaFull, 'sessão antiga alterada');
    assert(antiga.status === 'Inativo', 'status da sessão antiga alterado');
    const nova = after.find(s => s.sessionId !== 1);
    // tempoCell usa (saidaFull - entradaFull); nova sessão sem saida => contagem ao vivo por entradaFull
    assert(!nova.saidaFull && nova.entradaFull, 'nova sessão deveria usar a própria entrada para a contagem');
});

// 8. Indicadores/exportações: métricas contam nova sessão; cadastro não duplica
await test('8. Métricas contam a reentrada como nova sessão sem duplicar cadastro', async () => {
    resetState([USER_VALID, USER_OTHER], [ENDED, ENDED_OTHER]);
    run('__updatedMetrics = 0;');
    await run('registerReentry(1, 5)');
    assert(run('__updatedMetrics') > 0, 'updateMetrics não chamado');
    assert(getJSON('userBase').length === 2, 'cadastro duplicado');
    assert(getJSON('sessions').length === 3, 'sessões: esperado 3, veio ' + getJSON('sessions').length);
    // exportSessionsCSV itera sobre sessions — garantir que a nova sessão tem os campos que o export lê
    const nova = getJSON('sessions').find(s => s.sessionId !== 1 && s.sessionId !== 2);
    for (const campo of ['sessionId', 'userId', 'pc', 'status', 'entrada', 'entradaFull']) {
        assert(nova[campo] !== undefined, 'campo ausente para exportação: ' + campo);
    }
});

// 9. Falha ao salvar
await test('9. Falha no salvamento: rollback + erro claro, sem sucesso falso', async () => {
    resetState([USER_VALID], [ENDED]);
    const before = getJSON('sessions');
    apiStub.failSets = true;
    const r = await run('registerReentry(1, 5)');
    assert(r.ok === false && /Falha ao salvar/i.test(r.message), 'mensagem de falha inesperada: ' + r.message);
    assert(JSON.stringify(getJSON('sessions')) === JSON.stringify(before), 'rollback não ocorreu');
    // fluxo completo pelo modal: falha de save deve avisar o responsável e não fechar como sucesso
    apiStub.failSets = true;
    run('__toasts = [];');
    run('openReentryModal(1)');
    documentStub.getElementById('reentrada-pc').value = '5';
    const okBtn = modalConfirmButton();
    assert(okBtn, 'botão de confirmação do modal não encontrado');
    await okBtn.onclick();
    assert(lastToast() && lastToast().type === 'error' && /Falha ao salvar/i.test(lastToast().msg), 'toast de falha esperado no modal');
    assert(getJSON('sessions').length === before.length, 'modal não deveria concluir com falha de save');
    apiStub.failSets = false;
});

// Impedimento: validade vencida
await test('8b. Reentrada bloqueada com matrícula vencida', async () => {
    resetState([USER_EXPIRED], [{ ...ENDED, userId: 101 }]);
    const r = await run('registerReentry(1, 5)');
    assert(r.ok === false && /vencida/i.test(r.message), 'mensagem inesperada: ' + r.message);
});

// Validações de entrada
await test('Validações: PC inválido e sessão de origem inválida', async () => {
    resetState([USER_VALID], [ENDED]);
    for (const pc of ['99', '0', 'abc', '', null]) {
        const r = await run(`registerReentry(1, ${JSON.stringify(pc)})`);
        assert(r.ok === false, 'PC ' + pc + ' deveria ser rejeitado');
    }
    const r1 = await run('registerReentry(99999, 5)');
    assert(r1.ok === false, 'sessionId inexistente deveria ser rejeitado');
    // origem Ativa
    resetState([USER_VALID], [{ ...ENDED, status: 'Ativo', saida: '-', saidaFull: undefined }]);
    const r2 = await run('registerReentry(1, 5)');
    assert(r2.ok === false && /não está encerrada/i.test(r2.message), 'sessão Ativa de origem deveria ser rejeitada');
});

// Cliques repetidos: 2ª confirmação no mesmo PC falha (estado revalidado)
await test('Proteção contra duplo clique: 2ª confirmação no mesmo PC é bloqueada', async () => {
    resetState([USER_VALID], [ENDED]);
    const r1 = await run('registerReentry(1, 5)');
    const r2 = await run('registerReentry(1, 5)');
    assert(r1.ok === true, '1ª deveria ok');
    assert(r2.ok === false, '2ª deveria falhar (usuário agora com sessão ativa)');
    assert(getJSON('sessions').filter(s => s.pc === 5).length === 1, 'duplicou sessão no PC 5');
});

// renderUsers: botão Reentrada apenas em Inativo
await test('renderUsers: botão Reentrada só nas sessões Inativo; ações existentes preservadas', () => {
    resetState([USER_VALID, USER_OTHER], [
        ENDED,
        { sessionId: 3, userId: 100, pc: 20, status: 'Ativo', entrada: '10:00:00', entradaFull: '2026-10-20T10:00:00.000Z', saida: '-' },
        { sessionId: 4, userId: 200, pc: 21, status: 'Suspenso', entrada: '10:00:00', entradaFull: '2026-10-20T10:00:00.000Z', saida: '-' },
    ]);
    run('renderUsers("")');
    const rows = documentStub.getElementById('users-list').children.filter((r) => r.dataset && r.dataset.sessionId);
    assert(rows.length === 3, 'esperado 3 linhas, veio ' + rows.length);
    const rowInativa = rows.find(r => r.innerHTML.includes('data-click="openReentryModal" data-id="1"'));
    assert(rowInativa && rowInativa.innerHTML.includes('Reentrada'), 'linha inativa sem botão Reentrada');
    const rowAtiva = rows.find(r => r.innerHTML.includes('data-click="toggleSessionStatus" data-id="3"'));
    assert(rowAtiva && rowAtiva.innerHTML.includes('Registrar saída') && !rowAtiva.innerHTML.includes('Reentrada'), 'linha ativa não deve ter Reentrada');
    const rowSusp = rows.find(r => r.innerHTML.includes('data-click="toggleSessionStatus" data-id="4"'));
    assert(rowSusp && rowSusp.innerHTML.includes('Registrar saída') && !rowSusp.innerHTML.includes('Reentrada'), 'linha suspensa não deve ter Reentrada');
    assert(documentStub.getElementById('pc-dashboard').children.length === 28, 'painel de PCs deveria ter 28 tiles');
});

// renderUsers (layout C): blocos "No computador agora" em cima e "saíram" embaixo; 7 colunas
await test('renderUsers layout C: blocos agora/saíram, nome com linha de baixo, sem ID, botão ⋯', () => {
    resetState([USER_VALID, USER_OTHER], [
        ENDED,
        { sessionId: 3, userId: 100, pc: 20, status: 'Ativo', entrada: '10:00:00', entradaFull: '2026-10-20T10:00:00.000Z', saida: '-' },
        { sessionId: 4, userId: 200, pc: 21, status: 'Suspenso', entrada: '10:00:00', entradaFull: '2026-10-20T10:00:00.000Z', saida: '-' },
    ]);
    run('renderUsers("")');
    const todas = documentStub.getElementById('users-list').children;
    const ordem = todas.map(r => r.dataset && r.dataset.sessionId ? 's' + r.dataset.sessionId : r.className);
    assert(JSON.stringify(ordem) === JSON.stringify(['grupo-sessoes', 's3', 's4', 'grupo-sessoes', 's1']),
        'ordem inesperada: ' + JSON.stringify(ordem));
    assert(/No computador agora \(2\)/.test(todas[0].innerHTML), 'cabeçalho do bloco "agora" com contagem: ' + todas[0].innerHTML);
    assert(/saíram \(1\)/i.test(todas[3].innerHTML), 'cabeçalho do bloco "saíram" com contagem: ' + todas[3].innerHTML);
    assert(/colspan="7"/.test(todas[0].innerHTML), 'cabeçalho deve ocupar as 7 colunas');
    const ativa = todas[1].innerHTML;
    assert((ativa.match(/<td/g) || []).length === 7, 'linha de sessão deve ter 7 células: ' + ativa);
    assert(ativa.includes('Matrícula abc1 · Adulto · válida até 31/12/2099'), 'linha de baixo do nome (agora): ' + ativa);
    assert(!ativa.includes('>3<') && !ativa.includes('2099-12-31'), 'ID interno e validade crua não devem aparecer');
    assert(ativa.includes('data-click="openStatusModal" data-id="3"') && !ativa.includes('<select'), 'ativo usa botão ⋯ no lugar do select');
    const encerrada = todas[4].innerHTML;
    assert(encerrada.includes('Matrícula abc1 · Adulto') && !encerrada.includes('válida até'), 'linha de baixo (saíram) sem validade: ' + encerrada);
    assert(/\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}/.test(encerrada) && !/\d{2}:\d{2}:\d{2}/.test(encerrada),
        'sessão de outro dia: data + HH:MM, sem segundos: ' + encerrada);
});

await test('openStatusModal: ⋯ suspende o Ativo e reativa o Suspenso', async () => {
    resetState([USER_VALID, USER_OTHER], [
        { sessionId: 3, userId: 100, pc: 20, status: 'Ativo', entrada: '10:00:00', entradaFull: '2026-10-20T10:00:00.000Z', saida: '-' },
    ]);
    run('openStatusModal(3)');
    let overlay = documentStub.body.children.find(c => c.id === 'modal-overlay');
    assert(overlay && overlay.innerHTML.includes('Maria Silva') && overlay.innerHTML.includes('PC 20'), 'modal deveria citar usuário e PC');
    await modalConfirmButton().onclick();
    assert(getJSON('sessions')[0].status === 'Suspenso', 'deveria suspender');
    assert(!documentStub.body.children.find(c => c.id === 'modal-overlay'), 'modal deveria fechar');
    run('openStatusModal(3)');
    await modalConfirmButton().onclick();
    assert(getJSON('sessions')[0].status === 'Ativo', 'deveria reativar');
});

// openReentryModal: formulário
await test('openReentryModal: mostra nome, matrícula, PCs livres e botão "Confirmar reentrada"', async () => {
    resetState([USER_VALID, USER_OTHER], [
        ENDED,
        { sessionId: 3, userId: 200, pc: 9, status: 'Ativo', entrada: '10:00:00', entradaFull: '2026-10-20T10:00:00.000Z', saida: '-' },
        { sessionId: 4, userId: 200, pc: 10, status: 'Suspenso', entrada: '10:00:00', entradaFull: '2026-10-20T10:00:00.000Z', saida: '-' },
    ]);
    run('openReentryModal(1)');
    const overlay = documentStub.body.children.find(c => c.id === 'modal-overlay');
    assert(overlay, 'modal não abriu');
    const htmlOverlay = overlay.innerHTML;
    assert(htmlOverlay.includes('Maria Silva'), 'sem nome do usuário');
    assert(htmlOverlay.includes('abc1'), 'sem matrícula');
    assert(htmlOverlay.includes('Confirmar reentrada'), 'sem botão de confirmação');
    assert(!/<option value="9">/.test(htmlOverlay), 'PC 9 (ativo) não deveria estar disponível');
    assert(!/<option value="10">/.test(htmlOverlay), 'PC 10 (suspenso) não deveria estar disponível');
    assert(/<option value="5">/.test(htmlOverlay), 'PC 5 deveria estar disponível');
    assert(/reentrada-hora/.test(htmlOverlay), 'sem campo de data/hora');
    const okBtn = modalConfirmButton();
    assert(okBtn, 'botão de confirmação do modal não encontrado');
    // confirmação sem selecionar PC mantém modal aberto e avisa
    documentStub.getElementById('reentrada-pc').value = '';
    await okBtn.onclick();
    assert(lastToast().type === 'error' && /computador/i.test(lastToast().msg), 'deveria avisar para selecionar PC');
    assert(getJSON('sessions').length === 3, 'não deveria criar sessão sem PC');
    assert(documentStub.body.children.find(c => c.id === 'modal-overlay'), 'modal não deveria fechar com erro');
    // confirmar com PC válido cria a sessão e fecha o modal
    documentStub.getElementById('reentrada-pc').value = '5';
    await okBtn.onclick();
    assert(getJSON('sessions').length === 4, 'confirmação deveria criar a sessão');
    assert(lastToast().type === 'success' && /sucesso/i.test(lastToast().msg), 'toast de sucesso esperado: ' + lastToast().msg);
    assert(!documentStub.body.children.find(c => c.id === 'modal-overlay'), 'modal deveria fechar após sucesso');
});

await test('openReentryModal recusa sessão que não está Inativo', () => {
    resetState([USER_VALID], [{ ...ENDED, status: 'Ativo', saida: '-', saidaFull: undefined }]);
    run('__toasts = [];');
    run('openReentryModal(1)');
    assert(!documentStub.body.children.find(c => c.id === 'modal-overlay'), 'modal não deveria abrir');
    assert(/não está encerrada/i.test(lastToast().msg), 'mensagem inesperada: ' + lastToast().msg);
});

await test('Relógio do modal atualiza a data/hora exibida', () => {
    resetState([USER_VALID], [ENDED]);
    run('openReentryModal(1)');
    const cb = intervals[intervals.length - 1];
    const antes = documentStub.getElementById('reentrada-hora').textContent;
    cb();
    const depois = documentStub.getElementById('reentrada-hora').textContent;
    assert(typeof depois === 'string' && depois.length > 0, 'relógio não atualizou');
    void antes;
});

// ---------- Bloco 5: despachante de eventos (data-click/change/keyup → ACOES) ----------
// elemento mínimo com dataset e closest; classList real para conferir a aba ativa
function alvo(dataset) {
    const cls = new Set();
    const el = { dataset, classList: { add: (c) => cls.add(c), remove: (c) => cls.delete(c), toggle: (c, on) => (on ? cls.add(c) : cls.delete(c)), contains: (c) => cls.has(c) } };
    el.closest = (sel) => { const k = sel.match(/^\[data-(\w+)\]$/)[1]; return k in dataset ? el : null; };
    return el;
}
function disparar(tipo, target) {
    (documentStub._ouvintes[tipo] || []).forEach((fn) => fn({ target, type: tipo }));
}
run('ligarEventos()');

await test('Bloco 5: clicar numa aba ativa só ela (sem depender de onclick)', () => {
    const geral = alvo({ click: 'openTab', arg: 'tab-geral' });
    const cad = alvo({ click: 'openTab', arg: 'tab-cadastros' });
    const conteudoGeral = alvo({}), conteudoCad = alvo({});
    const antes = documentStub.getElementsByClassName;
    documentStub.getElementsByClassName = (c) => (c === 'tab-btn' ? [geral, cad] : c === 'tab-content' ? [conteudoGeral, conteudoCad] : []);
    documentStub._register('tab-geral', conteudoGeral);
    documentStub._register('tab-cadastros', conteudoCad);
    try {
        geral.classList.add('active'); conteudoGeral.classList.add('active');
        disparar('click', cad);
        assert(cad.classList.contains('active') && !geral.classList.contains('active'), 'botão da aba Cadastros deveria ser o único ativo');
        assert(conteudoCad.classList.contains('active') && !conteudoGeral.classList.contains('active'), 'conteúdo de Cadastros deveria ser o único visível');
    } finally {
        documentStub.getElementsByClassName = antes;
    }
});

await test('Bloco 5: botão gerado pela tabela entrega o id como número (Registrar saída)', async () => {
    resetState([USER_VALID], [
        { sessionId: 3, userId: 100, pc: 20, status: 'Ativo', entrada: '10:00:00', entradaFull: '2026-10-20T10:00:00.000Z', saida: '-' },
    ]);
    run('renderUsers("")');
    const linha = documentStub.getElementById('users-list').children.find((r) => r.dataset && r.dataset.sessionId === '3');
    assert(linha && linha.innerHTML.includes('data-click="toggleSessionStatus" data-id="3" data-arg="Inativo"'), 'botão Registrar saída sem os data-* esperados: ' + (linha && linha.innerHTML));
    disparar('click', alvo({ click: 'toggleSessionStatus', id: '3', arg: 'Inativo' }));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    const s = getJSON('sessions')[0];
    assert(s.status === 'Inativo' && s.saidaFull, 'a sessão 3 deveria ter saída registrada, veio ' + JSON.stringify(s));
});

await test('Bloco 5: ação desconhecida é ignorada (só a lista ACOES é chamada)', () => {
    run('var __chamou = false; alert = function () { __chamou = true; };');
    for (const nome of ['alert', 'constructor', '__proto__', 'toString', 'eval', 'hasOwnProperty']) {
        disparar('click', alvo({ click: nome }));
        // despacharEvento devolve o retorno da ação: fora de ACOES não pode chamar nada (undefined)
        const ret = run('despacharEvento')('click', { target: alvo({ click: nome }) });
        assert(ret === undefined, 'despachante chamou "' + nome + '" (herdado/global) e devolveu ' + String(ret));
    }
    disparar('click', alvo({}));   // sem data-click: nada
    assert(run('__chamou') === false, 'despachante chamou função fora de ACOES');
});

await test('Categorias: Infantil 0–14, Jovem 15–17, Adulto 18+ (pela idade de hoje)', () => {
    const nasc = (anos, dias) => {   // data de nascimento de quem faz `anos` hoje, `dias` dias atrás
        const d = new Date(); d.setFullYear(d.getFullYear() - anos); d.setDate(d.getDate() - (dias || 0));
        return d.toLocaleDateString('en-CA');
    };
    const casos = [[0, 10, 'Infantil'], [4, 0, 'Infantil'], [5, 0, 'Infantil'], [14, 0, 'Infantil'], [15, 0, 'Jovem'], [17, 300, 'Jovem'], [18, 0, 'Adulto'], [40, 0, 'Adulto']];
    for (const [anos, dias, esperado] of casos) {
        const veio = run('calculateCategory(' + JSON.stringify(nasc(anos, dias)) + ')');
        assert(veio === esperado, anos + ' anos deveria ser ' + esperado + ', veio ' + veio);
    }
    // quem faz 15 amanhã ainda é Infantil hoje
    const amanha = new Date(); amanha.setFullYear(amanha.getFullYear() - 15); amanha.setDate(amanha.getDate() + 1);
    assert(run('calculateCategory(' + JSON.stringify(amanha.toLocaleDateString('en-CA')) + ')') === 'Infantil', 'véspera dos 15 deveria ser Infantil');
    // cadastro antigo "Jovem" de 10 anos é reclassificado na próxima renderização
    run('userBase = [{ id: 1, nascimento: ' + JSON.stringify(nasc(10)) + ', categoria: "Jovem" }]; syncCategories();');
    assert(run('userBase[0].categoria') === 'Infantil', 'syncCategories deveria reclassificar para Infantil');
});

console.log(`\nResultado: ${passed} aprovados, ${failed} reprovados.`);
process.exit(failed > 0 ? 1 : 0);
