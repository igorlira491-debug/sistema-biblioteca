// Testes da PAGINAÇÃO de todas as tabelas + índice leve de sessões (Bloco 3)
// Uso: node test_paginacao.mjs /caminho/para/app/index.html
//
// Cobre:
//   - users (sessões): fatiamento, pager, ordenação equivalente ao algoritmo antigo,
//     reset de página ao mudar filtro/busca, clamp ao encolher dados;
//   - registration (cadastros): paginação + busca;
//   - audit (auditoria): paginação substitui o antigo teto de 200 + reset por período;
//   - pager some com a tabela vazia.
//
// Mesmo harness de test_reentrada.mjs (script inline real em vm + DOM stub).

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
run('var __toasts = []; showToast = function (m, t) { __toasts.push({ msg: String(m), type: t || "error" }); };');
run('var __updatedMetrics = 0; updateMetrics = function () { __updatedMetrics++; };');

// ---------- helpers ----------
function resetState(sessions, users, audit) {
    run(`sessions = ${JSON.stringify(sessions)};
         userBase = ${JSON.stringify(users)};
         auditLog = ${JSON.stringify(audit || [])};
         tablePage.users = 1; tablePage.registration = 1; tablePage.audit = 1;
         tableSig.users = null; tableSig.registration = null; tableSig.audit = null;
         modalQueue.length = 0;`);
    documentStub.getElementById('filter-status').value = 'todos';
    documentStub.getElementById('filter-cat').value = 'todos';
    documentStub.getElementById('filter-hist').checked = true;
    documentStub.getElementById('search-input').value = '';
    documentStub.getElementById('reg-search-input').value = '';
    documentStub.getElementById('audit-filter-start').value = '';
    documentStub.getElementById('audit-filter-end').value = '';
    documentStub.body.children = [];
}

// linhas de dados; na tabela de sessões, os cabeçalhos de bloco ("No computador agora" /
// "Saíram hoje") não contam — só as linhas que carregam data-session-id
function rowsOf(id) {
    const rows = documentStub.getElementById(id).children;
    return id === 'users-list' ? rows.filter((r) => r.dataset && r.dataset.sessionId) : rows;
}
function firstCell(tr) {
    // sessões: o ID vem do data-session-id (a coluna ID saiu no layout C); demais tabelas: 1ª <td>
    if (tr.dataset && tr.dataset.sessionId) return tr.dataset.sessionId;
    const mm = String(tr.innerHTML).match(/^<td>(.*?)<\/td>/);
    return mm ? mm[1] : null;
}
function pagerInfo(id) {
    const box = documentStub.getElementById(id);
    const info = box.children.find((c) => c.className === 'pager-info');
    return info ? info.textContent : null;
}
function pagerButton(id, label) {
    const box = documentStub.getElementById(id);
    return box.children.find((c) => c.tagName === 'button' && c.textContent === label);
}

function makeSessions(n, usersCount) {
    // ids 1..n; datas ascendentes com o id; status: 1–3 Ativo, 4–6 Suspenso, resto Inativo
    const out = [];
    for (let i = 1; i <= n; i++) {
        const status = i <= 3 ? 'Ativo' : (i <= 6 ? 'Suspenso' : 'Inativo');
        const d = new Date(Date.UTC(2025, 0, 1) + i * 3600 * 1000).toISOString();
        out.push({
            sessionId: i, userId: (i % usersCount) + 1, pc: ((i - 1) % 28) + 1, status: status,
            entrada: '08:00', entradaFull: d, saida: status === 'Inativo' ? '09:00' : '-',
            saidaFull: status === 'Inativo' ? d : undefined
        });
    }
    return out;
}
function makeUsers(n) {
    const out = [];
    for (let i = 1; i <= n; i++) {
        out.push({
            id: i, matricula: String(10000 + i).slice(-5),
            nome: (i % 10 === 0 ? 'Ana Silva ' : 'Usuário ') + i,
            nascimento: '1990-01-01', categoria: 'Adulto', validade: '2099-12-31'
        });
    }
    return out;
}
function makeAudit(n) {
    const out = [];
    for (let i = 1; i <= n; i++) {
        out.push({
            id: 'a' + i, timestamp: new Date(Date.UTC(2026, 0, 1) + i * 60000).toISOString(),
            acao: 'teste.' + i, alvo_tipo: 'session', alvo_id: String(i), resultado: 'sucesso', detalhes: 'd' + i
        });
    }
    return out;
}

// Ordem esperada (equivalente ao algoritmo antigo): Ativo > Suspenso > Inativo,
// e dentro do status, entradaFull decrescente (id maior = mais novo = primeiro).
function expectedOrder(sessions) {
    const ord = { Ativo: 0, Suspenso: 1, Inativo: 2 };
    return sessions.slice().sort((a, b) => (ord[a.status] - ord[b.status]) || (Date.parse(b.entradaFull) - Date.parse(a.entradaFull)));
}

let passed = 0, failed = 0;
async function test(name, fn) {
    try { await fn(); console.log(`  ✔ ${name}`); passed++; }
    catch (e) { console.log(`  ✘ ${name}\n    -> ${e.message}`); failed++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

console.log('Testes de PAGINAÇÃO das tabelas (Bloco 3)\n');

// ═══ Tabela de sessões (aba Geral) ═══

await test('1. Sessões: pagina 60 registros em 3 páginas de 25 (pager com faixa e total)', () => {
    resetState(makeSessions(60, 50), makeUsers(50));
    run('renderUsers("")');
    const rows = rowsOf('users-list');
    assert(rows.length === 25, 'página 1 deveria ter 25 linhas, veio ' + rows.length);
    assert(pagerInfo('users-pager') === '1–25 de 60 · Página 1 de 3', 'pager inesperado: ' + pagerInfo('users-pager'));
    const prev = pagerButton('users-pager', '◀ Anterior');
    const next = pagerButton('users-pager', 'Próxima ▶');
    assert(prev && next, 'botões do pager ausentes');
    assert(prev.disabled === true, 'Anterior deveria estar desabilitado na página 1');
    assert(next.disabled === false, 'Próxima deveria estar habilitada na página 1');
});

await test('2. Sessões: "Próxima" avança para as linhas 26–50; "Anterior" volta', () => {
    resetState(makeSessions(60, 50), makeUsers(50));
    run('renderUsers("")');
    pagerButton('users-pager', 'Próxima ▶').onclick();
    assert(rowsOf('users-list').length === 25, 'página 2 deveria ter 25 linhas');
    assert(pagerInfo('users-pager') === '26–50 de 60 · Página 2 de 3', 'pager inesperado: ' + pagerInfo('users-pager'));
    // ordem global preservada entre páginas: a linha 1 da página 2 é a posição26 da ordenação
    const esperado = expectedOrder(makeSessions(60, 50));
    assert(firstCell(rowsOf('users-list')[0]) === String(esperado[25].sessionId),
        'primeira linha da página 2 deveria ser sessionId ' + esperado[25].sessionId + ', veio ' + firstCell(rowsOf('users-list')[0]));
    pagerButton('users-pager', '◀ Anterior').onclick();
    assert(pagerInfo('users-pager') === '1–25 de 60 · Página 1 de 3', 'Anterior não voltou: ' + pagerInfo('users-pager'));
    // última página:11 restantes
    pagerButton('users-pager', 'Próxima ▶').onclick();
    pagerButton('users-pager', 'Próxima ▶').onclick();
    assert(pagerInfo('users-pager') === '51–60 de 60 · Página 3 de 3', 'última página inesperada: ' + pagerInfo('users-pager'));
    assert(rowsOf('users-list').length === 10, 'página 3 deveria ter 10 linhas, veio ' + rowsOf('users-list').length);
    assert(pagerButton('users-pager', 'Próxima ▶').disabled === true, 'Próxima deveria desabilitar na última página');
});

await test('3. Sessões: ordenação com índice epoch É idêntica ao algoritmo antigo (Date no sort)', () => {
    const sess = makeSessions(120, 50);
    resetState(sess, makeUsers(50));
    run('renderUsers("")');
    const rows = rowsOf('users-list');
    const esperado = expectedOrder(sess).slice(0, 25).map((s) => String(s.sessionId));
    const obtido = rows.map(firstCell);
    assert(JSON.stringify(obtido) === JSON.stringify(esperado),
        'ordem divergente do algoritmo de referência\n    esperado: ' + esperado.slice(0, 8).join(',') + '\n    obtido:   ' + obtido.slice(0, 8).join(','));
});

await test('4. Sessões: mudar filtro de status volta à página 1 e filtra', () => {
    resetState(makeSessions(60, 50), makeUsers(50));
    run('renderUsers("")');
    pagerButton('users-pager', 'Próxima ▶').onclick();
    assert(/Página 2/.test(pagerInfo('users-pager')), 'deveria estar na página 2');
    documentStub.getElementById('filter-status').value = 'Ativo';
    run('filterUsers()');
    assert(rowsOf('users-list').length === 3, 'filtro Ativo deveria dar 3 linhas, veio ' + rowsOf('users-list').length);
    assert(pagerInfo('users-pager') === '1–3 de 3 · Página 1 de 1', 'filtro deveria resetar para a página 1: ' + pagerInfo('users-pager'));
    // re-render SEM mudar a assinatura (ex.: toggle de status) preserva a página corrente
    documentStub.getElementById('filter-status').value = 'todos';
    run('renderUsers("")');                    // sig nova → página 1
    pagerButton('users-pager', 'Próxima ▶').onclick();
    const paginaAntes = pagerInfo('users-pager');
    run('renderUsers("")');                    // mesma assinatura → mantém página
    assert(pagerInfo('users-pager') === paginaAntes, 're-render sem mudança de filtro não deveria mudar de página');
});

await test('5. Sessões: busca sem resultado esconde o pager; dados encolhidos são clamped', () => {
    resetState(makeSessions(60, 50), makeUsers(50));
    run('renderUsers("")');
    pagerButton('users-pager', 'Próxima ▶').onclick();   // página 2
    documentStub.getElementById('search-input').value = 'zzzzz';
    run('filterUsers()');
    assert(rowsOf('users-list').length === 0, 'busca sem resultado deveria zerar linhas');
    assert(documentStub.getElementById('users-pager').hidden === true, 'pager deveria some com tabela vazia');
    // volta para a página 2 com60 registros e encolhe para10 → clamp para a página 1
    documentStub.getElementById('search-input').value = '';
    run('filterUsers()');
    pagerButton('users-pager', 'Próxima ▶').onclick();
    assert(/Página 2/.test(pagerInfo('users-pager')), 'deveria estar na página 2');
    run('sessions = sessions.slice(0, 10); renderUsers("");');
    assert(pagerInfo('users-pager') === '1–10 de 10 · Página 1 de 1', 'página deveria ser clamped após encolher: ' + pagerInfo('users-pager'));
    assert(rowsOf('users-list').length === 10, '10 registros deveriam aparecer');
});

// ═══ Tabela de cadastros ═══

await test('6. Cadastros:120 usuários paginam em50; busca por nome reduz e reset a página', () => {
    resetState([], makeUsers(120), []);
    run('renderRegistrationList("")');
    assert(rowsOf('registration-list').length === 50, 'página 1 deveria ter50 linhas, veio ' + rowsOf('registration-list').length);
    assert(pagerInfo('registration-pager') === '1–50 de 120 · Página 1 de 3', 'pager inesperado: ' + pagerInfo('registration-pager'));
    pagerButton('registration-pager', 'Próxima ▶').onclick();
    assert(pagerInfo('registration-pager') === '51–100 de 120 · Página 2 de 3', 'página 2 inesperada: ' + pagerInfo('registration-pager'));
    // busca 'silva' →12 usuários (cada10º)
    run('renderRegistrationList("silva")');
    assert(rowsOf('registration-list').length === 12, 'busca "silva" deveria dar12, veio ' + rowsOf('registration-list').length);
    assert(pagerInfo('registration-pager') === '1–12 de 12 · Página 1 de 1', 'busca deveria resetar à página1: ' + pagerInfo('registration-pager'));
});

// ═══ Tabela de auditoria ═══

await test('7. Auditoria: teto de200 substituído por paginação real (120 →3 páginas de50)', () => {
    resetState([], makeUsers(5), makeAudit(120));
    run('renderAuditTable()');
    assert(rowsOf('audit-list').length === 50, 'página 1 deveria ter50 linhas, veio ' + rowsOf('audit-list').length);
    assert(pagerInfo('audit-pager') === '1–50 de 120 · Página 1 de 3', 'pager inesperado: ' + pagerInfo('audit-pager'));
    const note = documentStub.getElementById('audit-note').textContent;
    assert(/página 1 de 3/.test(note), 'nota deveria citar a página: ' + note);
    assert(!/máx\. 200/.test(note), 'nota não deveria mais citar o teto de200');
    pagerButton('audit-pager', 'Próxima ▶').onclick();
    assert(rowsOf('audit-list').length === 50 && /Página 2 de 3/.test(pagerInfo('audit-pager')), 'página 2 falhou');
    // dados MAIS ANTIGOS que o antigo teto de200 continuam acessíveis (120 > teto antigo? aqui120<200;
    // provar acesso a registros "profundos":120 registros, página3 contém o registro mais antigo a1)
    pagerButton('audit-pager', 'Próxima ▶').onclick();
    const lastPageHasOldest = rowsOf('audit-list').some((r) => String(r.innerHTML).includes('>teste.1<'));
    assert(lastPageHasOldest, 'registro mais antigo (teste.1) deveria estar na última página');
});

await test('8. Auditoria: mudar filtro de período reset para a página 1', () => {
    resetState([], makeUsers(5), makeAudit(120));
    run('renderAuditTable()');
    pagerButton('audit-pager', 'Próxima ▶').onclick();
    assert(/Página 2/.test(pagerInfo('audit-pager')), 'deveria estar na página 2');
    documentStub.getElementById('audit-filter-start').value = '2026-01-01';   // tudo a partir de jan/2026 →120
    documentStub.getElementById('audit-filter-end').value = '2026-01-01';     // só01/01 → poucos
    run('renderAuditTable()');
    assert(/Página 1 de/.test(pagerInfo('audit-pager')), 'filtro de período deveria resetar à página 1: ' + pagerInfo('audit-pager'));
});

await test('9. Compatibilidade: páginas cabem nos cenários dos testes existentes (1 página)', () => {
    // espelha o cenário do test_reentrada:3 sessões → tudo cabe, pager1/1
    resetState(makeSessions(3, 50), makeUsers(50), []);
    run('renderUsers("")');
    assert(rowsOf('users-list').length === 3, '3 sessões deveriam aparecer de uma vez');
    assert(pagerInfo('users-pager') === '1–3 de 3 · Página 1 de 1', 'pager1/1 esperado: ' + pagerInfo('users-pager'));
});

console.log(`\nResultado: ${passed} aprovados, ${failed} reprovados.`);
process.exit(failed > 0 ? 1 : 0);
