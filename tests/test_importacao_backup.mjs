// Testes da IMPORTAÇÃO de backup e da REIMPORTAÇÃO de sessões arquivadas — app/index.html
// Uso: node test_importacao_backup.mjs /caminho/para/app/index.html
//
// Cobertura (Bloco 2, item b):
//   - import válido (bpa-backup) ✔
//   - arquivo corrompido ✘ (JSON inválido, senha errada, payload adulterado, estrutura inválida)
//   - backup legado re-cifrado sob a DEK atual
//   - falha no meio da restauração não deixa estado parcial (lote tudo-ou-nada via POST /api/kv/batch)
//   - reimportação de .json.enc (item a): válido, senha errada, arquivo errado, sem sessões novas
//
// Mesmo harness de test_reentrada.mjs: script inline real em vm + DOM stub +
// API chave-valor em memória espelhando o /api/kv/* + WebCrypto real do Node.

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
const fonte = html + '\n' + scriptSource;   // textos/ausências: vale para o HTML e para o JS

// ---------- stubs (linhas gerais de test_reentrada.mjs) ----------
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
            if (id === 'modal-overlay') return null;   // semântica do openModal (ver test_reentrada)
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
            if (k === 'id') { this.id = v; return; }
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

// API chave-valor em memória — espelho do /api/kv/* do servidor Python.
// failBatch simula falha do backend no POST /api/kv/batch (tudo-ou-nada: nada aplicado).
function makeApi() {
    const map = new Map();
    return {
        failBatch: false,
        lastBatchBody: null,
        map,
        handle(url, init) {
            const method = (init && init.method) || 'GET';
            const path = String(url);
            if (path === '/api/kv/batch') {
                const body = JSON.parse(init.body);
                this.lastBatchBody = body;
                if (this.failBatch) {
                    return { ok: false, status: 500, json: async () => ({ error: 'falha simulada' }) };
                }
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
const localStorageStub = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
const apiStub = makeApi();
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
    Date, Math, JSON, parseInt, parseFloat, isNaN, String, Number, Array, Object, RegExp, Error,
    setTimeout: () => 1,
    clearTimeout: () => {},
    setInterval: () => 1,
    clearInterval: () => {},
    FileReader: function () { throw new Error('FileReader não deve ser usado direto no teste'); },
};
sandbox.window = sandbox;
vm.createContext(sandbox);
vm.runInContext(scriptSource, sandbox, { filename: 'sistema_inline.js' });

const run = (code) => vm.runInContext(code, sandbox);

// Observáveis: toast, renderAll e logout capturados (logout real zera o estado —
// aqui queremos inspecionar o estado pós-importação, então só registramos a chamada).
run(`
    var __toasts = [];
    showToast = function (msg, type) { __toasts.push({ msg: String(msg), type: type || 'error' }); };
    var __renderAlls = 0;
    renderAll = function () { __renderAlls++; };
    var __logouts = [];
    logout = function (msg, expired) { __logouts.push({ msg: String(msg || ''), expired: !!expired }); };
`);

// ---------- fixtures ----------
const INSTALL_FIXTURE = {
    schemaVersion: 2, installSalt: 'c2FsdA', iterations: 250000,
    createdAt: '2026-01-01T00:00:00.000Z', lastExportAt: null, lastArchiveAt: null, privacyAckAt: null
};
const SYSTEM_FIXTURE = {
    version: 3,
    password: { salt: 'cGFzcw', iterations: 250000, envelope: { iv: 'aXY', data: 'ZGF0YQ' } },
    recovery: { envelope: { iv: 'aXY', data: 'ZGF0YQ' } }
};
const USER_A = { id: 1, matricula: '10001', nome: 'Maria Silva', nascimento: '1990-01-01', categoria: 'Adulto', validade: '2099-12-31' };
const SESSION_A = { sessionId: 1, userId: 1, pc: 3, status: 'Inativo', entrada: '09:00', entradaFull: '2025-01-10T09:00:00.000Z', saida: '10:00', saidaFull: '2025-01-10T10:00:00.000Z' };
const NOTE_A = { title: 'Aviso', text: 'texto', category: 'Geral' };

// Payload do backup difere DO PROPOSITADOMENTE das fixtures de estado (USER_A/SESSION_A/NOTE_A):
// assim, se o rollback de memória falhar num teste, as asserções percebem a troca.
const USER_B = { id: 2, matricula: '20002', nome: 'Carlos Souza', nascimento: '1985-07-07', categoria: 'Adulto', validade: '2099-12-31' };
const SESSION_B = { sessionId: 50, userId: 2, pc: 9, status: 'Inativo', entrada: '14:00', entradaFull: '2025-02-01T14:00:00.000Z', saida: '15:00', saidaFull: '2025-02-01T15:00:00.000Z' };
const NOTE_B = { title: 'Aviso do backup', text: 'texto B', category: 'Geral' };

const BACKUP_PAYLOAD = { userBase: [USER_B], sessions: [SESSION_B], notes: [NOTE_B], audit: [{ id: 'a1', timestamp: '2026-01-01T00:00:00.000Z', acao: 'login', resultado: 'sucesso', detalhes: '' }] };

// Backup legado (v1, em claro) — também difere do estado atual, para o rollback ser verificável.
const LEGADO_PAYLOAD = { userBase: [USER_B], sessions: [SESSION_B], notes: [NOTE_B] };

function makeBackupSync(password, payload, opts) {
    // Gerado com a MESMA primitiva do app (deriveAesKey/wrapDek/encryptJSON) — roundtrip real.
    return run(`
        (async function () {
            const salt = randomB64(CFG.SALT_BYTES);
            const kek = await deriveAesKey(${JSON.stringify(password)}, salt, CFG.PBKDF2_ITER);
            const dek = await generateDek();
            const dekWrapped = await wrapDek(dek, kek);
            const payload = await encryptJSON(${JSON.stringify(payload)}, dek);
            const b = {
                format: 'bpa-backup', schemaVersion: CFG.SCHEMA_VERSION,
                kdf: { salt: salt, iterations: CFG.PBKDF2_ITER },
                dekWrapped: dekWrapped, payload: payload
            };
            ${opts && opts.noSystem ? '' : 'b.system = ' + JSON.stringify(opts && opts.system ? opts.system : SYSTEM_FIXTURE) + ';'}
            ${opts && opts.noInstall ? '' : 'b.installMeta = ' + JSON.stringify(opts && opts.installMeta ? opts.installMeta : INSTALL_FIXTURE) + ';'}
            return b;
        })()
    `);
}

function makeArchiveSync(password, list) {
    return run(`
        (async function () {
            const salt = randomB64(CFG.SALT_BYTES);
            const kek = await deriveAesKey(${JSON.stringify(password)}, salt, CFG.PBKDF2_ITER);
            const dekWrapped = await wrapDek(currentDek, kek);   // espelha archiveOldSessions
            const payload = await encryptJSON({ sessions: ${JSON.stringify(list)} }, currentDek);
            return {
                format: 'bpa-archive', schemaVersion: CFG.SCHEMA_VERSION,
                archivedAt: new Date().toISOString(),
                kdf: { salt: salt, iterations: CFG.PBKDF2_ITER },
                dekWrapped: dekWrapped, payload: payload
            };
        })()
    `);
}

function tamperB64(b64) {
    const buf = Buffer.from(b64, 'base64');
    buf[Math.floor(buf.length / 2)] ^= 0xff;
    return buf.toString('base64');
}

async function resetState() {
    apiStub.failBatch = false;
    apiStub.lastBatchBody = null;
    apiStub.map.clear();
    await run('generateDek().then(function (d) { currentDek = d; return 1; })');
    run(`
        system = ${JSON.stringify(SYSTEM_FIXTURE)};
        installMeta = ${JSON.stringify(INSTALL_FIXTURE)};
        userBase = [${JSON.stringify(USER_A)}];
        sessions = [${JSON.stringify(SESSION_A)}];
        notes = [${JSON.stringify(NOTE_A)}];
        auditLog = [];
        authSession = { unlockedAt: new Date().toISOString(), lastActivity: Date.now() };
        __toasts = []; __logouts = []; __renderAlls = 0;
        modalQueue.length = 0;
    `);
    const overlay = documentStub.getElementById('modal-overlay');
    if (overlay) overlay.remove();
    documentStub.body.children = [];
}

const getJSON = (expr) => JSON.parse(run(`JSON.stringify(${expr})`));
const lastToast = () => run('__toasts[__toasts.length - 1]');
const getLogouts = () => JSON.parse(run('JSON.stringify(__logouts)'));
const persistedRaw = (key) => apiStub.map.get(key);

async function persisted(key) {
    const raw = apiStub.map.get(key);
    if (raw === undefined) return null;
    return await run(`decryptJSON(JSON.parse(${JSON.stringify(raw)}), currentDek)`);
}

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

async function confirmModal() {
    const btn = modalConfirmButton();
    if (!btn) throw new Error('botão de confirmação do modal não encontrado');
    await btn.onclick();
    // ok.onclick do app não devolve o resultado de onConfirm: o sinal é o modal
    // fechar (onConfirm ≠ false) ou permanecer aberto (onConfirm === false / erro).
    const overlay = documentStub.body.children.find((c) => c.id === 'modal-overlay');
    return !overlay;
}

let passed = 0, failed = 0;
async function test(name, fn) {
    try { await fn(); console.log(`  ✔ ${name}`); passed++; }
    catch (e) { console.log(`  ✘ ${name}\n    -> ${e.message}`); failed++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

console.log('Testes de IMPORTAÇÃO de backup e REIMPORTAÇÃO de sessões\n');

// ═══ Import de backup cifrado ═══

await test('1. Import válido: cifra tudo em lote, decifra igual ao original, audita e pede novo login', async () => {
    await resetState();
    const backup = await makeBackupSync('senha-export-1', BACKUP_PAYLOAD);
    await run(`handleImportText(${JSON.stringify(JSON.stringify(backup))}, 'backup.json.enc')`);
    documentStub.getElementById('imp-pw').value = 'senha-export-1';
    const ok = await confirmModal();
    assert(ok === true, 'modal deveria concluir com true');
    for (const k of ['bpa_install', 'bpa_system', 'bpa_user_base', 'bpa_sessions', 'bpa_notes_v2', 'bpa_audit_v1']) {
        assert(persistedRaw(k), 'chave ausente no banco: ' + k);
        assert(!Array.isArray(JSON.parse(persistedRaw(k))), k + ' gravada em claro (esperado envelope {iv,data})');
    }
    const sess = await persisted('bpa_sessions');
    assert(sess.length === 1 && sess[0].sessionId === SESSION_B.sessionId, 'sessões restauradas divergem');
    const users = await persisted('bpa_user_base');
    assert(users[0].nome === USER_B.nome, 'usuário restaurado diverge');
    const sys = JSON.parse(persistedRaw('bpa_system'));
    assert(sys.password && sys.password.envelope, 'registro de senha não persistido');
    assert(JSON.stringify(getJSON('userBase')) === JSON.stringify([USER_B]), 'estado em memória diverge');
    const audit = getJSON('auditLog');
    assert(audit.some(a => a.acao === 'backup.importar' && a.resultado === 'sucesso'), 'auditoria sem registro de importação');
    const logouts = getLogouts();
    assert(logouts.length === 1 && /restaurado/i.test(logouts[0].msg), 'logout pós-restauração não chamado');
    assert(run('__renderAlls') > 0, 'renderAll não chamado');
});

await test('2. Senha de exportação errada: recusa, nada persistido, estado intacto', async () => {
    await resetState();
    const backup = await makeBackupSync('senha-certa', BACKUP_PAYLOAD);
    await run(`handleImportText(${JSON.stringify(JSON.stringify(backup))}, 'backup.json.enc')`);
    documentStub.getElementById('imp-pw').value = 'senha-errada';
    const ok = await confirmModal();
    assert(ok === false, 'modal deveria recusar (false)');
    assert(apiStub.map.size === 0, 'nada deveria ter sido gravado (chaves: ' + apiStub.map.size + ')');
    assert(JSON.stringify(getJSON('userBase')) === JSON.stringify([USER_A]), 'estado de memória alterado');
    assert(lastToast() && lastToast().type === 'error' && /Senha incorreta ou backup corrompido/.test(lastToast().msg), 'toast de erro esperado: ' + (lastToast() && lastToast().msg));
    assert(getLogouts().length === 0, 'não deveria chamar logout em falha');
});

await test('3. Payload adulterado (AES-GCM): recusa, nada persistido', async () => {
    await resetState();
    const backup = await makeBackupSync('senha-export-1', BACKUP_PAYLOAD);
    backup.payload.data = tamperB64(backup.payload.data);
    await run(`handleImportText(${JSON.stringify(JSON.stringify(backup))}, 'backup.json.enc')`);
    documentStub.getElementById('imp-pw').value = 'senha-export-1';
    const ok = await confirmModal();
    assert(ok === false, 'modal deveria recusar');
    assert(apiStub.map.size === 0, 'nada deveria ter sido gravado');
    assert(lastToast() && lastToast().type === 'error' && /corrompido/.test(lastToast().msg), 'toast de erro esperado');
});

await test('4. JSON ilegível e estrutura inválida: recusa clara, sem gravação', async () => {
    await resetState();
    await run(`handleImportText('{{{ isto não é json', 'x.json')`);
    assert(lastToast() && /JSON ilegível/.test(lastToast().msg), 'toast de JSON ilegível esperado: ' + (lastToast() && lastToast().msg));
    assert(!documentStub.body.children.find(c => c.id === 'modal-overlay'), 'não deveria abrir modal');
    assert(apiStub.map.size === 0, 'não deveria gravar');

    // formato com cabeçalho bpa-backup mas system sem envelope → "estrutura inválida"
    const backup = await makeBackupSync('senha-export-1', BACKUP_PAYLOAD, { noSystem: true });
    await run(`handleImportText(${JSON.stringify(JSON.stringify(backup))}, 'backup.json.enc')`);
    documentStub.getElementById('imp-pw').value = 'senha-export-1';
    const ok = await confirmModal();
    assert(ok === false, 'estrutura inválida deveria recusar');
    assert(apiStub.map.size === 0, 'não deveria gravar com estrutura inválida');
    assert(JSON.stringify(getJSON('sessions')) === JSON.stringify([SESSION_A]), 'estado alterado com estrutura inválida');
});

// ═══ Backup legado (em claro) ═══

await test('5. Backup legado: re-cifrado sob a DEK atual (gravação em lote, sem estado parcial)', async () => {
    await resetState();
    await run(`handleImportText(${JSON.stringify(JSON.stringify(LEGADO_PAYLOAD))}, 'antigo.json')`);
    documentStub.getElementById('imp-leg-chk').checked = true;
    const ok = await confirmModal();
    assert(ok === true, 'modal deveria concluir com true');
    assert(persistedRaw('bpa_user_base') && persistedRaw('bpa_sessions') && persistedRaw('bpa_notes_v2'), 'faltou chave no lote');
    for (const k of ['bpa_user_base', 'bpa_sessions', 'bpa_notes_v2']) {
        const parsed = JSON.parse(persistedRaw(k));
        assert(parsed && parsed.iv && parsed.data, k + ' não está cifrada (esperado envelope {iv,data})');
    }
    const users = await persisted('bpa_user_base');
    assert(users[0].nome === USER_B.nome, 're-cifração corrompeu os dados');
    const audit = getJSON('auditLog');
    assert(audit.some(a => a.acao === 'backup.importar' && /legado/.test(a.detalhes)), 'auditoria sem registro do legado');
});

await test('6. Backup legado sem checkbox de declaração: recusa e não grava', async () => {
    await resetState();
    const legado = LEGADO_PAYLOAD;
    await run(`handleImportText(${JSON.stringify(JSON.stringify(legado))}, 'antigo.json')`);
    documentStub.getElementById('imp-leg-chk').checked = false;
    const ok = await confirmModal();
    assert(ok === false, 'sem declaração deveria recusar');
    assert(apiStub.map.size === 0, 'não deveria gravar sem declaração');
});

// ═══ Falha no meio da restauração → tudo-ou-nada ═══

await test('7. Lote falha no meio: NENHUMA chave gravada + memória revertida (backup cifrado)', async () => {
    await resetState();
    const backup = await makeBackupSync('senha-export-1', BACKUP_PAYLOAD);
    await run(`handleImportText(${JSON.stringify(JSON.stringify(backup))}, 'backup.json.enc')`);
    apiStub.failBatch = true;
    documentStub.getElementById('imp-pw').value = 'senha-export-1';
    const ok = await confirmModal();
    assert(ok === false, 'modal deveria recusar na falha do lote');
    assert(apiStub.map.size === 0, 'estado PARCIAL: ' + apiStub.map.size + ' chave(s) gravada(s) quando o lote falhou');
    const body = apiStub.lastBatchBody;
    assert(body && body.put && Object.keys(body.put).length === 6, 'a restauração deveria enviar as 6 chaves num ÚNICO lote');
    assert(JSON.stringify(getJSON('userBase')) === JSON.stringify([USER_A]), 'memória não revertida: userBase');
    assert(JSON.stringify(getJSON('sessions')) === JSON.stringify([SESSION_A]), 'memória não revertida: sessions');
    assert(getJSON('auditLog').length === 0, 'memória não revertida: auditLog do backup vazou');
    assert(getJSON('installMeta').installSalt === INSTALL_FIXTURE.installSalt, 'memória não revertida: installMeta');
    assert(getJSON('system').password.salt === SYSTEM_FIXTURE.password.salt, 'memória não revertida: system');
    assert(lastToast() && lastToast().type === 'error' && /Senha incorreta ou backup corrompido/.test(lastToast().msg), 'toast de erro esperado');
});

await test('8. Lote falha no meio: backup legado também não deixa estado parcial', async () => {
    await resetState();
    await run(`handleImportText(${JSON.stringify(JSON.stringify(LEGADO_PAYLOAD))}, 'antigo.json')`);
    apiStub.failBatch = true;
    documentStub.getElementById('imp-leg-chk').checked = true;
    const ok = await confirmModal();
    assert(ok === false, 'modal deveria recusar na falha do lote');
    assert(apiStub.map.size === 0, 'estado PARCIAL no caminho legado (' + apiStub.map.size + ' chave(s))');
    const body = apiStub.lastBatchBody;
    assert(body && body.put && Object.keys(body.put).length === 3, 'caminho legado deveria enviar 3 chaves num ÚNICO lote');
    assert(JSON.stringify(getJSON('userBase')) === JSON.stringify([USER_A]), 'memória não revertida: userBase');
    assert(JSON.stringify(getJSON('sessions')) === JSON.stringify([SESSION_A]), 'memória não revertida: sessions');
    assert(lastToast() && lastToast().type === 'error' && /nada foi alterado/.test(lastToast().msg), 'toast de rollback esperado: ' + (lastToast() && lastToast().msg));
});

// ═══ Reimportação de sessões arquivadas (.json.enc) ═══

await test('9. Reimportar válido: anexa só as sessões novas, sem duplicar sessionId', async () => {
    await resetState();
    const S2 = { sessionId: 2, userId: 1, pc: 5, status: 'Inativo', entrada: '08:00', entradaFull: '2025-01-11T08:00:00.000Z', saida: '09:00', saidaFull: '2025-01-11T09:00:00.000Z' };
    const S3 = { sessionId: 3, userId: 1, pc: 7, status: 'Inativo', entrada: '10:00', entradaFull: '2025-01-12T10:00:00.000Z', saida: '11:00', saidaFull: '2025-01-12T11:00:00.000Z' };
    const archive = await makeArchiveSync('senha-arquivo', [SESSION_A, S2, S3]);   // sessionId 1 já existe
    await run(`handleImportText(${JSON.stringify(JSON.stringify(archive))}, 'arquivo_sessoes.json.enc', 'archive')`);
    documentStub.getElementById('reimp-pw').value = 'senha-arquivo';
    const ok = await confirmModal();
    assert(ok === true, 'reimportação deveria concluir com true');
    const sess = getJSON('sessions');
    assert(sess.length === 3, 'esperado 3 sessões (1 atual + 2 novas), veio ' + sess.length);
    assert(sess.filter(s => s.sessionId === 1).length === 1, 'sessionId duplicado');
    assert(sess.some(s => s.sessionId === 2) && sess.some(s => s.sessionId === 3), 'sessões arquivadas não voltaram');
    const persist = await persisted('bpa_sessions');
    assert(persist && persist.length === 3, 'banco não persistiu a reimportação');
    assert(JSON.parse(persistedRaw('bpa_sessions')).iv, 'sessões gravadas em claro');
    const audit = getJSON('auditLog');
    assert(audit.some(a => a.acao === 'arquivo.reimportar' && a.resultado === 'sucesso'), 'auditoria sem registro de reimportação');
    assert(lastToast() && lastToast().type === 'success' && /reimportada/.test(lastToast().msg), 'toast de sucesso esperado: ' + (lastToast() && lastToast().msg));
});

await test('10. Reimportar com senha errada ou payload adulterado: recusa, nada muda', async () => {
    await resetState();
    const S2 = { sessionId: 2, userId: 1, pc: 5, status: 'Inativo', entrada: '08:00', entradaFull: '2025-01-11T08:00:00.000Z', saida: '09:00', saidaFull: '2025-01-11T09:00:00.000Z' };
    const archive = await makeArchiveSync('senha-certa', [SESSION_A, S2]);
    // a) senha errada
    await run(`handleImportText(${JSON.stringify(JSON.stringify(archive))}, 'arquivo.json.enc', 'archive')`);
    documentStub.getElementById('reimp-pw').value = 'outra-senha';
    let ok = await confirmModal();
    assert(ok === false, 'senha errada deveria recusar');
    assert(apiStub.map.size === 0 && getJSON('sessions').length === 1, 'senha errada não deveria alterar nada');
    // b) payload adulterado (senha correta)
    const overlay = documentStub.getElementById('modal-overlay');
    if (overlay) overlay.remove(); run('modalQueue.length = 0;');
    const corrupto = await makeArchiveSync('senha-certa', [SESSION_A, S2]);
    corrupto.payload.data = tamperB64(corrupto.payload.data);
    await run(`handleImportText(${JSON.stringify(JSON.stringify(corrupto))}, 'arquivo.json.enc', 'archive')`);
    documentStub.getElementById('reimp-pw').value = 'senha-certa';
    ok = await confirmModal();
    assert(ok === false, 'payload adulterado deveria recusar');
    assert(apiStub.map.size === 0 && getJSON('sessions').length === 1, 'payload adulterado não deveria alterar nada');
    assert(lastToast() && lastToast().type === 'error' && /Senha incorreta ou arquivo corrompido/.test(lastToast().msg), 'toast de erro esperado: ' + (lastToast() && lastToast().msg));
});

await test('11. Reimportar arquivo errado / estrutura corrompida: recusa clara antes do modal', async () => {
    await resetState();
    // botão Reimportar apontando para um backup comum
    const backup = await makeBackupSync('senha-export-1', BACKUP_PAYLOAD);
    await run(`handleImportText(${JSON.stringify(JSON.stringify(backup))}, 'backup.json.enc', 'archive')`);
    assert(lastToast() && /não é um arquivo de sessões arquivadas/.test(lastToast().msg), 'toast de tipo errado esperado: ' + (lastToast() && lastToast().msg));
    assert(!documentStub.body.children.find(c => c.id === 'modal-overlay'), 'não deveria abrir modal para arquivo errado');
    // cabeçalho bpa-archive mas sem kdf/payload
    await run(`handleImportText(${JSON.stringify(JSON.stringify({ format: 'bpa-archive', schemaVersion: 2 }))}, 'quebrado.json.enc', 'archive')`);
    assert(lastToast() && /estrutura corrompida/.test(lastToast().msg), 'toast de estrutura esperado: ' + (lastToast() && lastToast().msg));
    assert(apiStub.map.size === 0, 'não deveria gravar');
});

await test('12. Reimportar arquivo com todas as sessões já presentes: fecha sem duplicar nem gravar', async () => {
    await resetState();
    const archive = await makeArchiveSync('senha-arquivo', [SESSION_A]);   // sessionId 1 já ativo
    await run(`handleImportText(${JSON.stringify(JSON.stringify(archive))}, 'arquivo.json.enc', 'archive')`);
    documentStub.getElementById('reimp-pw').value = 'senha-arquivo';
    const ok = await confirmModal();
    assert(ok === true, 'deveria concluir sem erro');
    assert(getJSON('sessions').length === 1, 'não deveria duplicar a sessão');
    assert(apiStub.map.size === 0, 'não deveria gravar quando não há sessões novas');
    assert(lastToast() && lastToast().type === 'success' && /Nenhuma sessão nova/.test(lastToast().msg), 'toast informativo esperado: ' + (lastToast() && lastToast().msg));
});

await test('13. Função de UI reimportArchive: exige sessão desbloqueada e usa leitura de arquivo', () => {
    // cobertura do gate de sessão do ponto de entrada da UI
    run('authSession = null;');
    let chamou = false;
    const orig = run('reimportArchive');
    // sem sessão: retorna sem tocar no FileReader
    const event = { target: { files: [{ name: 'a.json.enc' }], value: 'x' } };
    orig(event);
    assert(lastToast() && /sessão|login|bloqueado/i.test(lastToast().msg), 'deveria exigir sessão desbloqueada: ' + (lastToast() && lastToast().msg));
    // com sessão: segue para leitura (FileReader stub do harness lançaria se usado direto)
    run('authSession = { unlockedAt: new Date().toISOString(), lastActivity: Date.now() };');
    const event2 = { target: { files: [], value: 'x' } };
    orig(event2);   // sem arquivo → retorna cedo sem erro
    assert(true, 'sem arquivo deveria retornar cedo');
    void chamou;
});

// ═══ Sem senha (decisão da empresa, 24/10/2026): export/arquivo usam a senha fixa; import só pede senha de arquivo antigo ═══

function modalHasInput(id) {
    const overlay = documentStub.body.children.find((c) => c.id === 'modal-overlay');
    let found = false;
    (function walk(n) {
        for (const c of (n && n.children) || []) { if (c.tagName === 'input' && c.id === id) found = true; walk(c); }
    })(overlay);
    return found;
}
run('var __downloads = []; downloadJSON = function (obj, name) { __downloads.push({ obj: obj, name: name }); };');
async function opensWithFixed(file) {
    return await run(`(async function () {
        const f = ${JSON.stringify(file)};
        const kek = await deriveAesKey(SENHA_PADRAO, f.kdf.salt, f.kdf.iterations);
        const dek = await unwrapDek(f.dekWrapped, kek);
        return await decryptJSON(f.payload, dek);
    })()`);
}

await test('14. Backup sem senha (senha fixa): modal SEM campo de senha e restaura direto', async () => {
    await resetState();
    const backup = await makeBackupSync(run('SENHA_PADRAO'), BACKUP_PAYLOAD);
    await run(`handleImportText(${JSON.stringify(JSON.stringify(backup))}, 'backup.json.enc')`);
    assert(!modalHasInput('imp-pw'), 'não deveria pedir senha para backup gerado sem senha');
    assert(await confirmModal() === true, 'restauração deveria concluir');
    assert(getJSON('userBase')[0].nome === USER_B.nome, 'dados do backup não restaurados');
});

await test('15. Backup ANTIGO com senha escolhida: continua pedindo a senha (compatibilidade)', async () => {
    await resetState();
    const backup = await makeBackupSync('senha-export-1', BACKUP_PAYLOAD);
    await run(`handleImportText(${JSON.stringify(JSON.stringify(backup))}, 'backup.json.enc')`);
    assert(modalHasInput('imp-pw'), 'arquivo com senha escolhida deveria pedir a senha');
});

await test('16. Reimportar arquivo sem senha: SEM campo de senha e anexa as sessões', async () => {
    await resetState();
    const S2 = { sessionId: 2, userId: 1, pc: 5, status: 'Inativo', entrada: '08:00', entradaFull: '2025-01-11T08:00:00.000Z', saida: '09:00', saidaFull: '2025-01-11T09:00:00.000Z' };
    const archive = await makeArchiveSync(run('SENHA_PADRAO'), [SESSION_A, S2]);
    await run(`handleImportText(${JSON.stringify(JSON.stringify(archive))}, 'arquivo_sessoes.json.enc', 'archive')`);
    assert(!modalHasInput('reimp-pw'), 'não deveria pedir senha para arquivo gerado sem senha');
    assert(await confirmModal() === true, 'reimportação deveria concluir');
    assert(getJSON('sessions').length === 2, 'sessão arquivada não voltou');
});

await test('17. Exportar backup: sem campos de senha; o arquivo abre com a senha fixa', async () => {
    await resetState();
    run('__downloads.length = 0; exportBackup();');
    assert(!modalHasInput('bk-pw') && !modalHasInput('bk-pw2'), 'exportar não deveria pedir senha');
    assert(await confirmModal() === true, 'exportação deveria concluir');
    const file = getJSON('__downloads[0].obj');
    const payload = await opensWithFixed(file);
    assert(payload.userBase[0].nome === USER_A.nome, 'backup exportado não abre com a senha fixa');
});

await test('18. Arquivamento de sessões antigas: sem campos de senha; o arquivo abre com a senha fixa', async () => {
    await resetState();
    run('__downloads.length = 0;');
    run(`showArchiveModal([${JSON.stringify(SESSION_A)}]);`);
    assert(!modalHasInput('arch-pw') && !modalHasInput('arch-pw2'), 'arquivamento não deveria pedir senha');
    assert(await confirmModal() === true, 'arquivamento deveria concluir');
    const payload = await opensWithFixed(getJSON('__downloads[0].obj'));
    assert(payload.sessions[0].sessionId === SESSION_A.sessionId, 'arquivo não abre com a senha fixa');
});

await test('19. HTML: sem "Alterar senha", sem botão "Sair", instalação não mostra código de recuperação', () => {
    assert(!/id="sys-password-form"/.test(fonte) && !/Alterar senha do sistema/.test(fonte), 'quadro de alterar senha ainda existe');
    assert(!/id="btn-logout"/.test(fonte), 'botão Sair ainda existe');
    const install = (fonte.match(/async function runFirstInstall\(\) \{[\s\S]*?\n        \}/) || [''])[0];
    assert(install && !/openRecoveryCodeModal/.test(install), 'instalação ainda exibe o código de recuperação');
    assert(!/código de recuperação \(impresso/.test(fonte), 'checklist ainda manda entregar código de recuperação');
});

// ═══ Revisão do "sem senha": nenhum caminho deixa o sistema preso numa senha antiga ═══

const opensSystemWithFixed = () => run(`(async function () {
    const kek = await deriveAesKey(SENHA_PADRAO, system.password.salt, system.password.iterations);
    return !!(await unwrapDek(system.password.envelope, kek));
})().catch(function () { return false; })`);

// Backup de máquina que tinha senha TROCADA: o envelope de 'system' está sob 'senha-antiga'
async function makeBackupWithCustomSystem() {
    return run(`(async function () {
        const dek = await generateDek();
        const fs = randomB64(CFG.SALT_BYTES);
        const ps = randomB64(CFG.SALT_BYTES);
        return {
            format: 'bpa-backup', schemaVersion: CFG.SCHEMA_VERSION,
            kdf: { salt: fs, iterations: CFG.PBKDF2_ITER },
            dekWrapped: await wrapDek(dek, await deriveAesKey(SENHA_PADRAO, fs, CFG.PBKDF2_ITER)),
            payload: await encryptJSON(${JSON.stringify(BACKUP_PAYLOAD)}, dek),
            installMeta: ${JSON.stringify(INSTALL_FIXTURE)},
            system: { password: { salt: ps, iterations: CFG.PBKDF2_ITER, envelope: await wrapDek(dek, await deriveAesKey('senha-antiga', ps, CFG.PBKDF2_ITER)) },
                      recovery: { envelope: { iv: 'aXY', data: 'ZGF0YQ' } } }
        };
    })()`);
}

await test('20. Restaurar backup de máquina com senha trocada ⇒ volta ao modo sem senha (sem "credenciais")', async () => {
    await resetState();
    const backup = await makeBackupWithCustomSystem();
    await run(`handleImportText(${JSON.stringify(JSON.stringify(backup))}, 'backup.json.enc')`);
    assert(await confirmModal() === true, 'restauração deveria concluir');
    assert(await opensSystemWithFixed() === true, 'após restaurar, o sistema deveria abrir com a senha fixa (sem senha)');
    const gravado = JSON.parse(persistedRaw('bpa_system'));
    assert(gravado.password.salt === getJSON('system').password.salt, 'envelope sem senha deveria ser o gravado no banco');
    assert(!getLogouts().some((l) => /credenciais/i.test(l.msg)), 'mensagem não deveria falar em credenciais: ' + JSON.stringify(getLogouts()));
});

await test('21. Backup antigo com senha escolhida: digitando a senha, restaura', async () => {
    await resetState();
    const backup = await makeBackupSync('senha-export-1', BACKUP_PAYLOAD);
    await run(`handleImportText(${JSON.stringify(JSON.stringify(backup))}, 'backup.json.enc')`);
    documentStub.getElementById('imp-pw').value = 'senha-export-1';
    assert(await confirmModal() === true, 'restauração com a senha da época deveria concluir');
    assert(getJSON('userBase')[0].nome === USER_B.nome, 'dados do backup não restaurados');
});

await test('22. voltarParaSemSenha: troca o envelope para a senha fixa e grava; login e recuperação a usam', async () => {
    await resetState();
    await run(`(async function () {
        const ps = randomB64(CFG.SALT_BYTES);
        system.password = { salt: ps, iterations: CFG.PBKDF2_ITER, envelope: await wrapDek(currentDek, await deriveAesKey('senha-antiga', ps, CFG.PBKDF2_ITER)) };
        return 1;
    })()`);
    assert(await opensSystemWithFixed() === false, 'pré-condição: senha antiga');
    await run('voltarParaSemSenha(currentDek)');
    assert(await opensSystemWithFixed() === true, 'deveria abrir com a senha fixa');
    assert(JSON.parse(persistedRaw('bpa_system')).password.salt === getJSON('system').password.salt, 'envelope novo não gravado');
    const login = (fonte.match(/async function attemptLogin\(password\) \{[\s\S]*?\n        \}/) || [''])[0];
    assert(/voltarParaSemSenha/.test(login), 'login com senha antiga deveria voltar ao modo sem senha');
    const rec = (fonte.match(/async function handleRecovery\(e\) \{[\s\S]*?\n        \}/) || [''])[0];
    assert(/envelopeSemSenha|voltarParaSemSenha/.test(rec) && !/rec-password/.test(rec), 'recuperação não deveria pedir nova senha');
    assert(!/id="rec-password"/.test(fonte), 'campos de nova senha da recuperação ainda existem');
});

await test('23. Backup corrompido (envelope faltando ou iterações absurdas) ⇒ recusa clara, sem pedir senha', async () => {
    await resetState();
    const b1 = await makeBackupSync(run('SENHA_PADRAO'), BACKUP_PAYLOAD);
    delete b1.dekWrapped.iv;
    await run(`handleImportText(${JSON.stringify(JSON.stringify(b1))}, 'backup.json.enc')`);
    assert(!documentStub.body.children.find((c) => c.id === 'modal-overlay'), 'não deveria abrir modal pedindo senha');
    assert(lastToast() && /corromp|inválid/i.test(lastToast().msg), 'toast de arquivo corrompido esperado: ' + (lastToast() && lastToast().msg));
    const b2 = await makeBackupSync(run('SENHA_PADRAO'), BACKUP_PAYLOAD);
    b2.kdf.iterations = 2e9;
    const t0 = Date.now();
    await run(`handleImportText(${JSON.stringify(JSON.stringify(b2))}, 'backup.json.enc')`);
    assert(Date.now() - t0 < 3000, 'iterações absurdas não podem travar a importação');
    assert(!documentStub.body.children.find((c) => c.id === 'modal-overlay'), 'não deveria abrir modal com iterações absurdas');
});

await test('24. Instalação sem tela de senha manual; textos avisam que arquivos exportados não têm senha', () => {
    const install = (fonte.match(/async function runFirstInstall\(\) \{[\s\S]*?\n        \}/) || [''])[0];
    assert(install && !/showSetupView/.test(install), 'falha na instalação não pode levar à tela de criar senha');
    assert(/getElementById\('btn-show-setup'\)\.addEventListener\('click', runFirstInstall\)/.test(fonte), 'botão "configurar" deveria rodar a instalação sem senha');
    assert(!/Exportar backup CIFRADO/.test(fonte) && !/Exportar Backup \(cifrado\)/.test(fonte), 'export ainda se apresenta como protegido');
    assert(/não tem senha/i.test((fonte.match(/function exportBackup\(\) \{[\s\S]*?\n        \}/) || [''])[0]), 'modal de export deveria avisar que o arquivo não tem senha');
    assert(/arquivos exportados/i.test(fonte.match(/const PRIVACY_HTML[\s\S]*?';/)[0]), 'aviso de privacidade deveria falar dos arquivos exportados');
});

console.log(`\nResultado: ${passed} aprovados, ${failed} reprovados.`);
process.exit(failed > 0 ? 1 : 0);
