// Bloco 5 — JavaScript em arquivo externo e CSP sem 'unsafe-inline'
// Uso: node tests/test_js_externo.mjs   (servidor é spawnado pelo próprio teste)
//
// Guarda estática: nenhum <script> inline, nenhum atributo on<evento>= (no HTML ou montado
// pelo JS), CSP com script-src 'self', toda ação data-click/change/keyup existe em ACOES.
// Servidor: /app.js sai como JavaScript e sem cache (senão o navegador roda JS de ontem
// com HTML de hoje); só vendor/ pode ficar em cache.

import vm from 'node:vm';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { fileURLToPath } from 'node:url';

const PROJ = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const HTML_PATH = path.join(PROJ, 'app', 'index.html');
const JS_PATH = path.join(PROJ, 'app', 'app.js');
const PORT = 8797;

let passed = 0, failed = 0;
async function test(name, fn) {
    try { await fn(); passed++; console.log('  ✔ ' + name); }
    catch (e) { failed++; console.log('  ✘ ' + name + '\n      ' + e.message); }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

const html = fs.readFileSync(HTML_PATH, 'utf8');
const js = fs.existsSync(JS_PATH) ? fs.readFileSync(JS_PATH, 'utf8') : null;
const ATTR_INLINE = /\son[a-z]+\s*=/i;
const ATTR_EM_STRING = /\son[a-z]+\s*=\s*\\?["']/i;   // qualquer on<evento>= seguido de aspas (onmouseover, onfocus…)

await test('1. index.html: nenhum <script> inline; app.js carregado depois dos vendor/', () => {
    const tags = html.match(/<script\b[^>]*>/g) || [];
    const inline = tags.filter((t) => !/\bsrc=/.test(t));
    assert(inline.length === 0, 'há <script> inline: ' + inline.join(' '));
    const srcs = tags.map((t) => (t.match(/src="([^"]+)"/) || [])[1]);
    assert(JSON.stringify(srcs) === JSON.stringify(['vendor/chart.umd.js', 'vendor/jspdf.umd.min.js', 'vendor/html2canvas.min.js', 'app.js']),
        'ordem dos scripts inesperada: ' + JSON.stringify(srcs));
    assert(js !== null, 'app/app.js não encontrado');
});

await test('2. index.html: nenhum atributo on<evento>=', () => {
    const achados = html.split('\n').map((l, i) => [i + 1, l]).filter(([, l]) => ATTR_INLINE.test(l));
    assert(achados.length === 0, achados.length + ' atributo(s) inline, ex.: linha ' + (achados[0] || [])[0] + ': ' + ((achados[0] || [])[1] || '').trim().slice(0, 100));
});

await test('3. app.js: nenhum on<evento>= montado em string', () => {
    assert(js !== null, 'app/app.js não encontrado');
    const achados = js.split('\n').map((l, i) => [i + 1, l]).filter(([, l]) => ATTR_EM_STRING.test(l));
    assert(achados.length === 0, achados.length + ' em string, ex.: linha ' + (achados[0] || [])[0] + ': ' + ((achados[0] || [])[1] || '').trim().slice(0, 100));
});

await test("4. CSP: script-src 'self' sem 'unsafe-inline'; demais diretivas intactas", () => {
    const csp = (html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/) || [])[1];
    assert(csp, 'meta CSP não encontrada');
    const dirs = csp.split(';').map((d) => d.trim()).filter(Boolean);
    const esperado = ["default-src 'self'", "script-src 'self'", "style-src 'self' 'unsafe-inline'", "img-src 'self' data: blob:",
        "font-src 'self' data:", "connect-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'self'"];
    assert(JSON.stringify(dirs) === JSON.stringify(esperado), 'CSP inesperada: ' + csp);
});

await test('5. toda ação data-click/data-change/data-keyup existe em ACOES', () => {
    assert(js !== null, 'app/app.js não encontrado');
    const nomes = new Set();
    for (const fonte of [html, js]) {
        for (const mm of fonte.matchAll(/data-(?:click|change|keyup)=\\?["']([A-Za-z_$][\w$]*)\\?["']/g)) nomes.add(mm[1]);
    }
    assert(nomes.size >= 20, 'poucas ações encontradas (' + nomes.size + ') — conversão incompleta?');
    // carrega o app.js num contexto mínimo só para ler ACOES (nada roda: o bootstrap espera DOMContentLoaded)
    const el = () => new Proxy(function () {}, { get: (t, k) => (k === Symbol.toPrimitive ? () => '' : el()), apply: () => el() });
    const sandbox = { document: { addEventListener() {}, getElementById: () => el(), querySelectorAll: () => [] },
        window: {}, console, localStorage: { getItem: () => null, setItem() {} }, setInterval: () => 1, setTimeout: () => 1,
        TextEncoder, TextDecoder, crypto: globalThis.crypto, btoa, atob };
    sandbox.window = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(js, sandbox, { filename: 'app.js' });
    const faltando = [...nomes].filter((n) => vm.runInContext('typeof ACOES[' + JSON.stringify(n) + ']', sandbox) !== 'function');
    assert(faltando.length === 0, 'ações sem entrada em ACOES: ' + faltando.join(', '));
});

await test('6. servidor: /app.js com tipo JavaScript e sem cache; vendor/ continua em cache', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bpa_jsext_'));
    const srv = spawn('python3', ['run.py', '--sem-navegador', '--porta', String(PORT), '--data', dataDir], { cwd: PROJ, stdio: 'ignore' });
    try {
        const base = 'http://127.0.0.1:' + PORT;
        let ok = false;
        for (let i = 0; i < 50 && !ok; i++) {
            try { ok = (await fetch(base + '/api/health')).ok; } catch { await new Promise((r) => setTimeout(r, 200)); }
        }
        assert(ok, 'servidor não subiu');
        const r = await fetch(base + '/app.js');
        assert(r.status === 200, '/app.js status ' + r.status);
        assert(/^(text|application)\/javascript/.test(r.headers.get('content-type') || ''), 'content-type: ' + r.headers.get('content-type'));
        assert(r.headers.get('cache-control') === 'no-store', '/app.js cache-control: ' + r.headers.get('cache-control'));
        const v = await fetch(base + '/vendor/chart.umd.js');
        assert(v.headers.get('cache-control') === 'public, max-age=86400', 'vendor cache-control: ' + v.headers.get('cache-control'));
        const h = await fetch(base + '/');
        assert(h.headers.get('cache-control') === 'no-store', 'index cache-control: ' + h.headers.get('cache-control'));
    } finally {
        srv.kill('SIGTERM');
        await new Promise((r) => srv.once('exit', r));
        fs.rmSync(dataDir, { recursive: true, force: true });
    }
});

await test('7. servidor: caminho que escapa para pasta vizinha "app…" é recusado (403)', async () => {
    // pasta irmã cujo nome começa com "app": a checagem antiga por startswith("…/app") deixava passar
    const irma = path.join(PROJ, 'app_teste_irma');
    fs.mkdirSync(irma, { recursive: true });
    fs.writeFileSync(path.join(irma, 'segredo.txt'), 'nao deveria sair');
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bpa_jsext_'));
    const porta = PORT - 1;
    const srv = spawn('python3', ['run.py', '--sem-navegador', '--porta', String(porta), '--data', dataDir], { cwd: PROJ, stdio: 'ignore' });
    // http.request envia o caminho como está (fetch normalizaria o "..")
    const cru = (p) => new Promise((res, rej) => {
        http.get({ host: '127.0.0.1', port: porta, path: p }, (r) => { r.resume(); res(r.statusCode); }).on('error', rej);
    });
    try {
        let ok = false;
        for (let i = 0; i < 50 && !ok; i++) {
            try { ok = (await fetch('http://127.0.0.1:' + porta + '/api/health')).ok; } catch { await new Promise((r) => setTimeout(r, 200)); }
        }
        assert(ok, 'servidor não subiu');
        const st = await cru('/../app_teste_irma/segredo.txt');
        assert(st === 403, 'pasta vizinha deveria dar 403, deu ' + st);
        assert(await cru('/../run.py') === 403, 'arquivo fora de app/ deveria dar 403');
        assert(await cru('/app.js') === 200, 'app.js deveria continuar 200');
        assert(await cru('/vendor/chart.umd.js') === 200, 'vendor deveria continuar 200');
    } finally {
        srv.kill('SIGTERM');
        await new Promise((r) => srv.once('exit', r));
        fs.rmSync(dataDir, { recursive: true, force: true });
        fs.rmSync(irma, { recursive: true, force: true });
    }
});

console.log(`\nResultado: ${passed} aprovados, ${failed} reprovados.`);
process.exit(failed ? 1 : 0);
