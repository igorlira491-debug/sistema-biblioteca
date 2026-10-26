// Reabrir a MESMA aba ao reiniciar o servidor — run.py real + SQLite temporário.
//   Ctrl+C com aba ativa ⇒ servidor anota; no próximo start espera a aba antiga
//   reconectar (ela re-sonda a cada 10 s, Bloco 4) antes de abrir outra.
//
// O navegador é falso: BROWSER="echo ABRIU_NAVEGADOR %s" (webbrowser do Python
// respeita a variável), então nada abre na tela — só aparece no stdout.
//
// Uso: node tests/test_reabrir_aba.mjs   (~25 s: um cenário espera o prazo inteiro)

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const PROJ = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 8798;
const BASE = `http://127.0.0.1:${PORT}`;
const DATA = fs.mkdtempSync('/tmp/bpa_aba_');
const MARCA = path.join(DATA, '.aba_aberta');

function spawnServer() {
    const p = spawn('python3', ['run.py', '--porta', String(PORT), '--data', DATA], {
        cwd: PROJ, stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, BROWSER: 'echo ABRIU_NAVEGADOR %s', PYTHONUNBUFFERED: '1' },
    });
    p.out = '';
    p.stdout.on('data', (d) => { p.out += d; });
    p.stderr.on('data', (d) => process.stderr.write('[servidor] ' + d));
    return p;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond, timeoutMs) {
    const t0 = Date.now();
    while (Date.now() - t0 < timeoutMs) { if (await cond()) return Date.now() - t0; await sleep(100); }
    return -1;
}
const up = async () => { try { return (await fetch(`${BASE}/api/health`)).ok; } catch (_) { return false; } };
const tabPing = () => fetch(`${BASE}/api/kv/bpa_ping`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ value: new Date().toISOString() }),
});
async function stop(p) {
    p.kill('SIGINT');
    await new Promise((r) => p.once('exit', r));
}
const opened = (p) => p.out.includes('ABRIU_NAVEGADOR');

let passed = 0, failed = 0;
async function test(name, fn) {
    try { await fn(); console.log(`  ✔ ${name}`); passed++; }
    catch (e) { console.log(`  ✘ ${name}\n    -> ${e.message}`); failed++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

console.log('Testes de REABRIR A MESMA ABA (run.py)\n');

let srv = null;
try {
    await test('1. Sem aba anterior: abre o navegador na hora', async () => {
        srv = spawnServer();
        assert(await waitFor(up, 8000) >= 0, 'servidor não subiu');
        assert(await waitFor(() => opened(srv), 3000) >= 0, 'deveria abrir o navegador logo: ' + srv.out);
        await stop(srv);   // nenhuma requisição /api/kv ⇒ nenhuma aba ativa anotada
    });

    await test('2. Ctrl+C sem aba ativa ⇒ próximo start abre na hora (não espera)', async () => {
        srv = spawnServer();
        assert(await waitFor(up, 8000) >= 0, 'servidor não subiu');
        assert(await waitFor(() => opened(srv), 3000) >= 0, 'deveria abrir sem esperar: ' + srv.out);
    });

    await test('3. Aba ativa no Ctrl+C + aba reconecta ⇒ NÃO abre outra', async () => {
        await tabPing();            // a aba (simulada) está viva
        await stop(srv);
        srv = spawnServer();
        assert(await waitFor(up, 8000) >= 0, 'servidor não subiu');
        await sleep(1000);
        await tabPing();            // a aba antiga re-sondou e reconectou
        assert(await waitFor(() => /reconectou/.test(srv.out), 3000) >= 0, 'deveria avisar que a aba reconectou: ' + srv.out);
        await sleep(500);
        assert(!opened(srv), 'NÃO deveria abrir outra aba: ' + srv.out);
    });

    await test('4. Aba sumiu ⇒ abre após o prazo (~15 s); pedido inválido não conta como aba; marca de uso único', async () => {
        await tabPing();
        await stop(srv);
        assert(fs.readFileSync(MARCA, 'utf8') === String(PORT), 'marca deveria guardar a porta');
        srv = spawnServer();
        assert(await waitFor(up, 8000) >= 0, 'servidor não subiu');
        assert(!fs.existsSync(MARCA), 'marca deveria ser consumida no start');
        await fetch(`${BASE}/api/kvx`);                 // 404 — rota que só começa com /api/kv
        await fetch(`${BASE}/api/kv/chave-invalida!`);  // 400 — chave recusada
        const t = await waitFor(() => opened(srv), 20000);
        assert(t >= 13000, 'pedidos inválidos não podem contar como aba reconectando (abriu em ' + t + ' ms)');
    });

    await test('5. Marca de OUTRA porta (servidor subiu em porta diferente) ⇒ não espera, abre na hora', async () => {
        await stop(srv);
        fs.writeFileSync(MARCA, String(PORT + 1));
        srv = spawnServer();
        assert(await waitFor(up, 8000) >= 0, 'servidor não subiu');
        assert(await waitFor(() => opened(srv), 3000) >= 0, 'aba antiga não acha outra porta — deveria abrir logo: ' + srv.out);
    });

    await test('6. Intervalo da sonda da aba (app.js) cabe na espera do run.py', () => {
        const html = fs.readFileSync(path.join(PROJ, 'app/app.js'), 'utf8');
        const runpy = fs.readFileSync(path.join(PROJ, 'run.py'), 'utf8');
        const probe = Number((html.match(/DB_PROBE_MS: (\d+) \* 1000/) || [])[1]);
        const espera = Number((runpy.match(/^ESPERA_ABA_S = (\d+)/m) || [])[1]);
        assert(probe > 0 && espera > 0, 'constantes não encontradas');
        assert(probe + 3 <= espera, `sonda da aba (${probe} s) + folga deveria caber na espera (${espera} s)`);
    });
} finally {
    if (srv && srv.exitCode === null) await stop(srv);
    fs.rmSync(DATA, { recursive: true, force: true });
}

console.log(`\nResultado: ${passed} aprovados, ${failed} reprovados.`);
process.exit(failed ? 1 : 0);
