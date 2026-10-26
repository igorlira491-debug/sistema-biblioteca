// Backup diário automático (Bloco 6) — run.py real + SQLite em pastas temporárias.
//   Cada cenário usa sua própria pasta de dados (sem estado compartilhado entre testes).
//   Funções de server/backup.py são testadas direto via `python3 -I -c`.
//
// Uso: node tests/test_backup.mjs   (~30 s)

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';

const PROJ = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 8797;
const BASE = `http://127.0.0.1:${PORT}`;
const HOJE = new Date().toLocaleDateString('en-CA');   // AAAA-MM-DD local
const tmpDirs = [];
const newData = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'bpa_b6_')); tmpDirs.push(d); return d; };
const bdir = (d) => path.join(d, 'backups');

function spawnServer(data, env = {}) {
    const p = spawn('python3', ['run.py', '--sem-navegador', '--porta', String(PORT), '--data', data], {
        cwd: PROJ, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, PYTHONUNBUFFERED: '1', ...env },
    });
    p.out = '';
    p.stdout.on('data', (d) => { p.out += d; });
    p.stderr.on('data', (d) => { p.out += d; });
    return p;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond, timeoutMs) {
    const t0 = Date.now();
    while (Date.now() - t0 < timeoutMs) { if (await cond()) return true; await sleep(100); }
    return false;
}
const up = async () => { try { return (await fetch(`${BASE}/api/health`)).ok; } catch (_) { return false; } };
async function start(data, env) {
    const p = spawnServer(data, env);
    if (!(await waitFor(up, 8000))) throw new Error('servidor não subiu: ' + p.out);
    return p;
}
async function stop(p) {
    if (p.exitCode !== null) return p.exitCode;
    p.kill('SIGINT');
    return await new Promise((r) => p.once('exit', (code) => r(code)));
}
const put = (key, value) => fetch(`${BASE}/api/kv/${key}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ value }),
});

// Python: helpers do projeto + leitura de arquivos SQLite
function py(code) {
    const r = spawnSync('python3', ['-I', '-c', `import sys, sqlite3; sys.path.insert(0, ${JSON.stringify(PROJ)})\n${code}`], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error('python falhou: ' + r.stderr);
    return r.stdout.trim();
}
const integrity = (f) => py(`print(sqlite3.connect(${JSON.stringify(f)}).execute('PRAGMA integrity_check').fetchone()[0])`);
const kvValue = (f, key) => py(`r = sqlite3.connect(${JSON.stringify(f)}).execute('SELECT value FROM kv WHERE key=?', (${JSON.stringify(key)},)).fetchone(); print(r[0] if r else '<nada>')`);
function makeDb(f, pairs) {
    py(`c = sqlite3.connect(${JSON.stringify(f)}); c.execute('CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
for k, v in ${JSON.stringify(Object.entries(pairs))}: c.execute('INSERT INTO kv VALUES (?, ?)', (k, v))
c.commit(); c.close()`);
}
const backups = (d) => fs.existsSync(bdir(d)) ? fs.readdirSync(bdir(d)).filter((f) => /^backup_\d{4}-\d{2}-\d{2}\.db$/.test(f)).sort() : [];
const hojeFile = (d) => path.join(bdir(d), `backup_${HOJE}.db`);
function restore(data, file, comPorta = true) {
    const args = ['run.py', '--restaurar', file, '--data', data].concat(comPorta ? ['--porta', String(PORT)] : []);
    return spawnSync('python3', args, { cwd: PROJ, encoding: 'utf8' });
}
// Pedido com cabeçalhos livres (Origin/Host), como um navegador faria
function rawReq(method, pathname, headers = {}) {
    return new Promise((resolve, reject) => {
        const r = http.request({ host: '127.0.0.1', port: PORT, method, path: pathname, headers }, (res) => {
            let b = ''; res.on('data', (c) => (b += c)); res.on('end', () => resolve({ status: res.statusCode, body: b }));
        });
        r.on('error', reject);
        r.end(method === 'PUT' || method === 'POST' ? '{"value":"x","put":{"teste_b6":"invasor"}}' : undefined);
    });
}
function fakeXdgOpen(script) {
    const bin = newData();
    fs.writeFileSync(path.join(bin, 'xdg-open'), script, { mode: 0o755 });
    return bin;
}

let passed = 0, failed = 0;
async function test(name, fn) {
    const srvs = [];   // todo servidor ligado no teste é desligado no fim, mesmo se o teste falhar
    const track = (p) => (srvs.push(p), p);
    try { await fn(track); console.log(`  ✔ ${name}`); passed++; }
    catch (e) { console.log(`  ✘ ${name}\n    -> ${e.message}`); failed++; }
    finally { for (const p of srvs) await stop(p); }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

console.log('Testes do BACKUP DIÁRIO AUTOMÁTICO (Bloco 6)\n');
if (await up()) { console.error(`Porta ${PORT} ocupada por outro servidor — feche-o antes de rodar.`); process.exit(2); }

try {
    await test('1. Start gera o backup de hoje: SQLite íntegro com a tabela kv; status coerente', async (track) => {
        const d = newData();
        track(await start(d));
        assert(await waitFor(() => fs.existsSync(hojeFile(d)), 3000), 'backup de hoje não foi criado');
        assert(integrity(hojeFile(d)) === 'ok', 'backup deveria passar no integrity_check');
        assert(py(`print(sqlite3.connect(${JSON.stringify(hojeFile(d))}).execute("SELECT count(*) FROM sqlite_master WHERE name='kv'").fetchone()[0])`) === '1', 'backup sem tabela kv');
        const st = await (await fetch(`${BASE}/api/backup/status`)).json();
        assert(st.total >= 1 && st.arquivo === `backup_${HOJE}.db` && st.erro === null && st.ultimo, 'status inesperado: ' + JSON.stringify(st));
    });

    await test('2. Ctrl+C regrava o backup de hoje com o estado do fim do dia', async (track) => {
        const d = newData();
        const srv = track(await start(d));
        await waitFor(() => fs.existsSync(hojeFile(d)), 3000);
        await put('teste_b6', 'fim-do-dia');
        assert(await stop(srv) === 0, 'Ctrl+C deveria sair com 0');
        assert(kvValue(hojeFile(d), 'teste_b6') === 'fim-do-dia', 'backup do desligamento sem o dado do fim do dia');
    });

    await test('3. Guarda só 30 backups; antes_restaurar_* e arquivos alheios ficam intactos', async (track) => {
        const d = newData();
        fs.mkdirSync(bdir(d));
        for (let i = 0; i < 35; i++) {
            const dia = new Date(Date.UTC(2020, 0, 1 + i)).toISOString().slice(0, 10);
            makeDb(path.join(bdir(d), `backup_${dia}.db`), { x: String(i) });
        }
        makeDb(path.join(bdir(d), 'antes_restaurar_2020-01-01_000000.db'), { x: 'seguranca' });
        fs.writeFileSync(path.join(bdir(d), 'notas.txt'), 'do operador');
        track(await start(d));
        assert(await waitFor(() => backups(d).length === 30, 3000), 'esperado 30 backups, há ' + backups(d).length);
        assert(backups(d).includes(`backup_${HOJE}.db`), 'o de hoje deveria estar entre os 30');
        assert(!backups(d).includes('backup_2020-01-06.db') && backups(d).includes('backup_2020-01-07.db'), 'deveriam sumir os 6 mais antigos: ' + backups(d).slice(0, 3));
        assert(fs.existsSync(path.join(bdir(d), 'antes_restaurar_2020-01-01_000000.db')), 'antes_restaurar_* não pode ser apagado');
        assert(fs.existsSync(path.join(bdir(d), 'notas.txt')), 'arquivo alheio não pode ser apagado');
    });

    await test('4. Sobra .tmp de backup cortado por queda de energia é limpa; backup final válido', async (track) => {
        const d = newData();
        fs.mkdirSync(bdir(d));
        const tmp = path.join(bdir(d), `.backup_${HOJE}.db.tmp`);
        for (const suf of ['', '-wal', '-shm', '-journal']) fs.writeFileSync(tmp + suf, 'lixo de um backup pela metade');
        track(await start(d));
        assert(await waitFor(() => fs.existsSync(hojeFile(d)), 3000), 'backup de hoje não foi criado');
        const sobras = fs.readdirSync(bdir(d)).filter((f) => f.startsWith('.'));
        assert(sobras.length === 0, 'sobras do .tmp (inclusive -wal/-shm/-journal) deveriam ser limpas: ' + sobras);
        assert(integrity(hojeFile(d)) === 'ok', 'backup final deveria ser válido');
    });

    await test('5. ensure_today: cria o do dia pedido uma vez só (2ª chamada não regrava)', () => {
        const d = newData();
        const out = py(`from pathlib import Path; from datetime import date; import os
from server.db import Database; from server import backup
db = Database(Path(${JSON.stringify(d)}) / 'biblioteca.db')
p1 = backup.ensure_today(db, Path(${JSON.stringify(d)}), date(2030, 1, 1)); m1 = os.stat(p1).st_mtime_ns
p2 = backup.ensure_today(db, Path(${JSON.stringify(d)}), date(2030, 1, 1)); m2 = os.stat(p1).st_mtime_ns
db.close(); print(p1.name, p2, m1 == m2)`);
        assert(out === 'backup_2030-01-01.db None True', 'inesperado: ' + out);
    });

    await test('5b. Relógio errado: a limpeza nunca apaga o backup recém-feito; "último" = o gravado por último', () => {
        const d = newData();
        fs.mkdirSync(bdir(d));
        for (let i = 1; i <= 30; i++) makeDb(path.join(bdir(d), `backup_2099-01-${String(i).padStart(2, '0')}.db`), { x: String(i) });
        const out = py(`from pathlib import Path; from datetime import date
from server.db import Database; from server import backup
d = Path(${JSON.stringify(d)}); db = Database(d / 'biblioteca.db')
backup.make_backup(db, d, date(2000, 1, 1)); backup.prune(d, today=date(2000, 1, 1)); db.close()
print((d / 'backups' / 'backup_2000-01-01.db').exists(), backup.status(d)['arquivo'])`);
        assert(out === 'True backup_2000-01-01.db', 'inesperado: ' + out);
    });

    await test('6a. --restaurar com o sistema aberto ⇒ recusa sem tocar no banco', async (track) => {
        const d = newData();
        track(await start(d));
        await put('teste_b6', 'atual');
        await waitFor(() => fs.existsSync(hojeFile(d)), 3000);
        const r = restore(d, hojeFile(d));
        assert(r.status !== 0 && /Feche o sistema/.test(r.stdout + r.stderr), 'deveria recusar: ' + r.stdout + r.stderr);
        assert(!fs.readdirSync(bdir(d)).some((f) => f.startsWith('antes_restaurar_')), 'não deveria criar cópia de segurança');
        assert((await (await fetch(`${BASE}/api/kv/teste_b6`)).json()).value === 'atual', 'banco não pode mudar');
    });

    await test('6b. --restaurar com o sistema fechado ⇒ restaura e guarda o banco atual antes', async (track) => {
        const d = newData();
        let srv = track(await start(d));
        await put('bpa_system', '{}'); await put('teste_b6', 'antes');
        await stop(srv);
        const src = path.join(d, 'copia_antes.db');
        fs.copyFileSync(hojeFile(d), src);
        srv = track(await start(d));
        await put('teste_b6', 'depois');
        await stop(srv);
        const r = restore(d, src);
        assert(r.status === 0, 'restauração deveria funcionar: ' + r.stdout + r.stderr);
        assert(kvValue(path.join(d, 'biblioteca.db'), 'teste_b6') === 'antes', 'banco deveria ter o conteúdo do backup');
        const seg = fs.readdirSync(bdir(d)).filter((f) => f.startsWith('antes_restaurar_'));
        assert(seg.length === 1 && kvValue(path.join(bdir(d), seg[0]), 'teste_b6') === 'depois', 'cópia de segurança deveria ter o estado anterior');
        track(await start(d));   // sobe de novo sobre o banco restaurado
        assert((await (await fetch(`${BASE}/api/kv/teste_b6`)).json()).value === 'antes', 'servidor deveria ler o banco restaurado');
    });

    await test('6c. --restaurar arquivo de lixo ou SQLite sem bpa_system ⇒ recusa, banco intacto', async (track) => {
        const d = newData();
        const srv = track(await start(d));
        await put('bpa_system', '{}'); await put('teste_b6', 'atual');
        await stop(srv);
        const lixo = path.join(d, 'lixo.db'); fs.writeFileSync(lixo, 'isto não é sqlite');
        const alheio = path.join(d, 'alheio.db'); makeDb(alheio, { outra: 'coisa' });
        for (const f of [lixo, alheio]) {
            const r = restore(d, f);
            assert(r.status !== 0 && /não é um backup válido/.test(r.stdout + r.stderr), `deveria recusar ${path.basename(f)}: ` + r.stdout + r.stderr);
        }
        assert(kvValue(path.join(d, 'biblioteca.db'), 'teste_b6') === 'atual', 'banco não pode mudar');
        assert(!fs.readdirSync(bdir(d)).some((f) => f.startsWith('antes_restaurar_')), 'recusa não deveria criar cópia de segurança');
    });

    await test('6d. --restaurar sem --porta detecta o sistema aberto em porta fora da faixa padrão', async (track) => {
        const d = newData();
        track(await start(d));   // PORT do teste (8797) está fora de 8765..8779
        await waitFor(() => fs.existsSync(hojeFile(d)), 3000);
        const r = restore(d, hojeFile(d), false);
        assert(r.status !== 0 && /Feche o sistema/.test(r.stdout + r.stderr), 'deveria recusar: ' + r.stdout + r.stderr);
    });

    await test('6e. Falha inesperada ao restaurar (pasta de backups sem escrita) ⇒ [erro] legível, sem traceback, banco intacto', async (track) => {
        const d = newData();
        const srv = track(await start(d));
        await put('bpa_system', '{}'); await put('teste_b6', 'atual');
        await stop(srv);
        const src = path.join(d, 'copia.db'); fs.copyFileSync(hojeFile(d), src);
        fs.chmodSync(bdir(d), 0o555);
        try {
            const r = restore(d, src);
            assert(r.status !== 0 && /\[erro\]/.test(r.stderr) && !/Traceback/.test(r.stderr), 'esperado [erro] sem traceback: ' + r.stderr);
        } finally { fs.chmodSync(bdir(d), 0o755); }
        assert(kvValue(path.join(d, 'biblioteca.db'), 'teste_b6') === 'atual', 'banco não pode mudar');
    });

    await test('7. Pasta de backups sem permissão ⇒ servidor no ar, status com erro, Ctrl+C fecha o banco certo', async (track) => {
        const d = newData();
        fs.mkdirSync(bdir(d)); fs.chmodSync(bdir(d), 0o555);
        try {
            const srv = track(await start(d));
            await waitFor(async () => (await (await fetch(`${BASE}/api/backup/status`)).json()).erro, 3000);
            const res = await fetch(`${BASE}/api/backup/status`);
            const st = await res.json();
            assert(res.status === 200 && st.erro, 'status deveria ser 200 com erro: ' + res.status + ' ' + JSON.stringify(st));
            assert(await stop(srv) === 0, 'Ctrl+C deveria sair com 0 mesmo com o backup falhando: ' + srv.out);
            assert(integrity(path.join(d, 'biblioteca.db')) === 'ok', 'banco principal deveria fechar íntegro');
        } finally { fs.chmodSync(bdir(d), 0o755); }
    });

    await test('8. "Abrir pasta de backups" chama xdg-open com a pasta certa', async (track) => {
        const d = newData();
        const bin = newData();
        const marca = path.join(bin, 'chamado.txt');
        fs.writeFileSync(path.join(bin, 'xdg-open'), `#!/bin/sh\necho "$1" > ${JSON.stringify(marca)}\n`, { mode: 0o755 });
        track(await start(d, { PATH: bin + ':' + process.env.PATH }));
        const r = await (await fetch(`${BASE}/api/backup/abrir-pasta`, { method: 'POST' })).json();
        assert(r.ok === true, 'resposta inesperada: ' + JSON.stringify(r));
        assert(await waitFor(() => fs.existsSync(marca), 2000), 'xdg-open não foi chamado');
        assert(fs.readFileSync(marca, 'utf8').trim() === bdir(d), 'pasta errada: ' + fs.readFileSync(marca, 'utf8'));
    });

    await test('8b. xdg-open falhou (sem ambiente gráfico) ⇒ resposta ok:false com erro, não "aberta"', async (track) => {
        const d = newData();
        const bin = fakeXdgOpen('#!/bin/sh\nexit 3\n');
        track(await start(d, { PATH: bin + ':' + process.env.PATH }));
        const r = await (await fetch(`${BASE}/api/backup/abrir-pasta`, { method: 'POST' })).json();
        assert(r.ok === false && r.erro, 'deveria reportar a falha: ' + JSON.stringify(r));
    });

    await test('8c. Página de OUTRO site (Origin/Host estranhos) é recusada; a própria página passa', async (track) => {
        const d = newData();
        const bin = newData(); const marca = path.join(bin, 'chamado.txt');
        fs.writeFileSync(path.join(bin, 'xdg-open'), `#!/bin/sh\necho "$1" > ${JSON.stringify(marca)}\n`, { mode: 0o755 });
        track(await start(d, { PATH: bin + ':' + process.env.PATH }));
        await put('teste_b6', 'original');
        const host = `127.0.0.1:${PORT}`;
        for (const [m, pth] of [['POST', '/api/backup/abrir-pasta'], ['PUT', '/api/kv/teste_b6'], ['POST', '/api/kv/batch'], ['DELETE', '/api/kv/teste_b6']]) {
            const r = await rawReq(m, pth, { Host: host, Origin: 'http://site-malicioso.com', 'Content-Type': 'text/plain' });
            assert(r.status === 403, `${m} ${pth} de outra origem deveria dar 403, deu ${r.status}`);
        }
        const rebind = await rawReq('GET', '/api/kv/teste_b6', { Host: `site-malicioso.com:${PORT}` });
        assert(rebind.status === 403, 'Host estranho (DNS rebinding) deveria dar 403, deu ' + rebind.status);
        assert(!fs.existsSync(marca), 'xdg-open não pode ter sido chamado');
        assert((await (await fetch(`${BASE}/api/kv/teste_b6`)).json()).value === 'original', 'dado não pode ter mudado');
        const ok = await rawReq('PUT', '/api/kv/teste_b6', { Host: host, Origin: `http://${host}`, 'Content-Type': 'application/json' });
        assert(ok.status === 200, 'a própria página (mesma origem) deveria passar, deu ' + ok.status);
    });

    await test('9. Laço periódico: backup de hoje some com o servidor no ar ⇒ volta sozinho', async (track) => {
        const d = newData();
        track(await start(d, { BPA_BACKUP_INTERVALO_S: '1' }));
        assert(await waitFor(() => fs.existsSync(hojeFile(d)), 3000), 'backup de hoje não foi criado');
        fs.unlinkSync(hojeFile(d));   // simula a virada do dia: não há backup do "novo" dia
        assert(await waitFor(() => fs.existsSync(hojeFile(d)), 3000), 'laço deveria recriar o backup do dia');
    });
} finally {
    for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true });
}

console.log(`\nResultado: ${passed} aprovados, ${failed} reprovados.`);
process.exit(failed ? 1 : 0);
