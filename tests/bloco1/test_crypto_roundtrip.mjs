// Teste Bloco 1 — roundtrip de criptografia (C1/C2)
// Lê o JS extraído de 03.sistema_biblioteca.html e executa as funções REAIS
// (CONFIG + crypto-core) — nenhuma função criptográfica é reimplementada aqui.
// O fluxo de "instalação/troca de senha/recuperação" espelha exatamente
// createSystem / attemptLogin / handleChangeSystemPassword do sistema.

import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./app_extracted.js', import.meta.url), 'utf8');

function sliceRegion(startMark, endMark) {
    const a = src.indexOf(startMark);
    const b = src.indexOf(endMark);
    if (a === -1 || b === -1) throw new Error('região não encontrada: ' + startMark);
    return src.slice(a, b + endMark.length);
}

const configCode = sliceRegion('const CFG = {', "const SENHA_PADRAO = '123456789';");
const cryptoCode = sliceRegion('// #region crypto-core', '// #endregion crypto-core');

// Avalia o código real do sistema em escopo de função (globals de WebCrypto do Node)
const factory = new Function(`
    ${configCode}
    ${cryptoCode}
    return { CFG, deriveAesKey, generateDek, wrapDek, unwrapDek, encryptJSON, decryptJSON,
             generateRecoveryCode, normalizeRecoveryCode, formatRecoveryCode, randomB64, bytesToB64, b64ToBytes };
`);
const A = factory();

let pass = 0, fail = 0;
function ok(name, cond, extra = '') {
    if (cond) { pass++; console.log('  ✅ ' + name); }
    else { fail++; console.log('  ❌ ' + name + (extra ? ' — ' + extra : '')); }
}
function throws(fn) { return Promise.resolve().then(fn).then(() => false, () => true); }

const PII = { nome: 'Maria da Silva 🇧🇷', nascimento: '1985-03-12', matricula: '2024-0001', categoria: 'Idoso' };

console.log('\n══ Bloco 1 — Teste de roundtrip de criptografia ══\n');

// ── T1: instalação (espelha createSystem) ─────────────────────────────
console.log('T1 — Instalação: DEK + envelope por senha + envelope por código de recuperação');
const installSalt = A.randomB64(A.CFG.SALT_BYTES);
const senha = A.CFG.SENHA_PADRAO; // '123456789'
const dek = await A.generateDek();
const pwSalt = A.randomB64(A.CFG.SALT_BYTES);
const kek = await A.deriveAesKey(senha, pwSalt, A.CFG.PBKDF2_ITER);
const rc = A.generateRecoveryCode();
const rcKek = await A.deriveAesKey(rc, installSalt, A.CFG.PBKDF2_ITER);
const system = {
    password: { salt: pwSalt, iterations: A.CFG.PBKDF2_ITER, envelope: await A.wrapDek(dek, kek) },
    recovery: { envelope: await A.wrapDek(dek, rcKek) },
};
ok('instalação criou os 2 envelopes', !!system.password.envelope?.data && !!system.recovery.envelope?.data);
ok('código de recuperação tem 16 caracteres', rc.length === 16, 'len=' + rc.length);
ok('código usa só alfabeto sem ambíguos (sem I/L/O/0/1)', !/[ILO01]/.test(rc), rc);
ok('PBKDF2 com 250.000 iterações', A.CFG.PBKDF2_ITER >= 200000 && A.CFG.PBKDF2_ITER === 250000);
ok('IV com 12 bytes', A.CFG.IV_BYTES === 12);
ok('salt com 16 bytes', A.CFG.SALT_BYTES === 16);

// ── T2: cifrar dados PII com a DEK ────────────────────────────────────
console.log('\nT2 — Cifragem de PII com a DEK');
const ciphertext = await A.encryptJSON(PII, dek);
ok('ciphertext tem iv + data', typeof ciphertext.iv === 'string' && typeof ciphertext.data === 'string');
const ctStr = JSON.stringify(ciphertext) + JSON.stringify(system);
ok('PII não aparece em claro no ciphertext/envelopes', !ctStr.includes('Maria') && !ctStr.includes('2024-0001'));

// ── T3: login com senha correta (espelha attemptLogin) ────────────────
console.log('\nT3 — Login com senha correta → decifra os dados');
const kekLogin = await A.deriveAesKey(senha, system.password.salt, system.password.iterations);
const dekLogin = await A.unwrapDek(system.password.envelope, kekLogin);
const decrypted = await A.decryptJSON(ciphertext, dekLogin);
ok('dados decifrados idênticos aos originais (PII + emoji)', JSON.stringify(decrypted) === JSON.stringify(PII));

// ── T4: senha ERRADA não destrincha o envelope ────────────────────────
console.log('\nT4 — Senha errada → envelope resiste');
const kekErrada = await A.deriveAesKey('senha-certamente-errada', system.password.salt, system.password.iterations);
ok('unwrapDek lança exceção com senha errada', await throws(() => A.unwrapDek(system.password.envelope, kekErrada)));

// ── T5: recuperação por código (fluxo de emergência) ──────────────────
console.log('\nT5 — Recuperação por código de 16 caracteres');
const rcKek2 = await A.deriveAesKey(A.normalizeRecoveryCode(rc.toLowerCase().replace(/(.{4})/g, '$1 ')), installSalt, A.CFG.PBKDF2_ITER);
const dekRec = await A.unwrapDek(system.recovery.envelope, rcKek2);
const rawOriginal = new Uint8Array(await crypto.subtle.exportKey('raw', dek));
const rawRecuperada = new Uint8Array(await crypto.subtle.exportKey('raw', dekRec));
ok('código recupera a MESMA DEK (byte a byte)', rawOriginal.every((v, i) => v === rawRecuperada[i]));
ok('normalize/format do código são idênticos ao original', A.normalizeRecoveryCode(A.formatRecoveryCode(rc)) === rc);

// ── T6: troca de senha (espelha handleChangeSystemPassword) ───────────
console.log('\nT6 — Troca de senha: só o envelope é re-cifrado, DEK e dados intactos');
const novaSenha = 'Biblioteca#2026';
const novoSalt = A.randomB64(A.CFG.SALT_BYTES);
const novaKek = await A.deriveAesKey(novaSenha, novoSalt, A.CFG.PBKDF2_ITER);
system.password = { salt: novoSalt, iterations: A.CFG.PBKDF2_ITER, envelope: await A.wrapDek(dek, novaKek) };
const kekAntiga = await A.deriveAesKey(senha, pwSalt, A.CFG.PBKDF2_ITER);
ok('senha ANTIGA deixou de abrir o sistema', await throws(() => A.unwrapDek(system.password.envelope, kekAntiga)));
const kekNova = await A.deriveAesKey(novaSenha, system.password.salt, system.password.iterations);
const dekNova = await A.unwrapDek(system.password.envelope, kekNova);
const dadosAposTroca = await A.decryptJSON(ciphertext, dekNova);
ok('senha NOVA abre e os dados continuam legíveis SEM re-cifragem', JSON.stringify(dadosAposTroca) === JSON.stringify(PII));
ok('código de recuperação AINDA funciona após troca de senha', (await A.unwrapDek(system.recovery.envelope, rcKek2)) !== null);

// ── T7: IV aleatório por gravação ─────────────────────────────────────
console.log('\nT7 — IV único por gravação (mesmo dado cifrado 2× → resultados diferentes)');
const c1 = await A.encryptJSON(PII, dek);
const c2 = await A.encryptJSON(PII, dek);
ok('dois ciphertexts do mesmo objeto são distintos', c1.iv !== c2.iv && c1.data !== c2.data);
ok('ambos decifram para o mesmo objeto',
    JSON.stringify(await A.decryptJSON(c1, dek)) === JSON.stringify(await A.decryptJSON(c2, dek)));

// ── T8: ciphertext adulterado não decifra (auth tag do GCM) ───────────
console.log('\nT8 — Bytes adulterados → AES-GCM recusa (integridade)');
const bytes = A.b64ToBytes(c1.data);
bytes[bytes.length - 1] ^= 0xff; // flipa 1 bit no final
const adulterado = { iv: c1.iv, data: A.bytesToB64(bytes) };
ok('decryptJSON lança exceção com ciphertext adulterado', await throws(() => A.decryptJSON(adulterado, dek)));

// ── Resumo ────────────────────────────────────────────────────────────
console.log('\n══ Resultado: ' + pass + ' passaram, ' + fail + ' falharam ══\n');
process.exit(fail ? 1 : 0);
