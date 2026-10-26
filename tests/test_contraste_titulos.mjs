// Testes de contraste de títulos (modo claro/escuro) — 03.sistema_biblioteca.html
// Uso: node test_contraste_titulos.mjs /caminho/para/03.sistema_biblioteca.html
// Lê o CSS real do arquivo, resolve var() nos dois temas e calcula o
// contraste WCAG 2.2 entre cada título e o fundo do seu componente.

import fs from 'node:fs';
import path from 'node:path';

const htmlPath = process.argv[2];
if (!htmlPath) { console.error('Informe o caminho do HTML.'); process.exit(2); }
const html = fs.readFileSync(htmlPath, 'utf8');
const css = html.match(/<style>([\s\S]*?)<\/style>/)?.[1];
if (!css) { console.error('Bloco <style> não encontrado.'); process.exit(2); }

// ---------- helpers ----------
let passed = 0, failed = 0;
function test(name, fn) {
    try { fn(); console.log(`  ✔ ${name}`); passed++; }
    catch (e) { console.log(`  ✘ ${name}\n    -> ${e.message}`); failed++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

// Extrai o conteúdo do bloco de um seletor (primeira ocorrência)
function ruleBody(selector) {
    const re = new RegExp(selector.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&') + '\\s*\\{([^}]*)\\}', 'm');
    const m = css.match(re);
    return m ? m[1] : null;
}

// Extrai custom properties de um bloco
function customProps(block) {
    const props = {};
    for (const m of block.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/gi)) props[m[1]] = m[2].trim();
    return props;
}

const rootProps = customProps(ruleBody(':root') || '');
const darkBlock = ruleBody('body.dark-mode') || '';
const darkProps = { ...rootProps, ...customProps(darkBlock) }; // dark-mode sobrescreve

function resolve(theme, value) {
    let v = value.trim();
    const m = v.match(/^var\((--[a-z0-9-]+)\)$/i);
    if (m) v = (theme === 'dark' ? darkProps : rootProps)[m[1]];
    return v;
}

function hexToRgb(hex) {
    let h = hex.trim().replace('#', '');
    if (h.length === 3) h = h.split('').map(c => c + c).join('');
    const n = parseInt(h, 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function luminance(hex) {
    const [r, g, b] = hexToRgb(hex).map(c => {
        const s = c / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(fg, bg) {
    const l1 = luminance(fg), l2 = luminance(bg);
    return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}

function propOf(theme, name) { return (theme === 'dark' ? darkProps : rootProps)[name]; }

console.log('Testes de CONTRASTE DE TÍTULOS (claro/escuro)\n');

// ---------- variáveis de tema ----------
test('CSS define --heading-color nos dois temas (#111 claro / #fff escuro)', () => {
    assert(rootProps['--heading-color'], 'sem --heading-color em :root');
    assert(darkProps['--heading-color'], 'sem --heading-color em body.dark-mode');
    assert(resolve('light', 'var(--heading-color)') === '#111', 'claro deveria ser #111, veio ' + resolve('light', 'var(--heading-color)'));
    assert(resolve('dark', 'var(--heading-color)') === '#fff', 'escuro deveria ser #fff, veio ' + resolve('dark', 'var(--heading-color)'));
    // mecanismo de tema original preservado
    assert(rootProps['--primary-color'] && darkProps['--primary-color'], 'mecanismo de tema original alterado');
});

// ---------- regras usam a variável ----------
const headingRules = [
    ['.section-title', 'títulos dos cartões (Registrar Entrada, Computadores, Sessões, etc.)'],
    ['th', 'cabeçalhos de tabelas'],
    ['.tutorial-step h3', 'títulos do manual'],
    ['.chart-header h3', 'títulos dos gráficos'],
    ['.modal-box h3', 'títulos de janelas modais'],
];
for (const [sel, desc] of headingRules) {
    test(`Regra ${sel} usa var(--heading-color) — ${desc}`, () => {
        const body = ruleBody(sel);
        assert(body !== null, `regra ${sel} não encontrada`);
        assert(/color\s*:\s*var\(--heading-color\)/.test(body), `${sel} sem color: var(--heading-color)`);
    });
}

test('Sem remendo específico do pc-panel nem títulos legados em var(--primary-color)', () => {
    assert(!/dark-mode\s+\.pc-panel\s+\.section-title/.test(css), 'regra específica pc-panel ainda existe');
    const titles = ['.section-title', '.tutorial-step h3', 'th', '.chart-header h3', '.modal-box h3'];
    for (const sel of titles) {
        const body = ruleBody(sel) || '';
        assert(!/color\s*:\s*var\(--primary-color\)/.test(body), `${sel} ainda usa --primary-color`);
    }
});

// ---------- contraste WCAG por componente/tema ----------
// [seletor, fundo resolvido por tema, nome]
const pairs = [
    ['.section-title', { light: '--card-bg', dark: '--card-bg' }, 'títulos dos cartões'],
    ['th', { light: '--bg-color', dark: '--bg-color' }, 'cabeçalhos de tabelas'],
    ['.tutorial-step h3', { light: '--bg-color', dark: null }, 'títulos do manual'],
    ['.chart-header h3', { light: '--card-bg', dark: '--card-bg' }, 'títulos dos gráficos'],
    ['.modal-box h3', { light: '--card-bg', dark: '--card-bg' }, 'títulos dos modais'],
];
// tutorial-step escuro usa #2a2a2a fixo no CSS
const tutorialDark = (ruleBody('body.dark-mode .tutorial-step') || '').match(/background-color\s*:\s*(#[0-9a-f]{3,6})/i)?.[1];

for (const theme of ['light', 'dark']) {
    for (const [sel, bgMap, desc] of pairs) {
        const rule = ruleBody(sel) || '';
        const colorDecl = rule.match(/(?:^|[;\s}])color\s*:\s*([^;]+);/)?.[1];
        assert(colorDecl, `${sel} sem declaração de cor`);
        const fg = resolve(theme, colorDecl);
        let bg;
        if (bgMap[theme] === null) bg = tutorialDark;
        else bg = propOf(theme, bgMap[theme]);
        const ratio = contrast(fg, bg);
        test(`Contraste ${theme === 'light' ? 'CLARO' : 'ESCURO'} — ${desc}: ${fg} sobre ${bg} = ${ratio.toFixed(2)}:1 (mín. 4,5:1)`, () => {
            assert(ratio >= 4.5, `abaixo do mínimo WCAG: ${ratio.toFixed(2)}:1`);
        });
    }
}

// ---------- preservação de componentes com fundo próprio ----------
test('Componentes com fundo próprio preservados (logo/cabeçalho, avisos, status, relógio)', () => {
    const header = ruleBody('header') || '';
    assert(/color\s*:\s*white/.test(header), 'header com cor própria alterado');
    const noteCard = ruleBody('.note-card') || '';
    assert(/color\s*:\s*#333/.test(noteCard), 'note-card cor alterada');
    const darkNote = ruleBody('body.dark-mode .note-card') || '';
    assert(/color\s*:\s*#eee/.test(darkNote), 'note-card dark cor alterada');
    const banner = ruleBody('.urgent-banner') || '';
    assert(/color\s*:\s*#333/.test(banner), 'urgent-banner cor alterada');
    const badge = css.match(/\.status-suspenso[^{]*\{([^}]*)\}/)?.[1] || '';
    assert(/color\s*:\s*#333/.test(badge), 'status-suspenso cor alterada');
    // nenhum seletor genérico globalizando preto/branco em todos os títulos
    assert(!/^(?:\s*)h1\s*,\s*h2\s*,\s*h3\s*\{/m.test(css.replace(/\/\*[\s\S]*?\*\//g, '')), 'seletor global h1,h2,h3 adicionado');
    // branco sobre fundo do cabeçalho (primary escuro) mantém contraste
    const ratioHeader = contrast('#fff', propOf('light', '--primary-color'));
    assert(ratioHeader >= 3, 'contraste do h1 do header caiu: ' + ratioHeader.toFixed(2));
});

// ---------- comportamento do tema (JS) ----------
test('JS de alternância de tema intacto (toggle da classe dark-mode, sem recarregar)', () => {
    const js = fs.readFileSync(path.join(path.dirname(htmlPath), 'app.js'), 'utf8');   // Bloco 5: JS em app.js
    assert(/classList\.toggle\('dark-mode', isDark\)/.test(js), 'toggleTheme alterado');
    assert(/classList\.add\('dark-mode'\)/.test(js), 'initTheme alterado');
    assert(/localStorage\.setItem\('bpa_theme'/.test(js), 'persistência de tema alterada');
    // variáveis CSS herdam a classe no body — atualização imediata, sem reload
    assert(/body\.dark-mode\s*\{/.test(css), 'bloco body.dark-mode ausente');
});

console.log(`\nResultado: ${passed} aprovados, ${failed} reprovados.`);
process.exit(failed > 0 ? 1 : 0);
