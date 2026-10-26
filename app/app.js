        /**
         * Sistema de Registro V4 — Biblioteca Pública Municipal
         * Bloco 1 (C1–C5): senha única do sistema, criptografia de PII
         * (envelope DEK/KEK), SRI+CSP, modal seguro, LGPD/auditoria.
         * Persistência via repositório sobre backend local SQLite (seam PERSIST_MODE).
         */

        // #region CONFIG
        const CFG = {
            PBKDF2_ITER: 250000,            // ≥ 200.000 exigido
            IV_BYTES: 12,
            SALT_BYTES: 16,
            SESSION_IDLE_MS: 15 * 60 * 1000,
            MAX_LOGIN_ATTEMPTS: 5,
            LOCKOUT_MS: 15 * 60 * 1000,
            SCHEMA_VERSION: 2,
            LIMITE_USO_MIN: 60,
            RET_SESSIONS_MONTHS: 12,
            RET_AUDIT_MONTHS: 24,
            RET_USER_REVIEW_MONTHS: 24,
            AUDIT_CAP: 20000,
            DB_PROBE_MS: 10 * 1000,         // sonda do banco, online e offline (run.py espera a aba por 15 s)
            DB_PROBE_TIMEOUT_MS: 5 * 1000   // sonda sem resposta = servidor travado
        };
        const LIMITE_USO_MIN = CFG.LIMITE_USO_MIN;
        // Senha fixa interna: o sistema não pede senha (os 3 monitores operam como um só — decisão da empresa, 24/10/2026).
        // Ela só cifra os dados e os arquivos exportados; a tela de senha sobra como fallback de máquina com senha antiga.
        const SENHA_PADRAO = '123456789';
        // #endregion CONFIG

        // #region crypto-core — WebCrypto (testável isoladamente)
        const TE = new TextEncoder();
        const TD = new TextDecoder();

        function bytesToB64(bytes) {
            let s = '';
            const CH = 0x8000;
            for (let i = 0; i < bytes.length; i += CH) {
                s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
            }
            return btoa(s);
        }

        function b64ToBytes(b64) {
            const bin = atob(b64);
            const u = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
            return u;
        }

        function randomBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }
        function randomB64(n) { return bytesToB64(randomBytes(n)); }

        async function deriveAesKey(password, saltB64, iterations) {
            const km = await crypto.subtle.importKey('raw', TE.encode(String(password)), 'PBKDF2', false, ['deriveKey']);
            return crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: b64ToBytes(saltB64), iterations: iterations, hash: 'SHA-256' },
                km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
            );
        }

        async function generateDek() {
            // DEK extraível (precisa ser envelopada por várias KEKs)
            return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        }

        async function wrapDek(dek, kek) {
            const raw = await crypto.subtle.exportKey('raw', dek);
            const iv = randomBytes(CFG.IV_BYTES);
            const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, raw);
            return { iv: bytesToB64(iv), data: bytesToB64(new Uint8Array(ct)) };
        }

        async function unwrapDek(envelope, kek) {
            const pt = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: b64ToBytes(envelope.iv) }, kek, b64ToBytes(envelope.data)
            );
            return crypto.subtle.importKey('raw', pt, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
        }

        async function encryptJSON(obj, key) {
            const iv = randomBytes(CFG.IV_BYTES);
            const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, TE.encode(JSON.stringify(obj)));
            return { iv: bytesToB64(iv), data: bytesToB64(new Uint8Array(ct)) };
        }

        async function decryptJSON(envelope, key) {
            const pt = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: b64ToBytes(envelope.iv) }, key, b64ToBytes(envelope.data)
            );
            return JSON.parse(TD.decode(pt));
        }

        // Alfabeto sem caracteres ambíguos (sem I, L, O, 0, 1) — 31 símbolos
        const RC_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
        function generateRecoveryCode() {
            const r = randomBytes(16);
            let s = '';
            for (let i = 0; i < 16; i++) s += RC_ALPHABET[r[i] % RC_ALPHABET.length];
            return s;
        }
        function normalizeRecoveryCode(v) { return String(v || '').toUpperCase().replace(/[^A-Z0-9]/g, ''); }
        function formatRecoveryCode(code) { return (String(code).match(/.{1,4}/g) || []).join(' '); }
        // #endregion crypto-core

        // #region state
        let installMeta = null;      // { schemaVersion, installSalt, iterations, createdAt, lastExportAt, lastArchiveAt, privacyAckAt } — plaintext aceito (salt/metadata)
        let system = null;           // registro da senha única: { password: {salt, iterations, envelope}, recovery: {envelope} }
        let currentDek = null;       // CryptoKey em MEMÓRIA (nunca persistida em claro)
        let authSession = null;      // { unlockedAt, lastActivity } — em MEMÓRIA (sem identidade de operador)
        let userBase = [];
        let sessions = [];
        let notes = [];
        let auditLog = [];
        let loginAttempts = 0;
        let lockUntil = 0;
        let idleTimer = null;
        let charts = {};
        let chartsUnavailable = false;
        let chartsWarned = false;
        // #endregion state

        // #region repositório (pattern Repository — ApiRepo sobre backend local SQLite)
        // Seam de persistência: 'api' = backend Python local (durável sob corte de energia);
        // 'local' = localStorage legado. Reversão de emergência: troque a constante.
        const PERSIST_MODE = 'api';

        // Status do banco (Bloco 4): toda ida à rede passa por apiFetch, que alimenta o banner #db-status.
        let dbOnline = true;
        let dbRetryTimer = null;
        let dbReqSeq = 0, dbAppliedSeq = 0;

        function setDbStatus(ok) {
            if (ok === dbOnline) return;
            dbOnline = ok;
            const banner = document.getElementById('db-status');
            if (banner) banner.hidden = ok;
            if (ok) {
                // Sem system, o bootstrap falhou e a tela está sem dados: só F5 recarrega.
                if (system) showToast('Banco de dados local reconectado.', 'success');
                else showToast('Servidor voltou — recarregue a página (F5).', 'success');
            }
            scheduleServerCheck(); // recomeça a contagem da próxima sonda a partir da mudança
        }

        async function apiFetch(url, opts) {
            const seq = ++dbReqSeq;
            // Só o pedido mais recente decide: resposta atrasada de antes da queda não apaga o banner.
            const apply = function (ok) { if (seq < dbAppliedSeq) return; dbAppliedSeq = seq; setDbStatus(ok); };
            let res;
            try { res = await fetch(url, opts); }
            catch (err) { apply(false); throw err; }
            // 5xx = servidor de pé mas sem gravar (ex.: disco cheio); 4xx é erro do pedido, não queda.
            apply(res.status < 500);
            return res;
        }

        function scheduleServerCheck() {
            if (PERSIST_MODE === 'local') return;
            clearTimeout(dbRetryTimer);
            // Mesmo intervalo online: a aba nota um reinício rápido do servidor a tempo de o run.py reaproveitá-la.
            dbRetryTimer = setTimeout(checkServer, CFG.DB_PROBE_MS);
        }

        // Sonda de GRAVAÇÃO (não /api/health, que não toca o banco): só um PUT aceito prova que
        // o SQLite está gravando. Com timeout, servidor travado também conta como fora.
        async function checkServer() {
            if (PERSIST_MODE === 'local') return;
            try {
                await apiFetch('/api/kv/bpa_ping', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ value: new Date().toISOString() }),
                    signal: AbortSignal.timeout(CFG.DB_PROBE_TIMEOUT_MS)
                });
            } catch (_) { /* estado já registrado em apiFetch */ }
            scheduleServerCheck();
        }

        // Heartbeat + volta à aba: pega queda com a aba parada ou em segundo plano.
        function bindServerWatch() {
            document.addEventListener('visibilitychange', function () {
                if (document.visibilityState === 'visible') return checkServer();
            });
            scheduleServerCheck();
        }

        async function rawGet(key) {
            if (PERSIST_MODE === 'local') return localStorage.getItem(key);
            const res = await apiFetch('/api/kv/' + key);
            if (!res.ok) throw new Error('GET /api/kv/' + key + ' → HTTP ' + res.status);
            const body = await res.json();
            return body.value === null || body.value === undefined ? null : body.value;
        }

        async function rawSet(key, str) {
            if (PERSIST_MODE === 'local') { localStorage.setItem(key, str); return; }
            const res = await apiFetch('/api/kv/' + key, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ value: str })
            });
            if (!res.ok) throw new Error('PUT /api/kv/' + key + ' → HTTP ' + res.status);
        }

        async function rawDel(key) {
            if (PERSIST_MODE === 'local') { localStorage.removeItem(key); return; }
            const res = await apiFetch('/api/kv/' + key, { method: 'DELETE' });
            if (!res.ok) throw new Error('DELETE /api/kv/' + key + ' → HTTP ' + res.status);
        }

        // Lote transacional no backend: ou grava tudo, ou nada (restauração de backup)
        async function rawBatch(putMap, deleteKeys) {
            if (PERSIST_MODE === 'local') {
                Object.keys(putMap).forEach(function (k) { localStorage.setItem(k, putMap[k]); });
                (deleteKeys || []).forEach(function (k) { localStorage.removeItem(k); });
                return;
            }
            const res = await apiFetch('/api/kv/batch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ put: putMap, delete: deleteKeys || [] })
            });
            if (!res.ok) throw new Error('POST /api/kv/batch → HTTP ' + res.status);
        }

        async function persistInstall() { await rawSet('bpa_install', JSON.stringify(installMeta)); }
        async function saveSystem() { await rawSet('bpa_system', JSON.stringify(system)); }

        async function quarantineKey(key, raw) {
            try {
                await rawSet(key + '_corrompido', raw);
                await rawDel(key);
            } catch (_) { /* melhor esforço */ }
        }

        async function repoGet(key, fallback) {
            const raw = await rawGet(key);
            if (raw === null) return fallback;
            let parsed;
            try { parsed = JSON.parse(raw); } catch (_) { await quarantineKey(key, raw); return fallback; }
            if (Array.isArray(parsed)) return parsed; // legado em claro (migra no login)
            if (parsed && typeof parsed === 'object' && parsed.iv && parsed.data) {
                if (!currentDek) return fallback;
                try {
                    return await decryptJSON(parsed, currentDek);
                } catch (_) {
                    await quarantineKey(key, raw);
                    showToast('Dados de "' + key + '" não puderam ser decifrados. Cópia crua salva em "' + key + '_corrompido".', 'error');
                    return fallback;
                }
            }
            await quarantineKey(key, raw);
            return fallback;
        }

        async function repoSet(key, value) {
            if (!currentDek) throw new Error('Sem chave de dados em memória (sessão encerrada?)');
            const envelope = await encryptJSON(value, currentDek);
            await rawSet(key, JSON.stringify(envelope));
        }

        async function persistOrWarn(key, value) {
            try { await repoSet(key, value); return true; }
            catch (err) {
                showToast('Falha ao gravar dados: ' + (err && err.message ? err.message : err) + '. Verifique o servidor no terminal e tente novamente.', 'error');
                return false;
            }
        }

        async function ensureDataLoaded() {
            userBase = (await repoGet('bpa_user_base', [])) || [];
            sessions = (await repoGet('bpa_sessions', [])) || [];
            notes = (await repoGet('bpa_notes_v2', [])) || [];
            auditLog = (await repoGet('bpa_audit_v1', [])) || [];
            if (!Array.isArray(userBase)) userBase = [];
            if (!Array.isArray(sessions)) sessions = [];
            if (!Array.isArray(notes)) notes = [];
            if (!Array.isArray(auditLog)) auditLog = [];
            await migrateLegacyPlaintext();
        }

        // Migração transparente: dados do sistema antigo em texto puro → cifrados com a DEK
        async function migrateLegacyPlaintext() {
            const stores = [['bpa_user_base', userBase], ['bpa_sessions', sessions], ['bpa_notes_v2', notes]];
            for (const [key] of stores) {
                const raw = await rawGet(key);
                if (!raw) continue;
                try {
                    const p = JSON.parse(raw);
                    if (Array.isArray(p)) await repoSet(key, stores.find(s => s[0] === key)[1]);
                } catch (_) { /* já tratado em repoGet */ }
            }
        }
        // #endregion repositório

        // #region auditoria (cifrada com a DEK; formato tabela: id, timestamp, acao, alvo_tipo, alvo_id, resultado, detalhes — sem identidade de operador)
        function auditId() {
            return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
        }

        async function logAudit(acao, alvoTipo, alvoId, resultado, detalhes) {
            if (!currentDek) return;
            auditLog.push({
                id: auditId(),
                timestamp: new Date().toISOString(),
                acao: acao,
                alvo_tipo: String(alvoTipo || ''),
                alvo_id: String(alvoId === undefined || alvoId === null ? '' : alvoId),
                resultado: String(resultado || ''),
                detalhes: String(detalhes || '').slice(0, 300)
            });
            if (auditLog.length > CFG.AUDIT_CAP) auditLog = auditLog.slice(-CFG.AUDIT_CAP);
            try { await repoSet('bpa_audit_v1', auditLog); }
            catch (err) { console.error('Falha ao persistir auditoria:', err); }
        }

        // Falhas de login ficam em log PLAINTEXT limitado (100) — não há DEK antes do login.
        // Vai para o backend via fire-and-forget: assinatura continua síncrona para os
        // chamadores; falha de rede nunca bloqueia nem derruba o login.
        function logAuthFailure(username, reason) {
            (async function () {
                try {
                    const log = JSON.parse((await rawGet('bpa_auth_log')) || '[]');
                    log.push({ at: new Date().toISOString(), username: String(username).slice(0, 40), reason: reason });
                    await rawSet('bpa_auth_log', JSON.stringify(log.slice(-100)));
                } catch (_) { /* melhor esforço */ }
            })();
        }
        // #endregion auditoria
        // #region helpers de UI
        function el(tag, attrs) {
            const node = document.createElement(tag);
            const children = Array.prototype.slice.call(arguments, 2);
            if (attrs) {
                Object.keys(attrs).forEach(function (k) {
                    const v = attrs[k];
                    if (k === 'class') node.className = v;
                    else if (k === 'text') node.textContent = v;
                    else if (k.indexOf('on') === 0 && typeof v === 'function') node.addEventListener(k.slice(2), v);
                    else if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? '' : v);
                });
            }
            children.flat(Infinity).forEach(function (c) {
                if (c === null || c === undefined || c === false) return;
                node.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
            });
            return node;
        }

        function formGroup(labelText, input) {
            const g = el('div', { class: 'form-group' });
            if (input && input.id) g.appendChild(el('label', { for: input.id }, labelText));
            else g.appendChild(el('span', {}, labelText));
            g.appendChild(input);
            return g;
        }

        // SOMENTE para constantes HTML confiáveis (nunca interpolar dados do usuário)
        function staticHTML(html) {
            const d = document.createElement('div');
            d.innerHTML = html;
            return d;
        }

        function escapeHTML(str) {
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        function showToast(message, type) {
            let container = document.getElementById('toast-container');
            if (!container) {
                container = document.createElement('div');
                container.id = 'toast-container';
                document.body.appendChild(container);
            }
            const toast = document.createElement('div');
            toast.className = 'toast toast-' + (type || 'error');
            toast.textContent = message;
            container.appendChild(toast);
            setTimeout(function () { toast.remove(); }, 5000);
        }

        const modalQueue = [];

        function closeModal() {
            const overlay = document.getElementById('modal-overlay');
            if (overlay) overlay.remove();
            if (modalQueue.length) {
                const next = modalQueue.shift();
                openModal(next[0], next[1], next[2], next[3], next[4]);
            }
        }

        // C4: conteúdo NUNCA é HTML cru. Aceita:
        //  - string  → texto puro (textContent)
        //  - Node    → anexado diretamente
        //  - função  → constrói DOM com el()/staticHTML(constante)
        function openModal(title, content, onConfirm, confirmText, opts) {
            opts = opts || {};
            if (document.getElementById('modal-overlay')) {
                modalQueue.push([title, content, onConfirm, confirmText, opts]);
                return;
            }
            const overlay = document.createElement('div');
            overlay.id = 'modal-overlay';
            overlay.className = 'modal-overlay';
            const box = el('div', { class: 'modal-box' }, el('h3', {}, String(title)));
            const body = el('div', { class: 'modal-body' });
            if (content instanceof Node) body.appendChild(content);
            else if (typeof content === 'function') content(body);
            else body.appendChild(el('p', {}, String(content)));
            box.appendChild(body);
            const actions = el('div', { class: 'modal-actions' });
            if (!opts.hideCancel) {
                actions.appendChild(el('button', { type: 'button', class: 'btn-secondary', text: opts.cancelText || 'Cancelar', onclick: closeModal }));
            }
            const ok = el('button', { type: 'button', class: 'btn-primary', text: confirmText || 'Confirmar' });
            ok.onclick = async function () {
                let r;
                try {
                    r = onConfirm ? onConfirm(overlay) : true;
                    if (r && typeof r.then === 'function') r = await r;
                } catch (err) {
                    console.error(err);
                    showToast('Erro: ' + (err && err.message ? err.message : err), 'error');
                    return;
                }
                if (r !== false) closeModal();
            };
            actions.appendChild(ok);
            box.appendChild(actions);
            overlay.appendChild(box);
            document.body.appendChild(overlay);
            overlay.addEventListener('click', function (e) { if (e.target === overlay && !opts.locked) closeModal(); });
        }

        function openAlertModal(title, content, okText) {
            openModal(title, content, null, okText || 'Fechar', { hideCancel: true });
        }

        function askConfirm(message, onYes, confirmText) {
            openModal('Confirmação', message, onYes, confirmText || 'Confirmar');
        }
        // #endregion helpers de UI

        // #region aviso de privacidade (C5) — conteúdo estático confiável
        const PRIVACY_HTML =
            '<div class="privacy-body">' +
            '<h4>1. Finalidade do tratamento</h4>' +
            '<p>Registro de acesso de cidadãos aos computadores da Biblioteca Pública Municipal (matrícula, nome, data de nascimento, categoria, horários de uso) — finalidade exclusiva de controle de uso dos equipamentos.</p>' +
            '<h4>2. Base legal</h4>' +
            '<p>Art. 7º, III da LGPD — execução de políticas públicas previstas em lei (política de acesso público à informação e ao equipamento de biblioteca).</p>' +
            '<h4>3. Prazos de retenção</h4>' +
            '<ul>' +
            '<li><strong>Sessões:</strong> 12 meses no armazenamento ativo; mais antigas são arquivadas em arquivo cifrado (.json.enc).</li>' +
            '<li><strong>Usuários sem uso há 24 meses:</strong> revisão pelo responsável (sugestão automática ao entrar).</li>' +
            '<li><strong>Auditoria:</strong> 24 meses (ciclo de gestão de 2 anos).</li>' +
            '</ul>' +
            '<h4>4. Direitos do titular (art. 18)</h4>' +
            '<p>Acesso, correção e eliminação dos dados. A exclusão pode ser atendida na aba Cadastros (botão "Exclusão LGPD"), que apaga cadastro e sessões vinculadas e registra o atendimento na auditoria.</p>' +
            '<h4>5. Encarregado (DPO)</h4>' +
            '<p>[Preencher: nome, e-mail e telefone do encarregado pelo tratamento de dados da biblioteca].</p>' +
            '<h4>6. Riscos residuais (sistema sem backend — INTERIM)</h4>' +
            '<ul>' +
            '<li>Se o disco rígido falhar ou o navegador limpar os dados, <strong>só o backup diário salva</strong> — exporte com frequência.</li>' +
            '<li>A auditoria gravada localmente é <strong>editável</strong> por quem tiver acesso físico à máquina (não é à prova de adulteração).</li>' +
            '<li>Não há detecção de abuso remoto nem rate limiting de rede.</li>' +
            '<li>O sistema <strong>não tem senha</strong> (decisão da empresa): quem tem acesso ao computador acessa os dados. Proteção: senha de login do Linux obrigatória e bloqueio automático da tela.</li>' +
            '<li>Backups e arquivos exportados <strong>não têm senha</strong>: quem tiver uma cópia consegue ler os dados — guarde-os em local seguro.</li>' +
            '</ul>' +
            '<h4>7. Procedimento de handover (a cada 2 anos)</h4>' +
            '<ol>' +
            '<li>Exportar backup + relatório de gestão.</li>' +
            '<li>Entregar o último backup e os arquivos de sessões arquivadas.</li>' +
            '<li>Registrar a troca no controle externo da empresa.</li>' +
            '</ol>' +
            '<p style="font-size:0.8rem;opacity:0.8;">O controle de <strong>quem</strong> opera é feito externamente pela empresa.</p>' +
            '</div>';

        function openPrivacyNotice() {
            openAlertModal('Aviso de Privacidade, Retenção e Segurança (LGPD)', staticHTML(PRIVACY_HTML));
        }

        function maybeShowPrivacyAck() {
            if (installMeta && installMeta.privacyAckAt) return;
            const chk = el('input', { type: 'checkbox', id: 'priv-ack' });
            openModal('Aviso de Privacidade e Segurança (LGPD)',
                el('div', {}, staticHTML(PRIVACY_HTML), el('label', { class: 'check-line', for: 'priv-ack' }, chk, ' Li e compreendi os riscos residuais e o procedimento de troca de responsável.')),
                async function () {
                    if (!chk.checked) { showToast('Marque a confirmação para continuar.', 'error'); return false; }
                    installMeta.privacyAckAt = new Date().toISOString();
                    await persistInstall();
                    await logAudit('privacidade.aceite', 'sistema', 'lgpd', 'sucesso', '');
                    return true;
                },
                'Confirmar leitura', { hideCancel: true, locked: true });
        }
        // #endregion aviso de privacidade

        // #region sessão / autenticação (C1)
        function requireSession() {
            if (!authSession || !currentDek) {
                showLoginView();
                showToast('Sessão necessária. Faça login.', 'error');
                return false;
            }
            authSession.lastActivity = Date.now();
            return true;
        }

        function updateSessionBar() {
            const bar = document.getElementById('session-bar');
            if (!bar) return;
            if (!authSession) { bar.hidden = true; return; }
            bar.hidden = false;
            document.getElementById('session-operator').textContent = 'Sistema desbloqueado';
        }

        function showAuthOverlay() { document.getElementById('auth-overlay').hidden = false; }
        function hideAuthOverlay() { document.getElementById('auth-overlay').hidden = true; }

        function setAuthView(view) {
            document.getElementById('auth-login-view').hidden = view !== 'login';
            document.getElementById('auth-setup-view').hidden = view !== 'setup';
            document.getElementById('auth-recovery-view').hidden = view !== 'recovery';
            const loading = document.getElementById('auth-loading');
            if (loading) loading.hidden = true; // qualquer tela explícita encerra o "Abrindo…"
        }

        function showLoginView() {
            showAuthOverlay();
            setAuthView('login');
            const setupBtn = document.getElementById('btn-show-setup');
            if (setupBtn) setupBtn.hidden = !!system;
            const lockMsg = document.getElementById('lock-msg');
            if (lockMsg) {
                if (Date.now() < lockUntil) {
                    lockMsg.hidden = false;
                    lockMsg.textContent = 'Acesso bloqueado após 5 tentativas. Aguarde ' + Math.ceil((lockUntil - Date.now()) / 60000) + ' min.';
                } else { lockMsg.hidden = true; }
            }
            updateSessionBar();
        }

        function showSetupView() { showAuthOverlay(); setAuthView('setup'); }
        function showRecoveryView() { showAuthOverlay(); setAuthView('recovery'); }

        function onActivity() { if (authSession) authSession.lastActivity = Date.now(); }
        function bindActivity() {
            ['mousemove', 'keydown', 'pointerdown', 'scroll'].forEach(function (ev) {
                window.addEventListener(ev, onActivity, { passive: true });
            });
        }
        function startIdleTimer() {
            clearInterval(idleTimer);
            idleTimer = setInterval(function () {
                if (authSession && Date.now() - authSession.lastActivity > CFG.SESSION_IDLE_MS) {
                    renewAfterIdle().catch(function (err) { console.error('Falha na renovação por inatividade:', err); });
                }
            }, 15000);
        }

        // Expor por inatividade: com a senha de fábrica o acesso é direto, então a
        // sessão é renovada em silêncio (sem ciclo logout+login e sem poluir a
        // auditoria a cada 15 min). Se a senha foi trocada, cai no logout real e
        // a tela de login aparece — aí a expiração protege de verdade.
        async function renewAfterIdle() {
            if (!authSession) return;
            let senhaAindaPadrao = false;
            if (system && system.password && system.password.envelope) {
                try {
                    const kek = await deriveAesKey(SENHA_PADRAO, system.password.salt, system.password.iterations);
                    await unwrapDek(system.password.envelope, kek);
                    senhaAindaPadrao = true;
                } catch (_) { senhaAindaPadrao = false; }
            }
            if (senhaAindaPadrao) {
                if (!authSession) return;
                authSession.lastActivity = Date.now();
                // recarrega dados decifrados do servidor (pega mudanças); se o
                // servidor caiu, mantém o que está em memória sem derrubar a sessão
                try { await ensureDataLoaded(); } catch (_) { /* melhor esforço */ }
                renderAll();
                return;
            }
            await logout(null, true);
        }

        async function unlockSystem(dek, acao) {
            currentDek = dek;
            authSession = { unlockedAt: new Date().toISOString(), lastActivity: Date.now() };
            await ensureDataLoaded();
            await logAudit(acao, 'sistema', 'unlock', 'sucesso', '');
            hideAuthOverlay();
            updateSessionBar();
            startIdleTimer();
            renderAll();
            await runRetentionChecks();
            maybeShowPrivacyAck();
            showToast('Sistema desbloqueado.', 'success');
        }

        // Entrar direto: desbloqueio silencioso com a senha de fábrica, sem tela de senha.
        // Retorna false quando a senha foi trocada (ou o registro está incompleto) —
        // aí o chamador mantém a tela de login como fallback de segurança.
        async function trySilentUnlock(acao) {
            if (!system || !system.password || !system.password.envelope) return false;
            try {
                const kek = await deriveAesKey(SENHA_PADRAO, system.password.salt, system.password.iterations);
                const dek = await unwrapDek(system.password.envelope, kek);
                await unlockSystem(dek, acao || 'desbloqueio_automatico');
                return true;
            } catch (_) {
                currentDek = null;
                authSession = null;
                return false;
            }
        }

        async function logout(msg, expired, msgRelogado) {
            if (authSession && currentDek) {
                try { await logAudit(expired ? 'sessao.expirada' : 'logout', 'sistema', 'unlock', 'sucesso', ''); }
                catch (_) { /* melhor esforço */ }
            }
            currentDek = null;
            authSession = null;
            clearInterval(idleTimer); idleTimer = null;
            closeModal();
            // Entrar direto: com a senha de fábrica o sistema reabre sozinho;
            // a tela de senha só aparece como fallback (senha trocada / servidor fora).
            if (await trySilentUnlock()) {
                openTabById('tab-geral');
                showToast(msgRelogado || msg || (expired ? 'Sessão reaberta automaticamente após 15 minutos de inatividade.' : 'Sessão reaberta automaticamente.'), 'success');
                return;
            }
            userBase = []; sessions = []; notes = []; auditLog = [];
            updateSessionBar();
            openTabById('tab-geral');
            renderAll();
            showLoginView();
            if (msg) showToast(msg, expired ? 'error' : 'success');
            else if (expired) showToast('Sessão expirada por inatividade (15 minutos). Faça login novamente.', 'error');
        }

        function registerFailure(reason, msg) {
            loginAttempts++;
            if (loginAttempts >= CFG.MAX_LOGIN_ATTEMPTS) {
                lockUntil = Date.now() + CFG.LOCKOUT_MS;
                loginAttempts = 0;
                logAuthFailure('(bloqueio)', '5_tentativas');
                return '5 tentativas incorretas — acesso bloqueado por 15 minutos.';
            }
            const left = CFG.MAX_LOGIN_ATTEMPTS - loginAttempts;
            return msg + ' (' + left + ' tentativa' + (left > 1 ? 's' : '') + ' antes do bloqueio)';
        }

        // Sem senha (decisão da empresa): qualquer desbloqueio com senha antiga — login, recuperação,
        // backup restaurado — volta o envelope para a senha fixa; a tela de senha aparece no máximo uma vez.
        async function envelopeSemSenha(dek) {
            const salt = randomB64(CFG.SALT_BYTES);
            return { salt: salt, iterations: CFG.PBKDF2_ITER, envelope: await wrapDek(dek, await deriveAesKey(SENHA_PADRAO, salt, CFG.PBKDF2_ITER)) };
        }
        async function voltarParaSemSenha(dek) {
            system.password = await envelopeSemSenha(dek);
            await saveSystem();
            await logAudit('senha.removida', 'sistema', 'password', 'sucesso', 'voltou ao modo sem senha');
        }

        async function attemptLogin(password) {
            if (Date.now() < lockUntil) {
                return { ok: false, msg: 'Acesso bloqueado. Tente novamente em ' + Math.ceil((lockUntil - Date.now()) / 60000) + ' min.' };
            }
            if (!system || !system.password || !system.password.envelope) {
                return { ok: false, msg: 'Sistema não configurado.' };
            }
            let dek;
            try {
                const kek = await deriveAesKey(password, system.password.salt, system.password.iterations);
                dek = await unwrapDek(system.password.envelope, kek);
            } catch (_) {
                logAuthFailure('(senha)', 'senha_incorreta');
                return { ok: false, msg: registerFailure('auth', 'Senha incorreta.') };
            }
            loginAttempts = 0;
            await unlockSystem(dek, 'desbloqueio');
            if (password !== SENHA_PADRAO) {
                try { await voltarParaSemSenha(dek); }
                catch (err) { showToast('Entrou, mas não foi possível voltar ao modo sem senha: ' + (err && err.message ? err.message : err), 'error'); }
            }
            return { ok: true };
        }
        // #endregion sessão / autenticação
        // #region setup inicial + código de recuperação (C1/C2)
        function validPassword(p) { return typeof p === 'string' && p.length >= 8; }

        // Modal com o código de recuperação: exige checkbox + 4 caracteres para concluir.
        function openRecoveryCodeModal(code, onDone) {
            const formatted = formatRecoveryCode(code);
            const confirmChars = code.slice(4, 8); // caracteres 5–8
            const input = el('input', { type: 'text', id: 'rc-confirm', maxlength: '4', autocomplete: 'off' });
            const chk = el('input', { type: 'checkbox', id: 'rc-chk' });
            openModal('Código de recuperação — exibição única',
                el('div', {},
                    el('div', { class: 'warning-box' }, 'SE PERDER ESTE CÓDIGO E A SENHA, OS DADOS FICARÃO IRRECUPERÁVEIS. Ele é a única via de acesso alternativa à senha. Será exibido UMA única vez: imprima e guarde em local seguro (envelope físico).'),
                    el('div', { class: 'recovery-code', id: 'rc-display', text: formatted }),
                    el('label', { class: 'check-line', for: 'rc-chk' }, chk, ' Confirmo que li, imprimei/copiei e guardei o código acima.'),
                    formGroup('Digite os caracteres 5 a 8 do código (confirmação):', input)
                ),
                function () {
                    const typed = String(input.value).toUpperCase().replace(/[^A-Z0-9]/g, '');
                    if (!chk.checked || typed !== confirmChars) {
                        showToast('Confirme o checkbox e digite os 4 caracteres corretamente (posição 5–8) para concluir.', 'error');
                        return false;
                    }
                    onDone();
                    return true;
                },
                'Concluir', { hideCancel: true, locked: true });
        }

        // Cria o registro do sistema (installMeta + envelopes) com a senha informada.
        async function createSystem(pass1) {
            installMeta = {
                schemaVersion: CFG.SCHEMA_VERSION,
                installSalt: randomB64(CFG.SALT_BYTES),
                iterations: CFG.PBKDF2_ITER,
                createdAt: new Date().toISOString(),
                lastExportAt: null,
                lastArchiveAt: null,
                privacyAckAt: null
            };
            await persistInstall();
            const dek = await generateDek();
            const salt = randomB64(CFG.SALT_BYTES);
            const kek = await deriveAesKey(pass1, salt, installMeta.iterations);
            const rc = generateRecoveryCode();
            const rcKek = await deriveAesKey(rc, installMeta.installSalt, installMeta.iterations);
            const novo = {
                password: { salt: salt, iterations: installMeta.iterations, envelope: await wrapDek(dek, kek) },
                recovery: { envelope: await wrapDek(dek, rcKek) }
            };
            await rawSet('bpa_system', JSON.stringify(novo));
            system = novo;   // só depois de gravado: falha não deixa um 'system' fantasma em memória
            return { dek: dek, rc: rc };
        }

        // Primeira abertura: instalação AUTOMÁTICA com a senha pré-definida (sem tela de setup).
        async function runFirstInstall() {
            let temDadosAntigos = false;
            try { temDadosAntigos = !!(await rawGet('bpa_user_base')) && !(await rawGet('bpa_install')); }
            catch (_) { /* servidor caiu entre o bootstrap e aqui — createSystem acusa o erro */ }
            if (temDadosAntigos) {
                const ok = window.confirm('Há dados antigos nesta máquina. Se estiverem cifrados com uma senha perdida, ficarão irrecuperáveis após a nova configuração. Deseja continuar?');
                if (!ok) { showLoginView(); showToast('Configuração cancelada. Use "Primeiro uso: configurar o sistema" quando quiser continuar.', 'error'); return; }
            }
            try {
                const result = await createSystem(SENHA_PADRAO);
                await unlockSystem(result.dek, 'setup_inicial');
                // Sem senha (decisão da empresa): o código de recuperação é gerado mas não exibido — não há senha a recuperar
                showToast('Sistema configurado. Ele abre direto, sem senha.', 'success');
            } catch (err) {
                console.error(err);
                showLoginView();
                showToast('Falha na configuração inicial. Verifique o servidor no terminal e tente "Primeiro uso: configurar o sistema" (ou F5).', 'error');
            }
        }

        async function handleSetup(e) {
            e.preventDefault();
            const pass1 = document.getElementById('setup-password').value;
            const pass2 = document.getElementById('setup-password2').value;
            if (!validPassword(pass1)) return showToast('A senha deve ter no mínimo 8 caracteres.', 'error');
            if (pass1 !== pass2) return showToast('As senhas não conferem.', 'error');
            if (system) return showToast('O sistema já está configurado. Use o desbloqueio.', 'error');
            try {
                const result = await createSystem(pass1);
                await unlockSystem(result.dek, 'setup_inicial');
                openRecoveryCodeModal(result.rc, function () {
                    showToast('Senha do sistema criada. Guarde o código de recuperação em local seguro!', 'success');
                });
            } catch (err) {
                console.error(err);
                showToast('Falha na configuração inicial: ' + (err && err.message ? err.message : err), 'error');
            }
        }

        async function handleRecovery(e) {
            e.preventDefault();
            const code = normalizeRecoveryCode(document.getElementById('rec-code').value);
            if (!installMeta) return showToast('Metadados de instalação ausentes.', 'error');
            if (code.length !== 16) return showToast('O código de recuperação tem 16 caracteres.', 'error');
            if (!system || !system.recovery || !system.recovery.envelope) {
                logAuthFailure('(recuperacao)', 'sem_envelope');
                return showToast('Código de recuperação indisponível.', 'error');
            }
            let dek;
            try {
                const rcKek = await deriveAesKey(code, installMeta.installSalt, installMeta.iterations);
                dek = await unwrapDek(system.recovery.envelope, rcKek);
            } catch (_) {
                logAuthFailure('(recuperacao)', 'codigo_errado');
                return showToast('Código de recuperação inválido.', 'error');
            }
            system.password = await envelopeSemSenha(dek);
            await saveSystem();
            loginAttempts = 0;
            lockUntil = 0;
            await unlockSystem(dek, 'senha_resetada_recuperacao');
            document.getElementById('recovery-form').reset();
            showToast('Acesso recuperado. O sistema volta a abrir direto, sem senha.', 'success');
        }

        // #endregion setup inicial + código de recuperação

        // #region retenção/validação de dados (C5)
        function monthsAgo(n) {
            const d = new Date();
            d.setMonth(d.getMonth() - n);
            return d.getTime();
        }

        function usersInactive24m() {
            const cutoff = monthsAgo(CFG.RET_USER_REVIEW_MONTHS);
            return userBase.filter(function (u) {
                let last = 0;
                sessions.forEach(function (s) {
                    if (s.userId === u.id) {
                        const t = new Date(s.entradaFull).getTime();
                        if (t > last) last = t;
                    }
                });
                if (!last) last = new Date(u.id).getTime() || 0;
                return last < cutoff;
            });
        }

        async function runRetentionChecks() {
            // 1) Auditoria > 24 meses → purge
            const cutoffA = monthsAgo(CFG.RET_AUDIT_MONTHS);
            const before = auditLog.length;
            auditLog = auditLog.filter(function (a) { return new Date(a.timestamp).getTime() >= cutoffA; });
            if (auditLog.length !== before) await repoSet('bpa_audit_v1', auditLog);

            // 2) Sessões encerradas > 12 meses → modal de arquivamento (arquivo cifrado + remoção)
            const cutoffS = monthsAgo(CFG.RET_SESSIONS_MONTHS);
            const old = sessions.filter(function (s) {
                return s.status !== 'Ativo' && new Date(s.entradaFull).getTime() < cutoffS;
            });
            if (old.length) showArchiveModal(old);

            // 3) Usuários inativos há 24 meses → sugestão de revisão
            const review = usersInactive24m();
            if (review.length) {
                showToast(review.length + ' usuário(s) sem uso há 24 meses — revise o cadastro (aba Cadastros).', 'success');
                await logAudit('retencao.revisar_usuarios', 'user', review.length, 'sucesso', review.length + ' usuário(s)');
            }
        }

        function showArchiveModal(oldSessions) {
            openModal('Arquivamento de sessões antigas (12 meses)',
                el('div', {},
                    el('div', { class: 'warning-box' }, 'Há ' + oldSessions.length + ' sessão(ões) com mais de 12 meses no armazenamento ativo. Para manter o banco enxuto, elas serão exportadas para um arquivo (.json.enc) e removidas do armazenamento ativo. Para reconsultar no futuro, use o botão "Reimportar Sessões (.json.enc)" (aba Cadastros).')
                ),
                async function () {
                    return await archiveOldSessions(oldSessions, SENHA_PADRAO);
                }, 'Arquivar e exportar');
        }

        async function archiveOldSessions(oldSessions, exportPassword) {
            try {
                const salt = randomB64(CFG.SALT_BYTES);
                const kek = await deriveAesKey(exportPassword, salt, installMeta.iterations);
                const dekWrapped = await wrapDek(currentDek, kek);
                const payload = await encryptJSON({ sessions: oldSessions }, currentDek);
                const file = {
                    format: 'bpa-archive',
                    schemaVersion: CFG.SCHEMA_VERSION,
                    archivedAt: new Date().toISOString(),
                    kdf: { salt: salt, iterations: installMeta.iterations },
                    dekWrapped: dekWrapped,
                    payload: payload
                };
                downloadJSON(file, 'arquivo_sessoes_' + new Date().toISOString().slice(0, 10) + '.json.enc');
                const ids = {};
                oldSessions.forEach(function (s) { ids[String(s.sessionId)] = true; });
                sessions = sessions.filter(function (s) { return !ids[String(s.sessionId)]; });
                await repoSet('bpa_sessions', sessions);
                installMeta.lastArchiveAt = new Date().toISOString();
                await persistInstall();
                await logAudit('arquivo.gerado', 'arquivo', oldSessions.length, 'sucesso', oldSessions.length + ' sessões');
                renderAll();
                showToast(oldSessions.length + ' sessões arquivadas em arquivo (.json.enc) e removidas do armazenamento ativo.', 'success');
                return true;
            } catch (err) {
                showToast('Falha no arquivamento: ' + (err && err.message ? err.message : err), 'error');
                return false;
            }
        }
        // #endregion retenção/validação de dados
        // #region backup cifrado / importação (C2)
        function downloadJSON(obj, fileName) {
            const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.setAttribute('href', url);
            link.setAttribute('download', fileName);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        }

        function exportBackup() {
            if (!requireSession()) return;
            openModal('Exportar backup',
                el('div', { class: 'warning-box' }, 'O arquivo exportado não tem senha: qualquer pessoa com o arquivo e este sistema consegue ler os dados dos cidadãos. Guarde-o em local seguro. Para restaurar, use "Importar backup".'),
                async function () {
                    await doExportEncrypted(SENHA_PADRAO);
                    return true;
                }, 'Exportar');
        }

        async function doExportEncrypted(password) {
            try {
                const salt = randomB64(CFG.SALT_BYTES);
                const kek = await deriveAesKey(password, salt, installMeta.iterations);
                const dekWrapped = await wrapDek(currentDek, kek);
                const payload = await encryptJSON({ userBase: userBase, sessions: sessions, notes: notes, audit: auditLog }, currentDek);
                const backup = {
                    format: 'bpa-backup',
                    schemaVersion: CFG.SCHEMA_VERSION,
                    exportedAt: new Date().toISOString(),
                    kdf: { salt: salt, iterations: installMeta.iterations },
                    installMeta: installMeta,
                    system: system,
                    dekWrapped: dekWrapped,
                    payload: payload
                };
                downloadJSON(backup, 'backup_biblioteca_' + new Date().toISOString().slice(0, 10) + '.json.enc');
                installMeta.lastExportAt = new Date().toISOString();
                await persistInstall();
                await logAudit('backup.exportar_cifrado', 'backup', 'cifrado', 'sucesso', '');
                showToast('Backup exportado. Guarde o arquivo em local seguro.', 'success');
            } catch (err) {
                showToast('Falha ao exportar: ' + (err && err.message ? err.message : err), 'error');
            }
        }

        function exportBackupPlain() {
            if (!requireSession()) return;
            openModal('Exportar backup EM CLARO — perigo de PII',
                staticHTML('<div class="danger-box"><strong>ATENÇÃO:</strong> este arquivo conterá DADOS PESSOAIS EM CLARO (nome, nascimento, matrícula de cidadãos). Qualquer pessoa com acesso ao arquivo poderá ler. Use apenas para migração técnica ao banco de dados futuro.</div>'),
                function () {
                    openModal('Confirmação final — backup em claro',
                        staticHTML('<p>Declaro que entendo que este arquivo conterá PII em claro e me responsabilizo pelo armazenamento seguro dele.</p><label class="check-line"><input type="checkbox" id="plain-chk"> Estou ciente do risco</label>'),
                        async function () {
                            const chk = document.getElementById('plain-chk');
                            if (!chk || !chk.checked) { showToast('Confirme a declaração.', 'error'); return false; }
                            const backup = {
                                format: 'bpa-backup-plain',
                                schemaVersion: CFG.SCHEMA_VERSION,
                                warning: 'CONTÉM DADOS PESSOAIS EM CLARO',
                                exportedAt: new Date().toISOString(),
                                userBase: userBase, sessions: sessions, notes: notes, audit: auditLog,
                                system: system, installMeta: installMeta
                            };
                            downloadJSON(backup, 'backup_biblioteca_CLARO_' + new Date().toISOString().slice(0, 10) + '.json');
                            installMeta.lastExportAt = new Date().toISOString();
                            await persistInstall();
                            await logAudit('backup.exportar_claro', 'backup', 'claro', 'sucesso', '');
                            showToast('Backup em claro exportado.', 'success');
                            return true;
                        }, 'Exportar mesmo assim');
                    return true;
                }, 'Continuar');
        }

        function importBackup(event) {
            if (!requireSession()) return;
            const file = event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = function () { handleImportText(reader.result, file.name); };
            reader.readAsText(file);
            event.target.value = '';
        }

        // Reimportação de sessões arquivadas (.json.enc) — gera o arquivo showArchiveModal
        function reimportArchive(event) {
            if (!requireSession()) return;
            const file = event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = function () { handleImportText(reader.result, file.name, 'archive'); };
            reader.readAsText(file);
            event.target.value = '';
        }

        // Snapshot do estado em memória — rollback se a importação falhar no meio.
        // O backend grava tudo-ou-nada (POST /api/kv/batch); aqui garantimos o mesmo para a memória.
        function snapshotState() {
            return { installMeta: installMeta, system: system, currentDek: currentDek, userBase: userBase, sessions: sessions, notes: notes, auditLog: auditLog };
        }
        function restoreState(s) {
            installMeta = s.installMeta; system = s.system; currentDek = s.currentDek;
            userBase = s.userBase; sessions = s.sessions; notes = s.notes; auditLog = s.auditLog;
        }

        // Envelope de arquivo exportado bem formado; iterações vêm do arquivo (não confiável): teto evita travar.
        function envelopeArquivoOk(data) {
            return !!(data && data.kdf && typeof data.kdf.salt === 'string'
                && Number.isInteger(data.kdf.iterations) && data.kdf.iterations >= 1000 && data.kdf.iterations <= CFG.PBKDF2_ITER * 4
                && data.dekWrapped && data.dekWrapped.iv && data.dekWrapped.data
                && data.payload && data.payload.iv && data.payload.data);
        }

        // Arquivos novos usam a senha fixa (sem senha para o operador): devolve a DEK, ou null se for
        // arquivo antigo, gerado com senha escolhida.
        async function dekComSenhaFixa(data) {
            try { return await unwrapDek(data.dekWrapped, await deriveAesKey(SENHA_PADRAO, data.kdf.salt, data.kdf.iterations)); }
            catch (_) { return null; }
        }

        async function handleImportText(text, fname, expect) {
            let data;
            try { data = JSON.parse(text); }
            catch (_) { return showToast('Arquivo inválido (JSON ilegível).'); }

            if (expect === 'archive' && !(data && data.format === 'bpa-archive')) {
                return showToast('Este não é um arquivo de sessões arquivadas (.json.enc).');
            }

            if (data && data.format === 'bpa-archive') {
                // Reimportar sessões arquivadas: decifra com a senha de exportação, valida e anexa de volta
                if (!envelopeArquivoOk(data)) return showToast('Arquivo de sessões arquivado inválido (estrutura corrompida).');
                const dekFixa = await dekComSenhaFixa(data);
                const pw = dekFixa ? null : el('input', { type: 'password', id: 'reimp-pw', autocomplete: 'off' });
                openModal('Reimportar sessões arquivadas',
                    el('div', {},
                        el('div', { class: 'warning-box' }, 'As sessões deste arquivo .json.enc serão decifradas e anexadas de volta ao armazenamento ativo. Sessões que já existem não são duplicadas.'),
                        pw ? formGroup('Arquivo antigo, gerado com senha — digite a senha usada no arquivamento:', pw) : null
                    ),
                    async function () {
                        const snap = snapshotState();
                        let novas;
                        try {
                            const dek = dekFixa || await unwrapDek(data.dekWrapped, await deriveAesKey(pw.value, data.kdf.salt, data.kdf.iterations));
                            const payload = await decryptJSON(data.payload, dek);
                            const list = payload && payload.sessions;
                            const valido = Array.isArray(list)
                                && list.every(function (s) { return s && s.sessionId !== undefined && s.userId !== undefined && typeof s.entradaFull === 'string'; });
                            if (!valido) throw new Error('sessões inválidas');
                            const have = {};
                            sessions.forEach(function (s) { have[String(s.sessionId)] = true; });
                            novas = list.filter(function (s) { return !have[String(s.sessionId)]; });
                            if (!novas.length) {
                                showToast('Nenhuma sessão nova: todas já estão no armazenamento ativo.', 'success');
                                return true;
                            }
                            sessions = sessions.concat(novas);
                            // commit único e atômico no SQLite
                            await repoSet('bpa_sessions', sessions);
                        } catch (err) {
                            restoreState(snap);
                            showToast('Senha incorreta ou arquivo corrompido.', 'error');
                            return false;
                        }
                        // daqui em diante o commit já existe — melhor esforço
                        await logAudit('arquivo.reimportar', 'arquivo', novas.length, 'sucesso', 'reimportação de .json.enc');
                        renderAll();
                        showToast(novas.length + ' sessão(ões) reimportada(s) do arquivo arquivado.', 'success');
                        return true;
                    }, 'Reimportar');
            } else if (data && data.format === 'bpa-backup') {
                // Restauração completa: troca instalação + registro do sistema + dados (senha só para arquivo antigo)
                if (!envelopeArquivoOk(data)) return showToast('Backup inválido (estrutura corrompida).');
                const dekFixa = await dekComSenhaFixa(data);
                const pw = dekFixa ? null : el('input', { type: 'password', id: 'imp-pw', autocomplete: 'off' });
                openModal('Importar backup cifrado',
                    el('div', {},
                        el('div', { class: 'warning-box' }, 'A importação SUBSTITUI todos os dados atuais pelos do backup.'),
                        pw ? formGroup('Backup antigo, gerado com senha — digite a senha usada na geração:', pw) : null
                    ),
                    async function () {
                        const snap = snapshotState();
                        try {
                            const dek = dekFixa || await unwrapDek(data.dekWrapped, await deriveAesKey(pw.value, data.kdf.salt, data.kdf.iterations));
                            const payload = await decryptJSON(data.payload, dek);
                            const valido = payload && Array.isArray(payload.userBase) && Array.isArray(payload.sessions) && Array.isArray(payload.notes)
                                && data.system && data.system.password && data.system.password.envelope
                                && data.installMeta && typeof data.installMeta.installSalt === 'string';
                            if (!valido) throw new Error('estrutura inválida');
                            installMeta = data.installMeta;
                            // Backup de máquina com senha trocada: já volta ao modo sem senha (mesma DEK)
                            system = Object.assign({}, data.system, { password: await envelopeSemSenha(dek) });
                            currentDek = dek;
                            userBase = payload.userBase;
                            sessions = payload.sessions;
                            notes = payload.notes;
                            auditLog = Array.isArray(payload.audit) ? payload.audit : [];
                            // As 6 chaves numa transação única no backend: restaura tudo ou nada
                            await rawBatch({
                                bpa_install: JSON.stringify(installMeta),
                                bpa_system: JSON.stringify(system),
                                bpa_user_base: JSON.stringify(await encryptJSON(userBase, currentDek)),
                                bpa_sessions: JSON.stringify(await encryptJSON(sessions, currentDek)),
                                bpa_notes_v2: JSON.stringify(await encryptJSON(notes, currentDek)),
                                bpa_audit_v1: JSON.stringify(await encryptJSON(auditLog, currentDek))
                            }, []);
                        } catch (err) {
                            restoreState(snap);
                            showToast('Senha incorreta ou backup corrompido.', 'error');
                            return false;
                        }
                        // commit já existe no banco — daqui em diante é melhor esforço
                        await logAudit('backup.importar', 'backup', fname, 'sucesso', 'restauração completa');
                        renderAll();
                        await logout('Backup restaurado com sucesso.',
                            false, 'Backup restaurado com sucesso. Sistema reaberto automaticamente.');
                        return true;
                    }, 'Restaurar');
            } else if (data && Array.isArray(data.userBase)) {
                // Backup legado (v1, em claro) → re-cifrado sob a DEK atual; registro de senha preservado
                const valido = Array.isArray(data.sessions) && Array.isArray(data.notes)
                    && data.userBase.every(function (u) { return u && u.id !== undefined && typeof u.matricula === 'string' && typeof u.nome === 'string' && typeof u.nascimento === 'string'; })
                    && data.sessions.every(function (s) { return s && s.sessionId !== undefined && s.userId !== undefined; })
                    && data.notes.every(function (n) { return n && typeof n.title === 'string' && typeof n.text === 'string' && typeof n.category === 'string'; });
                if (!valido) return showToast('Formato de backup não reconhecido.');
                openModal('Importar backup legado (em claro)',
                    staticHTML('<div class="danger-box">Este é um backup ANTIGO em formato não cifrado. Ele será <strong>re-cifrado</strong> sob a chave atual e <strong>SUBSTITUI</strong> os dados atuais (usuários, sessões e avisos).</div><label class="check-line"><input type="checkbox" id="imp-leg-chk"> Estou ciente da substituição</label>'),
                    async function () {
                        const chk = document.getElementById('imp-leg-chk');
                        if (!chk || !chk.checked) { showToast('Confirme a declaração.', 'error'); return false; }
                        const snap = snapshotState();
                        try {
                            userBase = data.userBase;
                            sessions = data.sessions;
                            notes = data.notes;
                            // 3 chaves numa transação única no backend: re-cifra sem deixar estado parcial
                            await rawBatch({
                                bpa_user_base: JSON.stringify(await encryptJSON(userBase, currentDek)),
                                bpa_sessions: JSON.stringify(await encryptJSON(sessions, currentDek)),
                                bpa_notes_v2: JSON.stringify(await encryptJSON(notes, currentDek))
                            }, []);
                        } catch (err) {
                            restoreState(snap);
                            showToast('Falha na importação — nada foi alterado.', 'error');
                            return false;
                        }
                        await logAudit('backup.importar', 'backup', fname, 'sucesso', 'legado em claro re-cifrado');
                        renderAll();
                        showToast('Backup legado importado e re-cifrado.', 'success');
                        return true;
                    }, 'Importar');
            } else {
                showToast('Formato de backup não reconhecido.');
            }
        }
        // Backup automático (Bloco 6): o servidor gera; aqui só o status e "abrir a pasta".
        async function loadBackupStatus() {
            const out = document.getElementById('backup-status');
            if (PERSIST_MODE === 'local') { document.getElementById('backup-card').style.display = 'none'; return; }
            out.classList.remove('backup-erro');
            let st;
            try {
                const res = await apiFetch('/api/backup/status');
                if (!res.ok) throw new Error('HTTP ' + res.status);
                st = await res.json();
            }
            catch (_) { out.textContent = 'Status indisponível (servidor fora).'; return; }
            if (st.erro) {
                out.classList.add('backup-erro');
                out.textContent = 'Falha no backup automático: ' + st.erro + '. Veja o terminal.';
            } else if (!st.ultimo) out.textContent = 'Nenhum backup ainda.';
            else out.textContent = 'Último backup automático: ' + formatDateTime(st.ultimo) + ' (' + st.total + ' guardados)';
        }

        async function openBackupFolder() {
            try {
                const r = await (await apiFetch('/api/backup/abrir-pasta', { method: 'POST' })).json();
                if (r.ok) showToast('Pasta de backups aberta.', 'success');
                else showToast(r.erro || 'Não foi possível abrir a pasta de backups.', 'error');
            } catch (_) { showToast('Servidor fora — não foi possível abrir a pasta de backups.', 'error'); }
        }
        // #endregion backup cifrado / importação

        // #region exclusão de titular (C5 — LGPD)
        function requestLgpdDeletion(id) {
            if (!requireSession()) return;
            const user = userBase.find(function (u) { return u.id === id; });
            if (!user) return;
            const nSessions = sessions.filter(function (s) { return s.userId === id; }).length;
            openModal('Atender exclusão de titular (LGPD)',
                el('div', {},
                    el('div', { class: 'danger-box' }, 'Esta ação apagará PERMANENTEMENTE o cadastro de ' + user.nome + ' (mat. ' + user.matricula + ') e ' + nSessions + ' sessão(ões) vinculada(s). Não pode ser desfeita. O ATENDIMENTO (sem dados pessoais) ficará registrado na auditoria.'),
                    formGroup('Digite LGPD para confirmar:', el('input', { type: 'text', id: 'lgpd-confirm', autocomplete: 'off' }))
                ),
                async function () {
                    const conf = document.getElementById('lgpd-confirm');
                    if (!conf || String(conf.value).trim().toUpperCase() !== 'LGPD') {
                        showToast('Digite LGPD no campo para confirmar.', 'error');
                        return false;
                    }
                    userBase = userBase.filter(function (u) { return u.id !== id; });
                    sessions = sessions.filter(function (s) { return s.userId !== id; });
                    await repoSet('bpa_user_base', userBase);
                    await repoSet('bpa_sessions', sessions);
                    await logAudit('usuario.exclusao_lgpd', 'user', String(id), 'sucesso', nSessions + ' sessão(ões) removida(s)');
                    renderAll();
                    showToast('Exclusão de titular atendida e registrada na auditoria.', 'success');
                    return true;
                }, 'Excluir definitivamente');
        }
        // #endregion exclusão de titular

        // #region relatório de gestão (C5.6 / A2)
        function reportData() {
            const per = getFilteredSessions();
            const done = per.filter(function (s) { return s.saidaFull; });
            const totalMin = done.reduce(function (a, s) { return a + (new Date(s.saidaFull) - new Date(s.entradaFull)) / 60000; }, 0);
            const byUser = {};
            per.forEach(function (s) { byUser[s.userId] = (byUser[s.userId] || 0) + 1; });
            const top10 = Object.keys(byUser).map(function (uid) {
                const u = userBase.find(function (x) { return String(x.id) === String(uid); });
                return { matricula: u ? u.matricula : '-', nome: u ? u.nome : 'Excluído', acessos: byUser[uid] };
            }).sort(function (a, b) { return b.acessos - a.acessos; }).slice(0, 10);
            return {
                inicio: document.getElementById('start-date').value || 'início dos dados',
                fim: document.getElementById('end-date').value || 'hoje',
                totalAcessos: per.length,
                usuariosCadastrados: userBase.length,
                tempoMedio: done.length ? Math.round(totalMin / done.length) : 0,
                top10: top10,
                alertas: notes.filter(function (n) { return n.category === 'Urgente'; }).length,
                suspensas: per.filter(function (s) { return s.status === 'Suspenso'; }).length,
                geradoEm: new Date().toLocaleString('pt-BR')
            };
        }

        function generateManagementReportCSV() {
            if (!requireSession()) return;
            const d = reportData();
            const lines = [
                'Relatório de Gestão — Biblioteca Pública Municipal',
                'Gerado em;' + d.geradoEm,
                'Período;' + d.inicio + ';' + d.fim,
                'Total de acessos;' + d.totalAcessos,
                'Usuários cadastrados;' + d.usuariosCadastrados,
                'Tempo médio de uso (min);' + d.tempoMedio,
                'Alertas emitidos;' + d.alertas,
                'Sessões suspensas no período;' + d.suspensas,
                '',
                'Top 10 usuários',
                'Matrícula;Nome;Acessos'
            ];
            d.top10.forEach(function (t) { lines.push([t.matricula, t.nome, t.acessos].map(csvField).join(';')); });
            downloadCSV('relatorio_gestao_' + new Date().toISOString().slice(0, 10) + '.csv', lines);
            logAudit('relatorio.gestao_gerado', 'relatorio', 'csv', 'sucesso', d.totalAcessos + ' acessos');
        }

        function stripAccents(s) { return String(s).normalize('NFD').replace(/[̀-ͯ]/g, ''); }

        async function generateManagementReportPDF() {
            if (!requireSession()) return;
            if (!window.jspdf) return showToast('PDF indisponível (biblioteca offline). Gere o CSV.', 'error');
            const d = reportData();
            const pdf = new window.jspdf.jsPDF('p', 'mm', 'a4');
            let y = 15;
            const put = function (t, size) {
                pdf.setFontSize(size || 10);
                pdf.text(stripAccents(t), 10, y);
                y += size ? 7 : 5;
            };
            put('Relatorio de Gestao - Biblioteca Publica Municipal', 14);
            put('Gerado em: ' + d.geradoEm);
            put('Periodo: ' + d.inicio + ' a ' + d.fim);
            y += 3;
            put('Total de acessos: ' + d.totalAcessos);
            put('Usuarios cadastrados: ' + d.usuariosCadastrados);
            put('Tempo medio de uso: ' + d.tempoMedio + ' min');
            put('Alertas emitidos: ' + d.alertas);
            put('Sessoes suspensas no periodo: ' + d.suspensas);
            y += 4;
            put('Top 10 usuarios', 12);
            d.top10.forEach(function (t, i) {
                put('  ' + (i + 1) + '. ' + t.matricula + ' - ' + t.nome + ' - ' + t.acessos + ' acessos');
            });
            if (y > 270) { /* cabeçárium simples; conteúdo curto por padrão */ }
            pdf.save('relatorio_gestao_' + new Date().toISOString().slice(0, 10) + '.pdf');
            await logAudit('relatorio.gestao_gerado', 'relatorio', 'pdf', 'sucesso', d.totalAcessos + ' acessos');
            showToast('Relatório de gestão (PDF) gerado.', 'success');
        }
        // #endregion relatório de gestão
        // #region renderização de auditoria
        function getFilteredAudit() {
            let rows = auditLog.slice();
            const start = document.getElementById('audit-filter-start');
            const end = document.getElementById('audit-filter-end');
            if (start && start.value) rows = rows.filter(function (a) { return String(a.timestamp).slice(0, 10) >= start.value; });
            if (end && end.value) rows = rows.filter(function (a) { return String(a.timestamp).slice(0, 10) <= end.value; });
            rows.sort(function (a, b) { return String(b.timestamp).localeCompare(String(a.timestamp)); });
            return rows;
        }

        function renderAuditTable() {
            const list = document.getElementById('audit-list');
            if (!list) return;
            const rows = getFilteredAudit();
            const startEl = document.getElementById('audit-filter-start');
            const endEl = document.getElementById('audit-filter-end');
            // assinatura dos filtros: mudar período volta à página 1 (ver syncTablePage)
            const sig = JSON.stringify([startEl ? startEl.value : '', endEl ? endEl.value : '']);
            const w = syncTablePage('audit', sig, rows.length);
            const display = rows.slice(w.from, w.to);
            list.innerHTML = '';
            display.forEach(function (a) {
                const tr = document.createElement('tr');
                tr.innerHTML = '<td>' + escapeHTML(formatDateTime(a.timestamp)) + '</td>' +
                    '<td>' + escapeHTML(a.acao) + '</td>' +
                    '<td>' + escapeHTML(a.alvo_tipo + (a.alvo_id ? ': ' + a.alvo_id : '')) + '</td>' +
                    '<td>' + escapeHTML(a.resultado) + '</td>' +
                    '<td style="font-size:0.8rem;">' + escapeHTML(a.detalhes) + '</td>';
                list.appendChild(tr);
            });
            renderPager('audit-pager', 'audit', rows.length, renderAuditTable);
            const note = document.getElementById('audit-note');
            if (note) {
                const faixa = rows.length
                    ? 'Exibindo ' + (w.from + 1) + '–' + (w.from + display.length) + ' de ' + rows.length + ' registro(s) · página ' + w.page + ' de ' + w.pages + ' — use os filtros de período para reduzir.'
                    : 'Nenhum registro para os filtros atuais.';
                note.textContent = faixa + ' O registro identifica AÇÕES, não pessoas (controle de operadores é externo).';
            }
        }

        function exportAuditCSV() {
            if (!requireSession()) return;
            const rows = getFilteredAudit();
            if (!rows.length) return showToast('Nenhum registro de auditoria para exportar.');
            askConfirm('Exportar ' + rows.length + ' registro(s) de auditoria em CSV (conforme filtros atuais)?', async function () {
                const lines = ['ID;Timestamp;Ação;Alvo tipo;Alvo ID;Resultado;Detalhes'];
                rows.forEach(function (a) {
                    lines.push([a.id, a.timestamp, a.acao, a.alvo_tipo, a.alvo_id, a.resultado, a.detalhes].map(csvField).join(';'));
                });
                downloadCSV('auditoria_' + new Date().toISOString().slice(0, 10) + '.csv', lines);
                await logAudit('auditoria.exportar_csv', 'audit', 'auditoria.csv', 'sucesso', rows.length + ' registros');
                return true;
            }, 'Exportar');
        }
        // #endregion renderização de auditoria

        // #region relógio, tema, abas
        function formatDateTime(iso) {
            return new Date(iso).toLocaleString('pt-BR');
        }

        // Tabela de sessões: só HH:MM; a data completa aparece apenas quando não é de hoje.
        function horaCurta(iso) {
            const d = new Date(iso);
            if (isNaN(d)) return '—';
            const hora = d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
            return d.toLocaleDateString('en-CA') === new Date().toLocaleDateString('en-CA') ? hora : d.toLocaleDateString('pt-BR') + ' ' + hora;
        }

        // 2027-01-01 → 01/01/2027 (outros formatos passam como estão)
        function dataBR(ymd) {
            const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(ymd || ''));
            return m ? m[3] + '/' + m[2] + '/' + m[1] : String(ymd || '');
        }

        function formatElapsed(min) {
            return min < 60 ? min + ' min' : Math.floor(min / 60) + 'h' + String(min % 60).padStart(2, '0');
        }

        function tempoCell(s) {
            if (s.saidaFull) return '<td>' + formatElapsed(Math.floor((new Date(s.saidaFull) - new Date(s.entradaFull)) / 60000)) + '</td>';
            if (s.status === 'Inativo') return '<td>-</td>';
            return '<td class="tempo-uso" data-entrada="' + s.entradaFull + '" data-ativo="' + (s.status === 'Ativo') + '"></td>';
        }

        function updateElapsed() {
            document.querySelectorAll('.tempo-uso[data-entrada]').forEach(function (td) {
                const min = Math.floor((Date.now() - new Date(td.dataset.entrada)) / 60000);
                td.textContent = formatElapsed(min);
                td.classList.toggle('tempo-excedido', td.dataset.ativo === 'true' && min >= LIMITE_USO_MIN);
            });
        }

        function noteExpired(n) {
            return !!n.expira && n.expira < new Date().toLocaleDateString('en-CA');
        }

        function updateClock() {
            const now = new Date();
            const timeOptions = { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
            const dateOptions = { day: '2-digit', month: 'long', year: 'numeric' };
            document.getElementById('clock-time').innerText = now.toLocaleTimeString('pt-BR', timeOptions);
            document.getElementById('clock-date').innerText = now.toLocaleDateString('pt-BR', dateOptions);
        }

        function initTheme() {
            const savedTheme = localStorage.getItem('bpa_theme') || 'light';
            if (savedTheme === 'dark') {
                document.body.classList.add('dark-mode');
                document.getElementById('theme-toggle').checked = true;
            }
        }

        function toggleTheme() {
            const isDark = document.getElementById('theme-toggle').checked;
            document.body.classList.toggle('dark-mode', isDark);
            localStorage.setItem('bpa_theme', isDark ? 'dark' : 'light');
        }

        function openTabById(tabId) {
            const contents = document.getElementsByClassName('tab-content');
            for (let i = 0; i < contents.length; i++) contents[i].classList.remove('active');
            const btns = document.getElementsByClassName('tab-btn');
            for (let i = 0; i < btns.length; i++) {
                btns[i].classList.toggle('active', btns[i].dataset.arg === tabId);
            }
            const target = document.getElementById(tabId);
            if (target) target.classList.add('active');

            if (tabId === 'tab-graficos') {
                if (chartsUnavailable && !chartsWarned) {
                    chartsWarned = true;
                    showToast('Gráficos indisponíveis: a biblioteca de gráficos não carregou (sem internet?). Relatórios CSV continuam disponíveis.', 'error');
                }
                updateCharts(); updateMetrics();
            }
            if (tabId === 'tab-cadastros') filterRegistrationList();
            if (tabId === 'tab-geral') { filterUsers(); renderUrgentNotes(); }
            if (tabId === 'tab-seguranca') { renderAuditTable(); loadBackupStatus(); }
        }
        // #endregion relógio, tema, abas

        // #region categorias e cadastro de usuários
        function calculateCategory(birthDate) {
            if (typeof birthDate !== 'string') return 'Adulto';
            const today = new Date();
            const parts = birthDate.split('-').map(Number);
            const birth = new Date(parts[0], parts[1] - 1, parts[2]);
            let age = today.getFullYear() - birth.getFullYear();
            const m = today.getMonth() - birth.getMonth();
            if (m < 0 || (m === 0 && today.getDate() < birth.getDate())) age--;
            // Infantil até 14 (pedido: 5–14; 0–4 também fica Infantil) · Jovem 15–17 · Adulto 18+
            if (age <= 14) return 'Infantil';
            return age < 18 ? 'Jovem' : 'Adulto';
        }

        function syncCategories() {
            userBase.forEach(function (u) { if (/^\d{4}-\d{2}-\d{2}$/.test(u.nascimento)) u.categoria = calculateCategory(u.nascimento); });
        }

        async function handlePermanentRegistration(e) {
            e.preventDefault();
            if (!requireSession()) return;
            const matricula = document.getElementById('reg-matricula').value.trim();
            const nome = document.getElementById('reg-nome').value;
            const nascimento = document.getElementById('reg-nascimento').value;
            const validade = document.getElementById('reg-validade').value;
            if (!/^[A-Za-z0-9]{1,5}$/.test(matricula)) {
                return showToast('Matrícula inválida! Use apenas letras e números, sem espaços (máximo 5 caracteres).');
            }
            const hoje = new Date().toLocaleDateString('en-CA');
            if (nascimento >= hoje) return showToast('Data de nascimento inválida! Deve ser anterior a hoje.');
            if (validade < hoje) return showToast('Validade inválida! A validade não pode estar no passado.');
            if (userBase.some(function (u) { return String(u.matricula).trim().toLowerCase() === matricula.toLowerCase(); })) {
                return showToast('Esta matrícula já está cadastrada!');
            }
            const newUser = {
                id: Date.now(),
                matricula: matricula,
                nome: nome,
                nascimento: nascimento,
                categoria: calculateCategory(nascimento),
                validade: validade
            };
            userBase.push(newUser);
            if (!await persistOrWarn('bpa_user_base', userBase)) { userBase.pop(); return; }
            await logAudit('usuario.criar', 'user', String(newUser.id), 'sucesso', 'matricula=' + matricula);
            renderRegistrationList();
            e.target.reset();
            showToast('Usuário cadastrado com sucesso na base!', 'success');
        }

        function renderRegistrationList(filter) {
            const list = document.getElementById('registration-list');
            if (!list) return;
            filter = filter || '';
            syncCategories();
            const filteredBase = userBase.filter(function (u) {
                return u.nome.toLowerCase().includes(filter.toLowerCase()) ||
                    u.matricula.toLowerCase().includes(filter.toLowerCase());
            });
            const w = syncTablePage('registration', JSON.stringify([filter]), filteredBase.length);
            list.innerHTML = '';
            filteredBase.slice(w.from, w.to).forEach(function (u) {
                const row = document.createElement('tr');
                row.innerHTML = '<td>' + escapeHTML(u.matricula) + '</td><td>' + escapeHTML(u.nome) + '</td><td>' + u.nascimento + '</td><td>' + u.categoria + '</td><td>' + u.validade + '</td>' +
                    '<td><button class="action-btn btn-status" data-click="editUser" data-id="' + u.id + '">Editar</button>' +
                    '<button class="action-btn btn-edit" data-click="deleteUser" data-id="' + u.id + '">Excluir</button>' +
                    '<button class="action-btn btn-lgpd" title="Atender exclusão de titular (LGPD)" data-click="requestLgpdDeletion" data-id="' + u.id + '">Exclusão LGPD</button></td>';
                list.appendChild(row);
            });
            renderPager('registration-pager', 'registration', filteredBase.length, function () { renderRegistrationList(filter); });
        }

        function filterRegistrationList() {
            const term = document.getElementById('reg-search-input').value;
            renderRegistrationList(term);
        }

        function editUser(id) {
            if (!requireSession()) return;
            const user = userBase.find(function (u) { return u.id === id; });
            if (!user) return;
            const nome = el('input', { type: 'text', id: 'edit-nome' }); nome.value = user.nome;
            const nasc = el('input', { type: 'date', id: 'edit-nascimento' }); nasc.value = user.nascimento;
            const val = el('input', { type: 'date', id: 'edit-validade' }); val.value = user.validade;
            openModal('Editar cadastro',
                el('div', {},
                    formGroup('Nome completo:', nome),
                    formGroup('Data de nascimento:', nasc),
                    formGroup('Validade da matrícula:', val)
                ),
                async function () {
                    const nNome = nome.value;
                    const nNasc = nasc.value;
                    const nVal = val.value;
                    const dataValida = function (d) {
                        if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
                        const p = d.split('-').map(Number);
                        const dt = new Date(p[0], p[1] - 1, p[2]);
                        return dt.getFullYear() === p[0] && dt.getMonth() === p[1] - 1 && dt.getDate() === p[2];
                    };
                    if (!nNome.trim() || !dataValida(nNasc) || !dataValida(nVal)) {
                        showToast('Dados inválidos! Informe o nome e datas válidas.');
                        return false;
                    }
                    const hoje = new Date().toLocaleDateString('en-CA');
                    if (nNasc !== user.nascimento && nNasc >= hoje) {
                        showToast('Data de nascimento inválida! Deve ser anterior a hoje.');
                        return false;
                    }
                    if (nVal !== user.validade && nVal < hoje) {
                        showToast('Validade inválida! A validade não pode estar no passado.');
                        return false;
                    }
                    user.nome = nNome.trim();
                    user.nascimento = nNasc;
                    user.validade = nVal;
                    user.categoria = calculateCategory(nNasc);
                    if (!await persistOrWarn('bpa_user_base', userBase)) return false;
                    await logAudit('usuario.editar', 'user', String(user.id), 'sucesso', '');
                    renderRegistrationList(document.getElementById('reg-search-input') ? document.getElementById('reg-search-input').value : '');
                    filterUsers();
                    showToast('Cadastro atualizado.', 'success');
                    return true;
                }, 'Salvar');
        }

        function deleteUser(id) {
            if (!requireSession()) return;
            if (sessions.some(function (s) { return s.userId === id && (s.status === 'Ativo' || s.status === 'Suspenso'); })) {
                return showToast('Não é possível excluir: o usuário possui sessão ativa ou suspensa. Encerre a sessão (status Inativo) antes de excluir.');
            }
            askConfirm('Deseja excluir este usuário da base de dados?', async function () {
                userBase = userBase.filter(function (u) { return u.id !== id; });
                if (!await persistOrWarn('bpa_user_base', userBase)) return false;
                await logAudit('usuario.excluir', 'user', String(id), 'sucesso', '');
                renderRegistrationList(document.getElementById('reg-search-input') ? document.getElementById('reg-search-input').value : '');
                return true;
            });
        }
        // #endregion categorias e cadastro de usuários
        // #region fluxo de acesso e sessões
        async function handleAccessRequest(e) {
            e.preventDefault();
            if (!requireSession()) return;
            const matricula = document.getElementById('access-identifier').value.trim().toLowerCase();
            const pc = document.getElementById('access-pc').value;
            const pcNum = parseInt(pc);
            if (pcNum < 1 || pcNum > 28 || isNaN(pcNum)) {
                return showToast('Por favor, insira um número de computador válido entre 1 e 28.');
            }
            const user = userBase.find(function (u) { return String(u.matricula).trim().toLowerCase() === matricula; });
            if (!user) {
                return showToast('Matrícula não encontrada! Por favor, cadastre o usuário primeiro na aba Cadastros.');
            }
            const hoje = new Date().toLocaleDateString('en-CA');
            if (user.validade && user.validade < hoje) {
                return showToast('A matrícula de ' + user.nome + ' está vencida (validade: ' + user.validade + '). Entrada não permitida.');
            }
            if (sessions.some(function (s) { return s.userId === user.id && s.status === 'Suspenso'; })) {
                return showToast(user.nome + ' está suspenso(a). Entrada não permitida.');
            }
            const activeSession = sessions.find(function (s) { return s.userId === user.id && s.status === 'Ativo'; });
            if (activeSession) {
                return showToast('Este usuário já possui uma sessão ativa no PC ' + activeSession.pc + '.');
            }
            const pcOcupado = sessions.find(function (s) { return parseInt(s.pc) === pcNum && s.status === 'Ativo'; });
            if (pcOcupado) {
                return showToast('O PC ' + pcNum + ' já está em uso por outro usuário.');
            }
            const newSession = {
                sessionId: Date.now(),
                userId: user.id,
                pc: pcNum,
                status: 'Ativo',
                entrada: new Date().toLocaleTimeString('pt-BR'),
                entradaFull: new Date().toISOString(),
                saida: '-'
            };
            sessions.push(newSession);
            if (!await persistOrWarn('bpa_sessions', sessions)) { sessions = sessions.filter(function (s) { return s !== newSession; }); return; }
            await logAudit('sessao.entrada', 'session', String(newSession.sessionId), 'sucesso', 'pc=' + pcNum + '; user=' + user.id);
            renderUsers();
            updateMetrics();
            e.target.reset();
            showToast('Entrada registrada! ' + user.nome + ' agora está no PC ' + pc + '.', 'success');
        }

        function renderUsers(filter) {
            const list = document.getElementById('users-list');
            if (!list) return;
            filter = filter || '';
            const statusFilter = document.getElementById('filter-status').value;
            const catFilter = document.getElementById('filter-cat').value;
            const showAll = document.getElementById('filter-hist').checked;
            const hojeLocal = new Date().toLocaleDateString('en-CA');
            syncCategories();
            const idx = buildRenderIndex();   // índice leve O(S+U) — ver região "paginação de tabelas"
            const sessionData = sessions.map(function (s) {
                const user = idx.usuarios.get(s.userId) || { nome: 'Excluído', matricula: 'N/A', categoria: 'N/A', validade: 'N/A' };
                return Object.assign({}, s, user);
            });
            const filteredSessions = sessionData.filter(function (s) {
                const matchSearch = s.nome.toLowerCase().includes(filter.toLowerCase()) || s.matricula.includes(filter);
                const matchStatus = statusFilter === 'todos' || s.status === statusFilter;
                const matchCat = catFilter === 'todos' || s.categoria === catFilter;
                const matchDia = showAll || s.status !== 'Inativo' || new Date(s.entradaFull).toLocaleDateString('en-CA') === hojeLocal;
                return matchSearch && matchStatus && matchCat && matchDia;
            });
            const ordemStatus = { 'Ativo': 0, 'Suspenso': 1, 'Inativo': 2 };
            filteredSessions.sort(function (a, b) {
                return (ordemStatus[a.status] - ordemStatus[b.status]) || ((idx.epoch.get(b.sessionId) || 0) - (idx.epoch.get(a.sessionId) || 0));
            });
            // filtros na assinatura: mudou busca/status/categoria/histórico → página 1
            const w = syncTablePage('users', JSON.stringify([filter, statusFilter, catFilter, showAll]), filteredSessions.length);
            const today = new Date().toISOString().split('T')[0];
            // Layout C: bloco "No computador agora" (Ativo/Suspenso) em cima, "Saíram hoje" (Inativo) embaixo.
            // A ordenação já agrupa por status, então cada bloco é contíguo; o cabeçalho do bloco
            // aparece em toda página onde o bloco tem linhas, com a contagem do total filtrado.
            let qtdAgora = 0;
            filteredSessions.forEach(function (s) { if (s.status !== 'Inativo') qtdAgora++; });
            const grupos = {
                agora: '<span class="ponto">●</span> No computador agora (' + qtdAgora + ')',
                sairam: (showAll ? 'Já saíram' : 'Saíram hoje') + ' (' + (filteredSessions.length - qtdAgora) + ')'
            };
            let grupoAtual = null;
            list.innerHTML = '';
            filteredSessions.slice(w.from, w.to).forEach(function (s) {
                const noComputador = s.status !== 'Inativo';
                const grupo = noComputador ? 'agora' : 'sairam';
                if (grupo !== grupoAtual) {
                    grupoAtual = grupo;
                    const cab = document.createElement('tr');
                    cab.className = 'grupo-sessoes';
                    cab.innerHTML = '<td colspan="7">' + grupos[grupo] + '</td>';
                    list.appendChild(cab);
                }
                const isExpired = s.validade && s.validade < today;
                const statusColors = {
                    'Ativo': { bg: '#d4edda', text: '#155724' },
                    'Suspenso': { bg: '#fff3cd', text: '#856404' },
                    'Inativo': { bg: '#f8d7da', text: '#721c24' }
                };
                const color = statusColors[s.status] || { bg: '#ccc', text: '#333' };
                const acoes = s.status === 'Inativo'
                    ? '<button class="action-btn btn-status" data-click="openReentryModal" data-id="' + s.sessionId + '">Reentrada</button>'
                    : '<button class="action-btn btn-status" data-click="toggleSessionStatus" data-id="' + s.sessionId + '" data-arg="Inativo">Registrar saída</button>' +
                      '<button class="action-btn btn-mais" title="Suspender / mudar status" aria-label="Suspender ou mudar status" data-click="openStatusModal" data-id="' + s.sessionId + '">⋯</button>';
                const sub = 'Matrícula ' + escapeHTML(s.matricula) + ' · ' + escapeHTML(s.categoria) +
                    (noComputador ? ' · válida até ' + escapeHTML(dataBR(s.validade)) : '');
                const row = document.createElement('tr');
                row.dataset.sessionId = String(s.sessionId);
                if (isExpired) row.classList.add('expired-row');
                row.innerHTML = '<td>' + escapeHTML(s.nome) + (isExpired ? ' ⚠️' : '') + '<span class="linha-sub">' + sub + '</span></td><td>' + s.pc + '</td>' +
                    '<td>' + horaCurta(s.entradaFull) + '</td>' +
                    '<td>' + (s.saidaFull ? horaCurta(s.saidaFull) : (s.saida && s.saida !== '-' ? escapeHTML(s.saida) : '—')) + '</td>' +
                    tempoCell(s) +
                    '<td><span class="status-badge" style="background-color: ' + color.bg + '; color: ' + color.text + '; font-weight: bold;">' + s.status + '</span></td>' +
                    '<td>' + acoes + '</td>';
                list.appendChild(row);
            });
            renderPager('users-pager', 'users', filteredSessions.length, function () { renderUsers(filter); });
            updateElapsed();
            renderPCDashboard(idx);
        }

        function renderPCDashboard(idx) {
            const grid = document.getElementById('pc-dashboard');
            const summary = document.getElementById('pc-summary');
            if (!grid || !summary) return;
            idx = idx || buildRenderIndex();   // índice leve: 1 passe em vez de 2×find por PC
            const TOTAL_PCS = 28;
            let livres = 0, emUso = 0, suspensos = 0;
            grid.innerHTML = '';
            for (let pc = 1; pc <= TOTAL_PCS; pc++) {
                const session = idx.pcs.get(pc);                 // Ativo (preferido) ou Suspenso
                const ativa = session && session.status === 'Ativo' ? session : null;
                const user = session && idx.usuarios.get(session.userId);
                const nome = user ? String(user.nome).trim() : '';
                const tile = document.createElement('div');
                tile.className = 'pc-tile' + (ativa ? ' occupied' : (session ? ' suspended' : ''));
                tile.setAttribute('role', 'listitem');
                const numero = document.createElement('strong');
                numero.textContent = pc;
                tile.appendChild(numero);
                let descricao = 'livre';
                if (session) {
                    const primeiroNome = document.createElement('small');
                    primeiroNome.textContent = nome.split(/\s+/)[0] || 'Usuário';
                    tile.appendChild(primeiroNome);
                    const quem = (nome || 'usuário') + ' (mat. ' + (user ? user.matricula : '-') + ')';
                    const desde = session.entradaFull ? ' desde ' + new Date(session.entradaFull).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }) : '';
                    descricao = ativa ? 'em uso por ' + quem + desde : 'sessão suspensa de ' + quem;
                }
                const texto = 'Computador ' + pc + ': ' + descricao;
                tile.title = texto;
                tile.setAttribute('aria-label', texto);
                grid.appendChild(tile);
                if (ativa) emUso++; else if (session) suspensos++; else livres++;
            }
            summary.innerHTML = '';
            [['free', livres, livres === 1 ? 'livre' : 'livres'], ['occupied', emUso, 'em uso'], ['suspended', suspensos, suspensos === 1 ? 'suspenso' : 'suspensos']].forEach(function (item) {
                if (item[0] === 'suspended' && item[1] === 0) return;
                const span = document.createElement('span');
                span.className = 'pc-count ' + item[0];
                span.textContent = item[1] + ' ' + item[2];
                summary.appendChild(span);
            });
        }

        function filterUsers() {
            const term = document.getElementById('search-input').value;
            renderUsers(term);
        }

        async function toggleSessionStatus(sessionId, selectedStatus) {
            if (!requireSession()) return;
            const session = sessions.find(function (s) { return s.sessionId === sessionId; });
            if (!session) return;
            if (['Ativo', 'Suspenso', 'Inativo'].indexOf(selectedStatus) === -1) return;
            if (session.status === 'Inativo') {
                showToast('Esta sessão já foi encerrada. Registre uma nova entrada na aba Geral.');
                return filterUsers();
            }
            if (selectedStatus === session.status) return;
            if (selectedStatus === 'Ativo' && sessions.some(function (s) { return s.sessionId !== session.sessionId && parseInt(s.pc) === parseInt(session.pc) && s.status === 'Ativo'; })) {
                showToast('O PC ' + session.pc + ' já está em uso por outro usuário.');
                return filterUsers();
            }
            session.status = selectedStatus;
            if (session.status === 'Inativo') {
                session.saida = new Date().toLocaleTimeString('pt-BR');
                session.saidaFull = new Date().toISOString();
            }
            if (!await persistOrWarn('bpa_sessions', sessions)) return filterUsers();
            await logAudit('sessao.status', 'session', String(sessionId), 'sucesso', 'status=' + selectedStatus);
            filterUsers();
            updateMetrics();
        }

        async function registerReentry(originalSessionId, pcNum) {
            const original = sessions.find(function (s) { return s.sessionId === originalSessionId; });
            if (!original || original.status !== 'Inativo') {
                return { ok: false, message: 'Esta sessão não está encerrada. A reentrada só está disponível para sessões com status Inativo.' };
            }
            const user = userBase.find(function (u) { return u.id === original.userId; });
            if (!user) return { ok: false, message: 'Usuário não encontrado na base de cadastros.' };
            const hoje = new Date().toLocaleDateString('en-CA');
            if (user.validade && user.validade < hoje) {
                return { ok: false, message: 'A matrícula de ' + user.nome + ' está vencida (validade: ' + user.validade + '). Reentrada não permitida.' };
            }
            if (sessions.some(function (s) { return s.userId === user.id && s.status === 'Suspenso'; })) {
                return { ok: false, message: user.nome + ' já possui uma sessão suspensa. Reative ou encerre essa sessão antes de registrar a reentrada.' };
            }
            if (sessions.some(function (s) { return s.userId === user.id && s.status === 'Ativo'; })) {
                return { ok: false, message: user.nome + ' já possui uma sessão ativa. Reentrada não permitida.' };
            }
            const pc = parseInt(pcNum);
            if (isNaN(pc) || pc < 1 || pc > 28) {
                return { ok: false, message: 'Selecione um computador válido (entre 1 e 28).' };
            }
            const pcOcupado = sessions.find(function (s) { return parseInt(s.pc) === pc && (s.status === 'Ativo' || s.status === 'Suspenso'); });
            if (pcOcupado) {
                return { ok: false, message: 'O PC ' + pc + ' já está ocupado (sessão ' + pcOcupado.status + '). Escolha outro computador.' };
            }
            let novoId = Date.now();
            while (sessions.some(function (s) { return s.sessionId === novoId; })) novoId++;
            const agora = new Date();
            const novaSessao = {
                sessionId: novoId,
                userId: user.id,
                pc: pc,
                status: 'Ativo',
                entrada: agora.toLocaleTimeString('pt-BR'),
                entradaFull: agora.toISOString(),
                saida: '-'
            };
            sessions.push(novaSessao);
            if (!await persistOrWarn('bpa_sessions', sessions)) {
                sessions = sessions.filter(function (s) { return s !== novaSessao; });
                return { ok: false, message: 'Falha ao salvar a reentrada. A operação não foi concluída; tente novamente.' };
            }
            await logAudit('sessao.reentrada', 'session', String(novoId), 'sucesso', 'pc=' + pc);
            filterUsers();
            updateMetrics();
            return { ok: true, message: 'Reentrada registrada com sucesso! ' + user.nome + ' retornou e está no PC ' + pc + '.' };
        }

        function openReentryModal(sessionId) {
            if (!requireSession()) return;
            const original = sessions.find(function (s) { return s.sessionId === sessionId; });
            if (!original || original.status !== 'Inativo') {
                return showToast('Esta sessão não está encerrada. A reentrada só está disponível para sessões com status Inativo.');
            }
            const user = userBase.find(function (u) { return u.id === original.userId; });
            if (!user) return showToast('Usuário não encontrado na base de cadastros.');
            const livres = [];
            for (let pc = 1; pc <= 28; pc++) {
                if (!sessions.some(function (s) { return parseInt(s.pc) === pc && (s.status === 'Ativo' || s.status === 'Suspenso'); })) livres.push(pc);
            }
            if (livres.length === 0) return showToast('Nenhum computador disponível no momento.');
            const nomeRO = el('input', { type: 'text', readonly: '' }); nomeRO.value = user.nome;
            const matRO = el('input', { type: 'text', readonly: '' }); matRO.value = user.matricula;
            const sel = el('select', { id: 'reentrada-pc' });
            sel.appendChild(el('option', { value: '' }, 'Selecione o computador...'));
            livres.forEach(function (pc) { sel.appendChild(el('option', { value: String(pc) }, 'PC ' + pc)); });
            const horaDiv = el('div', { id: 'reentrada-hora', class: 'reentrada-hora' });
            horaDiv.textContent = new Date().toLocaleString('pt-BR');
            openModal('Registrar Reentrada',
                el('div', {},
                    formGroup('Usuário:', nomeRO),
                    formGroup('Matrícula:', matRO),
                    formGroup('Computador disponível:', sel),
                    formGroup('Data e hora do registro:', horaDiv)
                ),
                async function () {
                    const resultado = await registerReentry(sessionId, sel.value);
                    showToast(resultado.message, resultado.ok ? 'success' : 'error');
                    return resultado.ok;
                }, 'Confirmar reentrada');
            const timer = setInterval(function () {
                const elH = document.getElementById('reentrada-hora');
                if (!elH) return clearInterval(timer);
                elH.textContent = new Date().toLocaleString('pt-BR');
            }, 1000);
        }

        // Botão "⋯" da tabela de sessões: suspende (Ativo) ou reativa (Suspenso) — a saída tem botão próprio.
        function openStatusModal(sessionId) {
            if (!requireSession()) return;
            const session = sessions.find(function (s) { return s.sessionId === sessionId; });
            if (!session || session.status === 'Inativo') return filterUsers();
            const user = userBase.find(function (u) { return u.id === session.userId; });
            const quem = (user ? user.nome : 'Usuário') + ' (PC ' + session.pc + ')';
            const novo = session.status === 'Ativo' ? 'Suspenso' : 'Ativo';
            openModal(novo === 'Suspenso' ? 'Suspender sessão' : 'Reativar sessão',
                novo === 'Suspenso'
                    ? 'Suspender a sessão de ' + quem + '? O computador continua reservado.'
                    : 'Reativar a sessão de ' + quem + '?',
                async function () { await toggleSessionStatus(sessionId, novo); },
                novo === 'Suspenso' ? 'Suspender' : 'Reativar');
        }
        // #region fluxo de acesso e sessões
        // #region exportações CSV
        function csvField(value) {
            return '"' + String(value).replace(/"/g, '""') + '"';
        }

        function downloadCSV(fileName, lines) {
            const blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.setAttribute('href', url);
            link.setAttribute('download', fileName);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        }

        function exportUsersCSV() {
            if (!requireSession()) return;
            if (userBase.length === 0) return showToast('Não há usuários cadastrados!');
            askConfirm('Este arquivo conterá DADOS PESSOAIS em CLARO (nome, nascimento, matrícula). Exportar mesmo assim?', async function () {
                syncCategories();
                const lines = ['ID;Matricula;Nome;Nascimento;Categoria;Validade'];
                userBase.forEach(function (u) {
                    lines.push([u.id, u.matricula, u.nome, u.nascimento, u.categoria, u.validade].map(csvField).join(';'));
                });
                downloadCSV('base_usuarios.csv', lines);
                await logAudit('csv.exportar_base', 'export', 'base_usuarios.csv', 'sucesso', userBase.length + ' registros');
                return true;
            }, 'Exportar');
        }

        function exportSessionsCSV() {
            if (!requireSession()) return;
            if (sessions.length === 0) return showToast('Não há sessões registradas!');
            askConfirm('Este arquivo conterá dados de uso vinculados a cidadãos em CLARO. Exportar mesmo assim?', async function () {
                syncCategories();
                const lines = ['ID Sessao;Matricula;Nome;Categoria;PC;Status;Entrada;Saida;Duracao (min)'];
                sessions.forEach(function (s) {
                    const user = userBase.find(function (u) { return u.id === s.userId; }) || { nome: 'Excluído', matricula: 'N/A', categoria: 'N/A' };
                    const entrada = new Date(s.entradaFull).toLocaleString('pt-BR');
                    const saida = s.saidaFull ? new Date(s.saidaFull).toLocaleString('pt-BR') : s.saida;
                    const duracao = s.saidaFull ? Math.round((new Date(s.saidaFull) - new Date(s.entradaFull)) / 60000) : '';
                    lines.push([s.sessionId, user.matricula, user.nome, user.categoria, s.pc, s.status, entrada, saida, duracao].map(csvField).join(';'));
                });
                downloadCSV('sessoes.csv', lines);
                await logAudit('csv.exportar_sessoes', 'export', 'sessoes.csv', 'sucesso', sessions.length + ' registros');
                return true;
            }, 'Exportar');
        }
        // #endregion exportações CSV

        // #region avisos (notes)
        async function addNote() {
            if (!requireSession()) return;
            const title = document.getElementById('note-title').value;
            const text = document.getElementById('note-text').value;
            const category = document.getElementById('note-category').value;
            if (!title || !text) return showToast('Preencha título e conteúdo!');
            const expira = document.getElementById('note-expire').value;
            const newNote = { id: Date.now(), title: title, text: text, category: category, expira: expira, date: new Date().toLocaleDateString('pt-BR') };
            notes.push(newNote);
            if (!await persistOrWarn('bpa_notes_v2', notes)) { notes = notes.filter(function (n) { return n !== newNote; }); return; }
            await logAudit('aviso.criar', 'note', String(newNote.id), 'sucesso', 'categoria=' + category);
            document.getElementById('note-title').value = '';
            document.getElementById('note-text').value = '';
            document.getElementById('note-category').value = 'Geral';
            document.getElementById('note-expire').value = '';
            renderNotes();
        }

        function deleteNote(id) {
            if (!requireSession()) return;
            askConfirm('Excluir este aviso?', async function () {
                notes = notes.filter(function (n) { return n.id !== id; });
                if (!await persistOrWarn('bpa_notes_v2', notes)) return false;
                await logAudit('aviso.excluir', 'note', String(id), 'sucesso', '');
                renderNotes();
                return true;
            });
        }

        function renderNotes() {
            const grid = document.getElementById('notes-grid');
            if (!grid) return;
            grid.innerHTML = '';
            notes.forEach(function (n) {
                const card = document.createElement('div');
                card.className = 'note-card ' + (({ geral: 'general', urgente: 'urgent', informativo: 'info' })[String(n.category).toLowerCase()] || '');
                const deleteBtn = document.createElement('button');
                deleteBtn.className = 'note-delete';
                deleteBtn.innerHTML = '&times;';
                deleteBtn.setAttribute('aria-label', 'Excluir aviso');
                deleteBtn.addEventListener('click', function () { deleteNote(n.id); });
                const dateSpan = document.createElement('span');
                dateSpan.className = 'note-date';
                dateSpan.textContent = n.date + ' | ' + n.category + (noteExpired(n) ? ' | Expirado' : (n.expira ? ' | Válido até ' + n.expira.split('-').reverse().join('/') : ''));
                const h4 = document.createElement('h4'); h4.textContent = n.title;
                const p = document.createElement('p'); p.textContent = n.text;
                card.appendChild(deleteBtn);
                card.appendChild(dateSpan);
                card.appendChild(h4);
                card.appendChild(p);
                grid.appendChild(card);
            });
            renderUrgentNotes();
        }

        function renderUrgentNotes() {
            const box = document.getElementById('urgent-notes');
            if (!box) return;
            box.innerHTML = notes.filter(function (n) { return n.category === 'Urgente' && !noteExpired(n); })
                .map(function (n) { return '<div class="urgent-banner"><strong>' + escapeHTML(n.title) + '</strong> — ' + escapeHTML(n.text) + '</div>'; }).join('');
        }
        // #endregion avisos (notes)

        // #region gráficos e métricas
        function getFilteredSessions() {
            const start = document.getElementById('start-date').value;
            const end = document.getElementById('end-date').value;
            return sessions.filter(function (s) {
                const entrada = new Date(s.entradaFull);
                if (start && entrada < new Date(start + 'T00:00:00')) return false;
                if (end && entrada > new Date(end + 'T23:59:59.999')) return false;
                return true;
            });
        }

        function updateMetrics() {
            const totalEl = document.getElementById('total-accesses');
            const avgEl = document.getElementById('avg-time');
            if (!totalEl || !avgEl) return;
            const periodSessions = getFilteredSessions();
            totalEl.innerText = periodSessions.length;
            let totalMin = 0, count = 0;
            periodSessions.forEach(function (s) { if (s.saidaFull) { totalMin += (new Date(s.saidaFull) - new Date(s.entradaFull)) / 60000; count++; } });
            avgEl.innerText = count > 0 ? Math.round(totalMin / count) + ' min' : '0 min';
        }

        function initCharts() {
            if (typeof Chart === 'undefined') { chartsUnavailable = true; return; }
            try {
                const ctxPizza = document.getElementById('chartPizza').getContext('2d');
                const ctxBars = document.getElementById('chartBars').getContext('2d');
                const ctxDonut = document.getElementById('chartDonut').getContext('2d');
                const ctxHourly = document.getElementById('chartHourly').getContext('2d');
                charts.pizza = new Chart(ctxPizza, { type: 'pie', data: { labels: [], datasets: [{ data: [], backgroundColor: ['#3498db', '#e74c3c', '#f1c40f', '#2ecc71', '#9b59b6'] }] }, options: { responsive: true } });
                charts.bars = new Chart(ctxBars, { type: 'bar', data: { labels: [], datasets: [{ label: 'Acessos', data: [], backgroundColor: '#3498db' }] }, options: { responsive: true } });
                charts.donut = new Chart(ctxDonut, { type: 'doughnut', data: { labels: [], datasets: [{ data: [], backgroundColor: ['#27ae60', '#f39c12', '#c0392b'] }] }, options: { responsive: true } });
                charts.hourly = new Chart(ctxHourly, { type: 'bar', data: { labels: Array.from({ length: 24 }, function (_, i) { return i + 'h'; }), datasets: [{ label: 'Entradas', data: Array(24).fill(0), backgroundColor: '#9b59b6' }] }, options: { responsive: true } });
            } catch (err) {
                console.error('Falha ao iniciar gráficos:', err);
                chartsUnavailable = true;
            }
        }

        function updateCharts() {
            if (chartsUnavailable || !charts.pizza) return;
            syncCategories();
            const filteredData = getFilteredSessions().map(function (s) {
                const user = userBase.find(function (u) { return u.id === s.userId; }) || { categoria: 'N/A' };
                return Object.assign({}, s, user);
            });
            const catCounts = {};
            filteredData.forEach(function (u) { catCounts[u.categoria] = (catCounts[u.categoria] || 0) + 1; });
            charts.pizza.data.labels = Object.keys(catCounts);
            charts.pizza.data.datasets[0].data = Object.values(catCounts);
            charts.pizza.update();
            const pcCounts = {};
            filteredData.forEach(function (u) { pcCounts[parseInt(u.pc)] = (pcCounts[parseInt(u.pc)] || 0) + 1; });
            charts.bars.data.labels = Object.keys(pcCounts).map(function (pc) { return 'PC ' + pc; });
            charts.bars.data.datasets[0].data = Object.values(pcCounts);
            charts.bars.update();
            const statusCounts = {};
            filteredData.forEach(function (u) { statusCounts[u.status] = (statusCounts[u.status] || 0) + 1; });
            charts.donut.data.labels = Object.keys(statusCounts);
            charts.donut.data.datasets[0].data = Object.values(statusCounts);
            charts.donut.update();
            const hourCounts = Array(24).fill(0);
            filteredData.forEach(function (u) {
                const hour = parseInt(String(u.entrada).split(':')[0]);
                if (!isNaN(hour)) hourCounts[hour]++;
            });
            charts.hourly.data.datasets[0].data = hourCounts;
            charts.hourly.update();
            updateMetrics();
        }

        async function downloadChartPDF(containerId, title) {
            if (!requireSession()) return;
            if (!window.jspdf || typeof html2canvas === 'undefined') {
                return showToast('PDF indisponível (biblioteca offline). Use o CSV do relatório de gestão.', 'error');
            }
            const jsPDF = window.jspdf.jsPDF;
            const element = document.getElementById(containerId);
            try {
                const canvas = await html2canvas(element, {
                    backgroundColor: document.body.classList.contains('dark-mode') ? '#1e1e1e' : '#ffffff',
                    scale: 2
                });
                const imgData = canvas.toDataURL('image/png');
                const pdf = new jsPDF('p', 'mm', 'a4');
                const imgProps = pdf.getImageProperties(imgData);
                const pdfWidth = pdf.internal.pageSize.getWidth();
                const pdfHeight = (imgProps.height * pdfWidth) / imgProps.width;
                pdf.setFontSize(16);
                pdf.text(title, 10, 10);
                pdf.addImage(imgData, 'PNG', 10, 20, pdfWidth - 20, pdfHeight - 20);
                pdf.save(title.replace(/\s+/g, '_').toLowerCase() + '.pdf');
                await logAudit('pdf.gerar_grafico', 'export', title, 'sucesso', '');
            } catch (error) {
                console.error('Erro ao gerar PDF:', error);
                showToast('Erro ao gerar PDF.');
            }
        }
        // #endregion gráficos e métricas

        // #region paginação de tabelas + índice leve de sessões (Bloco 3)
        // As sessões são UM BLOB CIFRADO por chave no SQLite — não existe CREATE INDEX
        // possível sem normalizar em tabela relacional (fase de normalização do roadmap,
        // com replanejamento da camada de criptografia). Portanto:
        //   - a paginação é CLIENT-SIDE sobre o array decifrado (todas as tabelas);
        //   - o "índice leve" é uma estrutura em memória materializada a cada render,
        //     em passeio único O(sessões + usuários), substituindo os find aninhados
        //     O(S×U) e os Date.parse repetidos do sort — é o que viabiliza 15–35 mil
        //     sessões em 2 anos na mesma máquina, sem internet e sem backend.
        const PAGE_SIZE = { users: 25, registration: 50, audit: 50 };
        const tablePage = { users: 1, registration: 1, audit: 1 };
        const tableSig = { users: null, registration: null, audit: null };

        // Janela da página: clampa o cursor (dados podem encolher) e devolve o fatiamento.
        function pageWindow(page, total, size) {
            const pages = Math.max(1, Math.ceil(total / size));
            const p = Math.min(Math.max(1, page), pages);
            return { page: p, pages: pages, from: (p - 1) * size, to: Math.min(total, p * size) };
        }

        // Assinatura dos filtros: mudou filtro/busca → volta para a página 1;
        // sem mudança (ex.: re-render após status) → mantém a página do operador.
        function syncTablePage(key, sig, total) {
            if (sig !== tableSig[key]) { tablePage[key] = 1; tableSig[key] = sig; }
            const w = pageWindow(tablePage[key], total, PAGE_SIZE[key]);
            tablePage[key] = w.page;
            return w;
        }

        function renderPager(boxId, key, total, rerender) {
            const box = document.getElementById(boxId);
            if (!box) return;
            const w = pageWindow(tablePage[key], total, PAGE_SIZE[key]);
            tablePage[key] = w.page;
            box.innerHTML = '';
            if (total === 0) { box.hidden = true; return; }
            box.hidden = false;
            const prev = el('button', { type: 'button', class: 'btn-secondary', text: '◀ Anterior' });
            prev.disabled = w.page <= 1;
            prev.onclick = function () { if (w.page > 1) { tablePage[key] = w.page - 1; rerender(); } };
            const next = el('button', { type: 'button', class: 'btn-secondary', text: 'Próxima ▶' });
            next.disabled = w.page >= w.pages;
            next.onclick = function () { if (w.page < w.pages) { tablePage[key] = w.page + 1; rerender(); } };
            const info = el('span', { class: 'pager-info', text: (total === 0 ? 0 : w.from + 1) + '–' + w.to + ' de ' + total + ' · Página ' + w.page + ' de ' + w.pages });
            box.appendChild(prev);
            box.appendChild(info);
            box.appendChild(next);
        }

        // Índice leve: passeio único sobre userBase + sessions.
        //   usuarios: userId → cadastro (antes: userBase.find dentro do map = O(S×U))
        //   epoch:    sessionId → entradaFull em ms (antes: Date.parse a cada comparação do sort)
        //   pcs:      pc → sessão Ativo (preferido) ou Suspenso (antes: 2×find por PC por render)
        // Vive só na memória e é reconstruído a cada render — sempre consistente com o
        // array decifrado atual, sem risco de estado desatualizado entre mutações.
        function buildRenderIndex() {
            const usuarios = new Map();
            for (let i = 0; i < userBase.length; i++) usuarios.set(userBase[i].id, userBase[i]);
            const epoch = new Map();
            const pcs = new Map();
            for (let i = 0; i < sessions.length; i++) {
                const s = sessions[i];
                epoch.set(s.sessionId, Date.parse(s.entradaFull) || 0);
                const pc = parseInt(s.pc);
                if (s.status === 'Ativo') pcs.set(pc, s);
                else if (s.status === 'Suspenso' && !pcs.has(pc)) pcs.set(pc, s);
            }
            return { usuarios: usuarios, epoch: epoch, pcs: pcs };
        }
        // #endregion paginação de tabelas + índice leve de sessões

        // #region eventos (Bloco 5) — CSP sem 'unsafe-inline' proíbe handlers escritos no HTML (atributos on*).
        // Botões e campos declaram data-click / data-change / data-keyup="<ação>" (argumentos em
        // data-arg, data-arg2, data-id); um único ouvinte por tipo no document despacha para ACOES.
        // Lista fechada: nome que não está aqui é ignorado (nada de window[nome]).
        const ACOES = {
            openTab: function (el) { openTabById(el.dataset.arg); },
            exportUsersCSV: function () { exportUsersCSV(); },
            exportSessionsCSV: function () { exportSessionsCSV(); },
            filterUsers: function () { filterUsers(); },
            filterRegistrationList: function () { filterRegistrationList(); },
            exportBackup: function () { exportBackup(); },
            exportBackupPlain: function () { exportBackupPlain(); },
            abrirSeletorArquivo: function (el) { document.getElementById(el.dataset.arg).click(); },
            importBackup: function (el, evt) { importBackup(evt); },
            reimportArchive: function (el, evt) { reimportArchive(evt); },
            exportAuditCSV: function () { exportAuditCSV(); },
            renderAuditTable: function () { renderAuditTable(); },
            updateCharts: function () { updateCharts(); },
            downloadChartPDF: function (el) { downloadChartPDF(el.dataset.arg, el.dataset.arg2); },
            generateManagementReportCSV: function () { generateManagementReportCSV(); },
            generateManagementReportPDF: function () { generateManagementReportPDF(); },
            addNote: function () { addNote(); },
            editUser: function (el) { editUser(Number(el.dataset.id)); },
            deleteUser: function (el) { deleteUser(Number(el.dataset.id)); },
            requestLgpdDeletion: function (el) { requestLgpdDeletion(Number(el.dataset.id)); },
            openReentryModal: function (el) { openReentryModal(Number(el.dataset.id)); },
            toggleSessionStatus: function (el) { toggleSessionStatus(Number(el.dataset.id), el.dataset.arg); },
            openStatusModal: function (el) { openStatusModal(Number(el.dataset.id)); }
        };

        function despacharEvento(tipo, evt) {
            const el = evt.target && evt.target.closest ? evt.target.closest('[data-' + tipo + ']') : null;
            if (!el) return;
            const nome = el.dataset[tipo];
            if (Object.prototype.hasOwnProperty.call(ACOES, nome)) return ACOES[nome](el, evt);
        }

        function ligarEventos() {
            ['click', 'change', 'keyup'].forEach(function (tipo) {
                document.addEventListener(tipo, function (evt) { despacharEvento(tipo, evt); });
            });
        }
        // #endregion eventos (Bloco 5)

        // #region render geral + bootstrap
        function renderAll() {
            renderUsers();
            renderRegistrationList(document.getElementById('reg-search-input') ? document.getElementById('reg-search-input').value : '');
            renderNotes();
            updateMetrics();
            updateSessionBar();
            renderAuditTable();
        }

        async function bootstrap() {
            let rawInstall = null, rawSystem = null;
            try {
                rawInstall = await rawGet('bpa_install');
                rawSystem = await rawGet('bpa_system');
            } catch (err) {
                // Servidor indisponível: NÃO cair no runFirstInstall (evita reinstalar por cima)
                installMeta = null;
                system = null;
                showLoginView();
                const setupBtn = document.getElementById('btn-show-setup');
                if (setupBtn) setupBtn.hidden = true;
                showToast('Banco de dados local indisponível — verifique o servidor no terminal e recarregue (F5).', 'error');
                return;
            }
            try { installMeta = JSON.parse(rawInstall || 'null'); }
            catch (_) { installMeta = null; }
            try { system = JSON.parse(rawSystem || 'null'); }
            catch (_) { system = null; }
            if (!system) await runFirstInstall();
            // Entrar direto: desbloqueio silencioso; tela de senha só se a senha foi trocada
            else if (!(await trySilentUnlock())) showLoginView();
        }

        function bindAuthForms() {
            document.getElementById('login-form').addEventListener('submit', async function (e) {
                e.preventDefault();
                const btn = document.getElementById('login-btn');
                const password = document.getElementById('login-password').value;
                btn.disabled = true;
                btn.textContent = 'Verificando...';
                try {
                    const r = await attemptLogin(password);
                    if (!r.ok) {
                        showToast(r.msg, 'error');
                        const lockMsg = document.getElementById('lock-msg');
                        if (lockMsg && r.msg.indexOf('bloqueado') !== -1) { lockMsg.hidden = false; lockMsg.textContent = r.msg; }
                        document.getElementById('login-password').value = '';
                        document.getElementById('login-password').focus();
                    } else {
                        document.getElementById('login-password').value = '';
                    }
                } catch (err) {
                    console.error(err);
                    showToast('Erro no login: ' + (err && err.message ? err.message : err), 'error');
                } finally {
                    btn.disabled = false;
                    btn.textContent = 'Entrar';
                }
            });

            document.getElementById('setup-form').addEventListener('submit', handleSetup);
            document.getElementById('recovery-form').addEventListener('submit', handleRecovery);

            document.getElementById('btn-show-setup').addEventListener('click', runFirstInstall);
            document.getElementById('btn-show-recovery').addEventListener('click', showRecoveryView);
            document.getElementById('btn-back-login').addEventListener('click', showLoginView);
            document.getElementById('btn-back-login2').addEventListener('click', showLoginView);
            document.getElementById('btn-privacy').addEventListener('click', openPrivacyNotice);
            document.getElementById('btn-privacy-login').addEventListener('click', openPrivacyNotice);
        }

        document.addEventListener('DOMContentLoaded', function () {
            initTheme();
            updateClock();
            setInterval(updateClock, 1000);
            setInterval(updateElapsed, 30000);
            bindAuthForms();
            bindActivity();
            bindServerWatch();
            ligarEventos();
            document.getElementById('user-registration-form').addEventListener('submit', handlePermanentRegistration);
            document.getElementById('access-form').addEventListener('submit', handleAccessRequest);
            document.getElementById('theme-toggle').addEventListener('change', toggleTheme);
            document.getElementById('btn-open-backups').addEventListener('click', openBackupFolder);
            initCharts();
            renderAll();
            bootstrap();
        });
        // #endregion render geral + bootstrap
    