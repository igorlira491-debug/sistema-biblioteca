
        /**
         * Sistema de Registro V4 — Biblioteca Pública Municipal
         * Bloco 1 (C1–C5): senha única do sistema, criptografia de PII
         * (envelope DEK/KEK), SRI+CSP, modal seguro, LGPD/auditoria.
         * Persistência via repositório sobre localStorage (backend-ready).
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
            AUDIT_CAP: 20000
        };
        const LIMITE_USO_MIN = CFG.LIMITE_USO_MIN;
        // Senha inicial pré-definida de fábrica. Recomenda-se trocar após o primeiro acesso (aba Segurança).
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

        // #region repositório (pattern Repository — LocalStorageRepo cifrado)
        function persistInstall() { localStorage.setItem('bpa_install', JSON.stringify(installMeta)); }
        function saveSystem() { localStorage.setItem('bpa_system', JSON.stringify(system)); }

        function quarantineKey(key, raw) {
            try {
                localStorage.setItem(key + '_corrompido', raw);
                localStorage.removeItem(key);
            } catch (_) { /* quota — melhor esforço */ }
        }

        async function repoGet(key, fallback) {
            const raw = localStorage.getItem(key);
            if (raw === null) return fallback;
            let parsed;
            try { parsed = JSON.parse(raw); } catch (_) { quarantineKey(key, raw); return fallback; }
            if (Array.isArray(parsed)) return parsed; // legado em claro (migra no login)
            if (parsed && typeof parsed === 'object' && parsed.iv && parsed.data) {
                if (!currentDek) return fallback;
                try {
                    return await decryptJSON(parsed, currentDek);
                } catch (_) {
                    quarantineKey(key, raw);
                    showToast('Dados de "' + key + '" não puderam ser decifrados. Cópia crua salva em "' + key + '_corrompido".', 'error');
                    return fallback;
                }
            }
            quarantineKey(key, raw);
            return fallback;
        }

        async function repoSet(key, value) {
            if (!currentDek) throw new Error('Sem chave de dados em memória (sessão encerrada?)');
            const envelope = await encryptJSON(value, currentDek);
            localStorage.setItem(key, JSON.stringify(envelope));
        }

        async function persistOrWarn(key, value) {
            try { await repoSet(key, value); return true; }
            catch (err) {
                showToast('Falha ao gravar dados: ' + (err && err.message ? err.message : err) + '. Exporte um backup e libere espaço.', 'error');
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
                const raw = localStorage.getItem(key);
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
        // Risco documentado no README; substituído por tabela server-side no backend.
        function logAuthFailure(username, reason) {
            try {
                const log = JSON.parse(localStorage.getItem('bpa_auth_log') || '[]');
                log.push({ at: new Date().toISOString(), username: String(username).slice(0, 40), reason: reason });
                localStorage.setItem('bpa_auth_log', JSON.stringify(log.slice(-100)));
            } catch (_) { /* ignorar */ }
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
            '<li>A auditoria em localStorage é <strong>editável</strong> por quem tiver acesso físico à máquina (não é à prova de adulteração).</li>' +
            '<li>Não há detecção de abuso remoto nem rate limiting de rede.</li>' +
            '<li>A autenticação é client-side e <strong>não resiste a acesso físico ao DevTools</strong>. Proteção real virá com o backend. Até lá: senha de SO obrigatória, bloqueio automático do SO em 5 min, backup diário.</li>' +
            '</ul>' +
            '<h4>7. Procedimento de handover (a cada 2 anos)</h4>' +
            '<ol>' +
            '<li>Exportar backup cifrado + relatório de gestão.</li>' +
            '<li>Trocar a senha única do sistema pelo canal seguro da empresa.</li>' +
            '<li>Entregar: nova senha, código de recuperação (impresso, em envelope) e o último backup cifrado.</li>' +
            '<li>Registrar a troca no controle externo da empresa.</li>' +
            '</ol>' +
            '<p style="font-size:0.8rem;opacity:0.8;">O controle de <strong>quem</strong> opera é feito externamente pela empresa. A senha do sistema protege os dados contra leitura via DevTools, mas não resiste a quem tem a senha e acesso físico. Proteção real virá com o backend.</p>' +
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
                    persistInstall();
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
        }

        function showLoginView() {
            showAuthOverlay();
            setAuthView('login');
            const setupBtn = document.getElementById('btn-show-setup');
            if (setupBtn) setupBtn.hidden = !!localStorage.getItem('bpa_system');
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
                    logout(null, true);
                }
            }, 15000);
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

        async function logout(msg, expired) {
            if (authSession && currentDek) {
                try { await logAudit(expired ? 'sessao.expirada' : 'logout', 'sistema', 'unlock', 'sucesso', ''); }
                catch (_) { /* melhor esforço */ }
            }
            currentDek = null;
            authSession = null;
            userBase = []; sessions = []; notes = []; auditLog = [];
            clearInterval(idleTimer); idleTimer = null;
            closeModal();
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
            persistInstall();
            const dek = await generateDek();
            const salt = randomB64(CFG.SALT_BYTES);
            const kek = await deriveAesKey(pass1, salt, installMeta.iterations);
            const rc = generateRecoveryCode();
            const rcKek = await deriveAesKey(rc, installMeta.installSalt, installMeta.iterations);
            system = {
                password: { salt: salt, iterations: installMeta.iterations, envelope: await wrapDek(dek, kek) },
                recovery: { envelope: await wrapDek(dek, rcKek) }
            };
            saveSystem();
            return { dek: dek, rc: rc };
        }

        // Primeira abertura: instalação AUTOMÁTICA com a senha pré-definida (sem tela de setup).
        async function runFirstInstall() {
            if (localStorage.getItem('bpa_user_base') && !localStorage.getItem('bpa_install')) {
                const ok = window.confirm('Há dados antigos nesta máquina. Se estiverem cifrados com uma senha perdida, ficarão irrecuperáveis após a nova configuração. Deseja continuar?');
                if (!ok) { showSetupView(); return; }
            }
            try {
                const result = await createSystem(SENHA_PADRAO);
                await unlockSystem(result.dek, 'setup_inicial');
                openRecoveryCodeModal(result.rc, function () {
                    showToast('Sistema configurado com a senha inicial ' + SENHA_PADRAO + '. Recomenda-se trocá-la na aba Segurança. Guarde o código de recuperação!', 'success');
                });
            } catch (err) {
                console.error(err);
                showToast('Falha na configuração inicial automática. Defina a senha manualmente.', 'error');
                showSetupView();
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
            const pass1 = document.getElementById('rec-password').value;
            const pass2 = document.getElementById('rec-password2').value;
            if (!installMeta) return showToast('Metadados de instalação ausentes.', 'error');
            if (code.length !== 16) return showToast('O código de recuperação tem 16 caracteres.', 'error');
            if (!validPassword(pass1)) return showToast('A nova senha deve ter no mínimo 8 caracteres.', 'error');
            if (pass1 !== pass2) return showToast('As senhas não conferem.', 'error');
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
            const salt = randomB64(CFG.SALT_BYTES);
            const kek = await deriveAesKey(pass1, salt, installMeta.iterations);
            system.password = { salt: salt, iterations: installMeta.iterations, envelope: await wrapDek(dek, kek) };
            saveSystem();
            loginAttempts = 0;
            lockUntil = 0;
            await unlockSystem(dek, 'senha_resetada_recuperacao');
            document.getElementById('recovery-form').reset();
            showToast('Nova senha definida via código de recuperação.', 'success');
        }

        async function handleChangeSystemPassword(e) {
            e.preventDefault();
            if (!requireSession()) return;
            const cur = document.getElementById('sys-current').value;
            const n1 = document.getElementById('sys-new').value;
            const n2 = document.getElementById('sys-new2').value;
            if (!validPassword(n1)) return showToast('A nova senha deve ter no mínimo 8 caracteres.', 'error');
            if (n1 !== n2) return showToast('As senhas não conferem.', 'error');
            if (!system || !system.password || !system.password.envelope) return showToast('Registro do sistema indisponível.', 'error');
            try {
                const curKek = await deriveAesKey(cur, system.password.salt, system.password.iterations);
                await unwrapDek(system.password.envelope, curKek); // valida a senha atual (falha se errada)
            } catch (_) {
                return showToast('Senha atual incorreta.', 'error');
            }
            const salt = randomB64(CFG.SALT_BYTES);
            const kek = await deriveAesKey(n1, salt, installMeta.iterations);
            // DEK permanece a mesma — só o envelope é re-cifrado (dados NÃO são re-cifrados)
            system.password = { salt: salt, iterations: installMeta.iterations, envelope: await wrapDek(currentDek, kek) };
            saveSystem();
            await logAudit('senha.troca', 'sistema', 'password', 'sucesso', '');
            e.target.reset();
            showToast('Senha do sistema alterada com sucesso.', 'success');
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
            const p1 = el('input', { type: 'password', id: 'arch-pw', autocomplete: 'new-password' });
            const p2 = el('input', { type: 'password', id: 'arch-pw2', autocomplete: 'new-password' });
            openModal('Arquivamento de sessões antigas (12 meses)',
                el('div', {},
                    el('div', { class: 'warning-box' }, 'Há ' + oldSessions.length + ' sessão(ões) com mais de 12 meses no armazenamento ativo. Para não estourar a cota do navegador, elas serão exportadas para um arquivo CIFRADO (.json.enc) e removidas do localStorage ativo. Para reconsultar no futuro, use "Reimportar" quando esse recurso estiver disponível (Bloco 2).'),
                    formGroup('Senha de exportação do arquivo (mín. 8):', p1),
                    formGroup('Confirmar senha:', p2)
                ),
                async function () {
                    if (!validPassword(p1.value)) { showToast('A senha deve ter no mínimo 8 caracteres.', 'error'); return false; }
                    if (p1.value !== p2.value) { showToast('As senhas não conferem.', 'error'); return false; }
                    return await archiveOldSessions(oldSessions, p1.value);
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
                persistInstall();
                await logAudit('arquivo.gerado', 'arquivo', oldSessions.length, 'sucesso', oldSessions.length + ' sessões');
                renderAll();
                showToast(oldSessions.length + ' sessões arquivadas em arquivo cifrado e removidas do armazenamento ativo.', 'success');
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
            const p1 = el('input', { type: 'password', id: 'bk-pw', autocomplete: 'new-password' });
            const p2 = el('input', { type: 'password', id: 'bk-pw2', autocomplete:'new-password' });
            openModal('Exportar backup CIFRADO',
                el('div', {},
                    el('p', {}, 'O backup é cifrado com a chave do sistema e embrulhado com uma senha de exportação que você escolhe agora. Para restaurar, será preciso esta senha.'),
                    formGroup('Senha de exportação (mín. 8):', p1),
                    formGroup('Confirmar senha:', p2)
                ),
                async function () {
                    if (!validPassword(p1.value)) { showToast('A senha deve ter no mínimo 8 caracteres.', 'error'); return false; }
                    if (p1.value !== p2.value) { showToast('As senhas não conferem.', 'error'); return false; }
                    await doExportEncrypted(p1.value);
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
                persistInstall();
                await logAudit('backup.exportar_cifrado', 'backup', 'cifrado', 'sucesso', '');
                showToast('Backup cifrado exportado. Guarde a senha junto do arquivo.', 'success');
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
                            persistInstall();
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

        async function handleImportText(text, fname) {
            let data;
            try { data = JSON.parse(text); }
            catch (_) { return showToast('Arquivo inválido (JSON ilegível).'); }

            if (data && data.format === 'bpa-backup') {
                // Restauração completa: exige senha de exportação; troca instalação + registro de senha + dados; força novo login
                const pw = el('input', { type: 'password', id: 'imp-pw', autocomplete: 'off' });
                openModal('Importar backup cifrado',
                    el('div', {},
                        el('div', { class: 'warning-box' }, 'A importação SUBSTITUI todos os dados atuais (instalação, senha e dados) e exigirá novo desbloqueio com a senha restaurada.'),
                        formGroup('Senha de exportação usada na geração:', pw)
                    ),
                    async function () {
                        try {
                            const kek = await deriveAesKey(pw.value, data.kdf.salt, data.kdf.iterations);
                            const dek = await unwrapDek(data.dekWrapped, kek);
                            const payload = await decryptJSON(data.payload, dek);
                            const valido = payload && Array.isArray(payload.userBase) && Array.isArray(payload.sessions) && Array.isArray(payload.notes)
                                && data.system && data.system.password && data.system.password.envelope
                                && data.installMeta && typeof data.installMeta.installSalt === 'string';
                            if (!valido) throw new Error('estrutura inválida');
                            localStorage.setItem('bpa_install', JSON.stringify(data.installMeta));
                            localStorage.setItem('bpa_system', JSON.stringify(data.system));
                            installMeta = data.installMeta;
                            system = data.system;
                            currentDek = dek;
                            userBase = payload.userBase;
                            sessions = payload.sessions;
                            notes = payload.notes;
                            auditLog = Array.isArray(payload.audit) ? payload.audit : [];
                            await repoSet('bpa_user_base', userBase);
                            await repoSet('bpa_sessions', sessions);
                            await repoSet('bpa_notes_v2', notes);
                            await repoSet('bpa_audit_v1', auditLog);
                            await logAudit('backup.importar', 'backup', fname, 'sucesso', 'restauração completa');
                            renderAll();
                            await logout('Backup restaurado com sucesso. Entre novamente com as credenciais restauradas.');
                            return true;
                        } catch (err) {
                            showToast('Senha incorreta ou backup corrompido.', 'error');
                            return false;
                        }
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
                        userBase = data.userBase;
                        sessions = data.sessions;
                        notes = data.notes;
                        await repoSet('bpa_user_base', userBase);
                        await repoSet('bpa_sessions', sessions);
                        await repoSet('bpa_notes_v2', notes);
                        await logAudit('backup.importar', 'backup', fname, 'sucesso', 'legado em claro re-cifrado');
                        renderAll();
                        showToast('Backup legado importado e re-cifrado.', 'success');
                        return true;
                    }, 'Importar');
            } else {
                showToast('Formato de backup não reconhecido.');
            }
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
            const display = rows.slice(0, 200);
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
            const note = document.getElementById('audit-note');
            if (note) {
                note.textContent = 'Exibindo ' + display.length + ' de ' + rows.length + ' registro(s) — máx. 200 por consulta, use os filtros de período. O registro identifica AÇÕES, não pessoas (controle de operadores é externo).';
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

        function openTab(evt, tabId) {
            openTabById(tabId);
            if (evt && evt.currentTarget) evt.currentTarget.classList.add('active');
        }

        function openTabById(tabId) {
            const contents = document.getElementsByClassName('tab-content');
            for (let i = 0; i < contents.length; i++) contents[i].classList.remove('active');
            const btns = document.getElementsByClassName('tab-btn');
            for (let i = 0; i < btns.length; i++) {
                const onclick = btns[i].getAttribute('onclick') || '';
                btns[i].classList.toggle('active', onclick.indexOf(tabId) !== -1);
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
            if (tabId === 'tab-seguranca') { renderAuditTable(); }
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
            list.innerHTML = '';
            const filteredBase = userBase.filter(function (u) {
                return u.nome.toLowerCase().includes(filter.toLowerCase()) ||
                    u.matricula.toLowerCase().includes(filter.toLowerCase());
            });
            filteredBase.forEach(function (u) {
                const row = document.createElement('tr');
                row.innerHTML = '<td>' + escapeHTML(u.matricula) + '</td><td>' + escapeHTML(u.nome) + '</td><td>' + u.nascimento + '</td><td>' + u.categoria + '</td><td>' + u.validade + '</td>' +
                    '<td><button class="action-btn btn-status" onclick="editUser(' + u.id + ')">Editar</button>' +
                    '<button class="action-btn btn-edit" onclick="deleteUser(' + u.id + ')">Excluir</button>' +
                    '<button class="action-btn btn-lgpd" title="Atender exclusão de titular (LGPD)" onclick="requestLgpdDeletion(' + u.id + ')">Exclusão LGPD</button></td>';
                list.appendChild(row);
            });
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
            list.innerHTML = '';
            const sessionData = sessions.map(function (s) {
                const user = userBase.find(function (u) { return u.id === s.userId; }) || { nome: 'Excluído', matricula: 'N/A', categoria: 'N/A', validade: 'N/A' };
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
            filteredSessions.sort(function (a, b) { return (ordemStatus[a.status] - ordemStatus[b.status]) || (new Date(b.entradaFull) - new Date(a.entradaFull)); });
            const today = new Date().toISOString().split('T')[0];
            filteredSessions.forEach(function (s) {
                const isExpired = s.validade && s.validade < today;
                const statusColors = {
                    'Ativo': { bg: '#d4edda', text: '#155724' },
                    'Suspenso': { bg: '#fff3cd', text: '#856404' },
                    'Inativo': { bg: '#f8d7da', text: '#721c24' }
                };
                const color = statusColors[s.status] || { bg: '#ccc', text: '#333' };
                const acoes = s.status === 'Inativo'
                    ? '<button class="action-btn btn-status" onclick="openReentryModal(' + s.sessionId + ')">Reentrada</button>'
                    : '<select onchange="toggleSessionStatus(' + s.sessionId + ', this.value)" style="padding: 0.3rem; border-radius: 6px; margin-right: 0.3rem;">' +
                      ['Ativo', 'Suspenso', 'Inativo'].map(function (o) {
                          return '<option value="' + o + '"' + (o === s.status ? ' selected' : '') + '>' + o + '</option>';
                      }).join('') + '</select>' +
                      '<button class="action-btn btn-status" onclick="toggleSessionStatus(' + s.sessionId + ', \'Inativo\')">Registrar saída</button>';
                const row = document.createElement('tr');
                if (isExpired) row.classList.add('expired-row');
                row.innerHTML = '<td>' + s.sessionId + '</td><td>' + escapeHTML(s.matricula) + '</td><td>' + escapeHTML(s.nome) + (isExpired ? ' ⚠️' : '') + '</td><td>' + s.categoria + '</td><td>' + s.pc + '</td>' +
                    '<td>' + formatDateTime(s.entradaFull) + '</td>' +
                    '<td>' + (s.saidaFull ? formatDateTime(s.saidaFull) : s.saida) + '</td>' +
                    tempoCell(s) + '<td>' + s.validade + '</td>' +
                    '<td><span class="status-badge" style="background-color: ' + color.bg + '; color: ' + color.text + '; font-weight: bold;">' + s.status + '</span></td>' +
                    '<td>' + acoes + '</td>';
                list.appendChild(row);
            });
            updateElapsed();
            renderPCDashboard();
        }

        function renderPCDashboard() {
            const grid = document.getElementById('pc-dashboard');
            const summary = document.getElementById('pc-summary');
            if (!grid || !summary) return;
            const TOTAL_PCS = 28;
            let livres = 0, emUso = 0, suspensos = 0;
            grid.innerHTML = '';
            for (let pc = 1; pc <= TOTAL_PCS; pc++) {
                const ativa = sessions.find(function (s) { return parseInt(s.pc) === pc && s.status === 'Ativo'; });
                const session = ativa || sessions.find(function (s) { return parseInt(s.pc) === pc && s.status === 'Suspenso'; });
                const user = session && userBase.find(function (u) { return u.id === session.userId; });
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
            try { installMeta = JSON.parse(localStorage.getItem('bpa_install') || 'null'); }
            catch (_) { installMeta = null; }
            try { system = JSON.parse(localStorage.getItem('bpa_system') || 'null'); }
            catch (_) { system = null; }
            if (!system) await runFirstInstall();
            else showLoginView();
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

            document.getElementById('btn-show-setup').addEventListener('click', showSetupView);
            document.getElementById('btn-show-recovery').addEventListener('click', showRecoveryView);
            document.getElementById('btn-back-login').addEventListener('click', showLoginView);
            document.getElementById('btn-back-login2').addEventListener('click', showLoginView);
            document.getElementById('btn-logout').addEventListener('click', function () { logout('Sessão encerrada. Até logo!'); });
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
            document.getElementById('user-registration-form').addEventListener('submit', handlePermanentRegistration);
            document.getElementById('access-form').addEventListener('submit', handleAccessRequest);
            document.getElementById('theme-toggle').addEventListener('change', toggleTheme);
            document.getElementById('sys-password-form').addEventListener('submit', handleChangeSystemPassword);
            initCharts();
            renderAll();
            bootstrap();
        });
        // #endregion render geral + bootstrap
    