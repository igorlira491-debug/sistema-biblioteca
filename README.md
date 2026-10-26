# Sistema de Registro de Biblioteca

Sistema para registrar o uso dos computadores de uma biblioteca pública: cadastro de
leitores, entrada e saída nas máquinas, relatórios e gráficos de gestão.

Desenvolvido para uso real em uma biblioteca pública municipal, com três requisitos
que guiaram todas as decisões técnicas:

- **Funcionar 100% sem internet**: tudo roda numa única máquina.
- **Não perder dados em quedas de energia**, que eram frequentes no local.
- **Proteger dados pessoais** (inclusive de crianças), seguindo a LGPD.

> O nome da instituição foi substituído por um genérico nesta versão pública.

---

## ✨ Funcionalidades

- Cadastro de leitores com **categoria automática pela idade** (Infantil, Jovem, Adulto)
- Registro de entrada e saída nos computadores, com tabela de quem está usando agora
- **Relatórios em PDF** e **gráficos** de uso para a gestão
- **Backup automático diário** (guarda os últimos 30 dias) e restauração por linha de comando
- Exportação e importação de backups **cifrados**
- Aviso claro na tela se o banco de dados ficar indisponível; o sistema nunca finge que salvou

## 🛠️ Tecnologias

| Camada | Tecnologia |
|---|---|
| Interface | HTML, CSS e JavaScript puro, sem frameworks |
| Servidor | Python 3, **só biblioteca padrão** (sem pip, sem dependências externas) |
| Banco de dados | SQLite em modo WAL com `synchronous=FULL` |
| Criptografia | Web Crypto API: AES-GCM-256 + PBKDF2-SHA256 |
| Gráficos e PDF | Chart.js, jsPDF e html2canvas, guardados localmente em `app/vendor/` |

## 🔒 Destaques de engenharia

- **Resistência a queda de energia:** cada gravação é uma transação atômica no SQLite.
  Testado matando o processo (`kill -9`) no meio de gravações e conferindo a integridade do banco.
- **Dados cifrados no navegador:** o servidor só guarda blocos cifrados e nunca vê
  dados pessoais em texto puro.
- **Content Security Policy rígida:** nenhum JavaScript dentro do HTML (`script-src 'self'`);
  os botões usam uma lista fechada de ações em vez de `onclick`.
- **API protegida:** o servidor só aceita conexões da própria máquina e confere a origem
  de cada pedido, bloqueando que outros sites abertos no navegador acessem os dados.
- **Backup seguro:** o arquivo é gravado em temporário, verificado e só então renomeado,
  então uma queda no meio do backup nunca estraga o anterior.

## 🚀 Como rodar

Requisitos: **Python 3.10+** (para o sistema) e **Node.js 18+** (só para os testes).

```bash
python3 run.py
```

O servidor sobe em `http://127.0.0.1:8765/` e abre o navegador sozinho. Para encerrar, use **Ctrl+C**.

| Opção | Efeito |
|---|---|
| `--sem-navegador` | não abre o navegador automaticamente |
| `--porta N` | usa a porta N |
| `--data DIR` | guarda o banco em outra pasta |
| `--verificar` | confere a integridade do banco e sai |
| `--restaurar ARQUIVO` | restaura um backup (com o sistema fechado) |

## ✅ Testes

São **11 suítes com 149 verificações**, cobrindo criptografia, recuperação após queda,
backup, paginação, desempenho (35 mil sessões), acessibilidade (contraste WCAG) e segurança.

```bash
node tests/bloco1/test_crypto_roundtrip.mjs
node tests/test_contraste_titulos.mjs app/index.html
node tests/test_reentrada.mjs app/index.html
node tests/test_importacao_backup.mjs app/index.html
node tests/test_paginacao.mjs app/index.html
node tests/desempenho_tabelas.mjs app/index.html
node tests/test_status_banco.mjs app/index.html
node tests/e2e_lifecycle.mjs
node tests/test_reabrir_aba.mjs
node tests/test_backup.mjs
node tests/test_js_externo.mjs
```

## 📁 Estrutura

```
├── run.py           # ponto de entrada: servidor + navegador
├── server/
│   ├── app.py       # servidor HTTP e API local
│   ├── db.py        # acesso ao SQLite
│   └── backup.py    # backup diário e restauração
├── app/
│   ├── index.html   # interface (HTML + CSS)
│   ├── app.js       # toda a lógica do cliente
│   └── vendor/      # bibliotecas de gráficos e PDF
└── tests/           # suítes de teste
```

---

**Autor:** [igorlira491-debug](https://github.com/igorlira491-debug)
