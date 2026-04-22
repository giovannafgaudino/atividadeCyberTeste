# 🔐 TechShop — OWASP ZAP Security Scan

> **FIAP — Investigação e Perícia Digital**  
> Aplicação web propositalmente vulnerável para demonstração de DAST com OWASP ZAP CLI no GitHub Actions.

---

## 📁 Estrutura do Projeto

```
fiap-zap-project/
├── .github/
│   └── workflows/
│       └── zap-scan.yml        ← Pipeline GitHub Actions (todas as tarefas)
├── app/
│   ├── index.html              ← Aplicação web vulnerável (frontend)
│   └── server.py               ← Servidor HTTP Python (sem headers de segurança)
├── analise_relatorio.py        ← Script de análise local do relatório ZAP
└── README.md
```

---

## 🚀 Como Usar

### 1. Subir no GitHub

```bash
git init
git add .
git commit -m "feat: aplicação vulnerável para scan ZAP"
git remote add origin https://github.com/SEU_USUARIO/SEU_REPO.git
git push -u origin main
```

O workflow dispara automaticamente a cada `push` na branch `main`.

---

### 2. Testar localmente

```bash
# Instalar dependências (nenhuma externa necessária — Python padrão)
cd app
python server.py

# Acessar em: http://localhost:8080
```

---

### 3. Analisar relatório localmente

Após baixar o `zap-report.json` dos Artifacts do GitHub Actions:

```bash
python analise_relatorio.py zap-report.json
```

---

## 🎯 Tarefas da Atividade

| # | Tarefa | Onde está implementado |
|---|--------|----------------------|
| 1 | ZAP CLI no GitHub Actions + relatório HTML | `zap-scan.yml` — step **"Executar OWASP ZAP"** |
| 2 | Pipeline falha em Alta/Crítica | `zap-scan.yml` — step **"Verificar vulnerabilidades"** |
| 3 | Análise do relatório (total, severidades, tipos) | `zap-scan.yml` — step **"Publicar análise"** + `analise_relatorio.py` |
| 4 | Vulnerabilidade proposital detectada pelo ZAP | `app/index.html` + `app/server.py` |
| 5 | Relatório salvo como artefato | `zap-scan.yml` — step **"Salvar relatório ZAP"** |

---

## ⚠️ Vulnerabilidades Intencionais

A aplicação contém as seguintes falhas propositais para o ZAP detectar:

### 1. XSS Refletido (CWE-79)
**Arquivo:** `app/index.html`

O parâmetro `?name=` da URL é inserido via `innerHTML` sem sanitização:
```javascript
// ⚠️ VULNERÁVEL
out.innerHTML = 'Olá, ' + name + '!';

// ✅ CORRETO seria:
out.textContent = 'Olá, ' + name + '!';
```

**Teste:** `http://localhost:8080?name=<img src=x onerror=alert(1)>`

---

### 2. XSS via Campo de Busca (CWE-79)
**Arquivo:** `app/index.html`

O input de busca é renderizado via `innerHTML`:
```javascript
// ⚠️ VULNERÁVEL
result.innerHTML = 'Você buscou por: <strong>' + q + '</strong>';
```

**Teste:** Digite `<script>alert('xss')</script>` no campo de busca.

---

### 3. Ausência de Headers de Segurança (CWE-693)
**Arquivo:** `app/server.py`

O servidor não envia nenhum header de segurança:
- ❌ `Content-Security-Policy`
- ❌ `X-Frame-Options`
- ❌ `X-Content-Type-Options`
- ❌ `Strict-Transport-Security`
- ❌ `Referrer-Policy`

---

### 4. Formulário via GET com Credenciais (CWE-598)
**Arquivo:** `app/index.html`

O formulário de login usa `method="GET"`, expondo usuário e senha na URL:
```html
<!-- ⚠️ VULNERÁVEL -->
<form method="GET" action="/login">
```

---

### 5. Exposição de Informações (CWE-200)
**Arquivo:** `app/server.py` + `app/index.html`

- Credenciais hardcoded em comentários HTML
- Versão do servidor exposta no header `Server`
- Credenciais logadas no console em texto puro

---

### 6. CORS Aberto (CWE-942)
**Arquivo:** `app/server.py`

```python
# ⚠️ VULNERÁVEL
self.send_header("Access-Control-Allow-Origin", "*")
```

---

## 📊 Baixar Relatório dos Artifacts

1. Acesse seu repositório no GitHub
2. Clique em **Actions**
3. Selecione a execução do workflow
4. Role até a seção **Artifacts**
5. Clique em `zap-report-run-N-SHA` para baixar

O arquivo ZIP contém:
- `zap-report.html` → Relatório visual completo
- `zap-report.json` → Para análise programática
- `zap-report.xml`  → Formato alternativo

---

## 🔧 Personalização do Workflow

### Alterar URL alvo
```yaml
# zap-scan.yml
target: 'http://sua-aplicacao.com'
```

### Mudar nível de falha
Para falhar apenas em Critical (não em High), edite:
```python
# No step "Verificar vulnerabilidades"
if counts['High'] > 0:          # ← altere aqui
```

### Aumentar retenção dos artefatos
```yaml
retention-days: 90   # padrão: 30
```

---

## 📚 Referências

- [OWASP ZAP](https://www.zaproxy.org/)
- [ZAP GitHub Action](https://github.com/zaproxy/action-baseline)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE — Common Weakness Enumeration](https://cwe.mitre.org/)
- [GitHub Actions Artifacts](https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts)

---

> ⚠️ **AVISO:** Esta aplicação contém vulnerabilidades **intencionais** para fins **exclusivamente didáticos**.  
> **Nunca** use este código em ambiente de produção.
