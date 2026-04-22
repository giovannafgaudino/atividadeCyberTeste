"""
analise_relatorio.py — Análise local do relatório OWASP ZAP
FIAP — Investigação e Perícia Digital

Uso:
    python analise_relatorio.py                      # lê zap-report.json
    python analise_relatorio.py meu-relatorio.json   # arquivo customizado

Saída: resumo no terminal + analise_zap.txt
"""

import json
import sys
import os
from collections import Counter
from datetime import datetime


# ── Configuração ─────────────────────────────────────────────────────────────
RISK_MAP = {
    3: ("High",          "🔴", "\033[1;31m"),
    2: ("Medium",        "🟡", "\033[1;33m"),
    1: ("Low",           "🟢", "\033[1;32m"),
    0: ("Informational", "ℹ️ ", "\033[0;36m"),
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def load_report(path: str) -> list:
    """Carrega e retorna a lista de alertas do JSON do ZAP."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    alerts = []
    for site in data.get("site", []):
        alerts.extend(site.get("alerts", []))
    return alerts


def print_separator(char="─", width=56):
    print(f"\033[90m  {''.join([char]*width)}{RESET}")


def analyze(alerts: list) -> dict:
    """Processa os alertas e retorna estatísticas."""
    counts      = Counter()
    vuln_names  = Counter()
    cwe_ids     = Counter()
    details     = []

    for a in alerts:
        rc   = int(a.get("riskcode", 0))
        name = a.get("name", "Desconhecido")
        cwe  = a.get("cweid",  "N/A")
        desc = a.get("desc",   "")
        soln = a.get("solution", "")
        inst = a.get("instances", [])
        urls = [i.get("uri", "") for i in inst]

        sev_name = RISK_MAP.get(rc, RISK_MAP[0])[0]
        counts[sev_name]     += 1
        vuln_names[name]     += 1
        if cwe != "N/A":
            cwe_ids[f"CWE-{cwe}"] += 1

        details.append({
            "riskcode":  rc,
            "severity":  sev_name,
            "name":      name,
            "cwe":       cwe,
            "instances": len(inst),
            "urls":      urls[:3],          # primeiras 3 URLs afetadas
            "solution":  soln[:200] if soln else "—",
        })

    # Ordena por risco decrescente
    details.sort(key=lambda x: x["riskcode"], reverse=True)
    return {
        "total":      sum(counts.values()),
        "counts":     counts,
        "top_vulns":  vuln_names.most_common(10),
        "top_cwes":   cwe_ids.most_common(5),
        "details":    details,
    }


def print_report(stats: dict, source: str):
    """Imprime o relatório formatado no terminal."""
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    print(f"\n{BOLD}  ╔══════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}  ║       ANÁLISE DE RELATÓRIO OWASP ZAP — FIAP          ║{RESET}")
    print(f"{BOLD}  ╚══════════════════════════════════════════════════════╝{RESET}\n")
    print(f"  Arquivo : {source}")
    print(f"  Data    : {now}")
    print()

    # ── TAREFA 3.1 — Quantidade total ────────────────────────────────────────
    print_separator()
    print(f"  {BOLD}📊 TAREFA 3.1 — Total de Alertas{RESET}")
    print_separator()
    print(f"\n  Total de alertas encontrados: {BOLD}{stats['total']}{RESET}\n")

    # ── TAREFA 3.2 — Por severidade ──────────────────────────────────────────
    print_separator()
    print(f"  {BOLD}📋 TAREFA 3.2 — Alertas por Severidade{RESET}")
    print_separator()
    print()
    for rc in [3, 2, 1, 0]:
        sev_name, emoji, color = RISK_MAP[rc]
        qty = stats["counts"].get(sev_name, 0)
        bar = "█" * min(qty * 2, 30)
        print(f"  {color}{emoji} {sev_name:<15}{RESET} │ {BOLD}{qty:>3}{RESET}  {color}{bar}{RESET}")
    print()

    # ── TAREFA 3.3 — Tipos mais comuns ───────────────────────────────────────
    print_separator()
    print(f"  {BOLD}🔍 TAREFA 3.3 — Vulnerabilidades Mais Comuns{RESET}")
    print_separator()
    print()
    for i, (name, count) in enumerate(stats["top_vulns"], 1):
        print(f"  {BOLD}{i:>2}.{RESET} {name}")
        print(f"      Ocorrências: {BOLD}{count}{RESET}")
    print()

    # ── CWEs mais frequentes ─────────────────────────────────────────────────
    if stats["top_cwes"]:
        print_separator()
        print(f"  {BOLD}🏷️  CWEs Mais Frequentes{RESET}")
        print_separator()
        print()
        for cwe, count in stats["top_cwes"]:
            print(f"  • {cwe:<12} → {count} ocorrência(s)")
        print()

    # ── Detalhe por alerta ───────────────────────────────────────────────────
    print_separator()
    print(f"  {BOLD}🗂️  Detalhamento dos Alertas{RESET}")
    print_separator()
    print()
    for a in stats["details"]:
        _, emoji, color = RISK_MAP.get(a["riskcode"], RISK_MAP[0])
        print(f"  {color}{emoji} [{a['severity'].upper()}] {BOLD}{a['name']}{RESET}")
        print(f"     CWE        : {a['cwe']}")
        print(f"     Instâncias : {a['instances']}")
        if a["urls"]:
            print(f"     URLs afetadas:")
            for url in a["urls"]:
                print(f"       → {url}")
        if a["solution"] and a["solution"] != "—":
            sol = a["solution"].replace("\n", " ").strip()[:120]
            print(f"     Solução    : {sol}...")
        print()

    print_separator("═")
    print()


def save_txt(stats: dict, source: str, out_path: str = "analise_zap.txt"):
    """Salva resumo em texto puro (sem escape ANSI)."""
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    lines = [
        "=" * 60,
        "ANÁLISE DE RELATÓRIO OWASP ZAP — FIAP",
        "=" * 60,
        f"Arquivo : {source}",
        f"Data    : {now}",
        "",
        "─" * 60,
        "TAREFA 3.1 — Total de Alertas",
        "─" * 60,
        f"Total: {stats['total']}",
        "",
        "─" * 60,
        "TAREFA 3.2 — Por Severidade",
        "─" * 60,
    ]
    for rc in [3, 2, 1, 0]:
        sev_name = RISK_MAP[rc][0]
        qty = stats["counts"].get(sev_name, 0)
        lines.append(f"  {sev_name:<15}: {qty}")

    lines += [
        "",
        "─" * 60,
        "TAREFA 3.3 — Vulnerabilidades Mais Comuns",
        "─" * 60,
    ]
    for i, (name, count) in enumerate(stats["top_vulns"], 1):
        lines.append(f"  {i:>2}. {name} ({count}x)")

    lines += ["", "=" * 60]

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  💾 Resumo salvo em: {BOLD}{out_path}{RESET}\n")


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else "zap-report.json"

    if not os.path.exists(source):
        print(f"\n  ❌ Arquivo não encontrado: {source}")
        print("     Execute o ZAP primeiro ou forneça o caminho correto.")
        print(f"     Uso: python {sys.argv[0]} [caminho/para/relatorio.json]\n")
        sys.exit(1)

    alerts = load_report(source)
    stats  = analyze(alerts)
    print_report(stats, source)
    save_txt(stats, source)


if __name__ == "__main__":
    main()
