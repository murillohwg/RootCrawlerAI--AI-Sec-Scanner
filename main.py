import argparse
import json
import os
import sys
import asyncio
from urllib.parse import urlparse

from scanner import scan_directories, scan_async
from scanner.wordlist_loader import load_wordlist
from analyzer import analyze_multiple
from ui.banner import banner


# ──────────────────────────────────────────────
# Utils
# ──────────────────────────────────────────────

def is_valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and parsed.netloc


def list_wordlists():
    try:
        return [f for f in os.listdir("wordlists") if f.endswith(".txt")]
    except:
        return []


# ──────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────

def print_findings(results):
    has_findings = False

    for result in results:
        if not result["findings"]:
            continue

        has_findings = True
        level = result["risk_level"].upper()

        print(f"\n{'='*60}")
        print(f"  [{level}] {result['url']}")
        print(f"  Status: {result['status_code']}  |  Score: {result['risk_score']}")
        print(f"{'='*60}")

        for f in result["findings"]:
            sev = f["severity"].upper()
            print(f"  [{sev}] {f['type']}")
            print(f"         {f['description']}")
            if f.get("evidence"):
                print(f"         Evidence: {f['evidence'][:120]}")

        if result.get("ai_analysis"):
            print("\n  [AI EXPLOIT SUGGESTIONS]")
            print(f"  {result['ai_analysis'][:500]}")

    if not has_findings:
        print("\n[*] Nenhuma anomalia detectada.")


def save_report(results, path):
    if not path.endswith(".json"):
        path += ".json"

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    try:
        with open(path, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Relatório salvo em: {path}")
    except Exception as e:
        print(f"[!] Erro ao salvar relatório: {e}")


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="rootcrawler",
        description="RootCrawler AI - Offensive Web Recon Engine",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-u", "--url", help="URL alvo")
    parser.add_argument("-w", "--wordlist", help="Caminho da wordlist")
    parser.add_argument("-o", "--output", default="reports/scan_report.json")

    parser.add_argument("--ai", action="store_true", help="Ativa análise com IA")
    parser.add_argument("--async", dest="use_async", action="store_true", help="Modo rápido (async)")
    parser.add_argument("--threads", type=int, default=10, help="Número de threads")

    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--only-findings", action="store_true")

    return parser.parse_args()


# ──────────────────────────────────────────────
# INTERACTIVE MODE
# ──────────────────────────────────────────────

def interactive_mode(args):
    print("\n[*] Modo interativo iniciado\n")

    while True:
        target = input("🌐 URL alvo: ").strip()
        if target:
            args.url = target
            break
        print("[!] URL não pode ser vazia.")

    args.ai = input("🤖 Ativar IA? (y/n): ").lower() == "y"
    args.use_async = input("⚡ Modo rápido (async)? (y/n): ").lower() == "y"

    if args.use_async:
        try:
            t = input("🔧 Threads (default 10): ").strip()
            args.threads = int(t) if t else 10
        except:
            args.threads = 10

    return args


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    banner()

    args = parse_args()

    if not args.url:
        args = interactive_mode(args)

    target = args.url.rstrip("/")

    if not is_valid_url(target):
        print("[!] URL inválida.")
        sys.exit(1)

    print(f"\n[*] Alvo: {target}")

    # ───────── Wordlist ─────────
    if args.wordlist:
        wordlist_path = args.wordlist
    else:
        available = list_wordlists()

        print("\n[*] Wordlists disponíveis:")
        for i, wl in enumerate(available, 1):
            print(f"  {i}. {wl}")
        print("  0. Inserir caminho manual")

        choice = input("\nEscolha uma opção: ").strip()

        if choice == "0":
            wordlist_path = input("Caminho da wordlist: ").strip()
        else:
            try:
                index = int(choice) - 1
                wordlist_path = f"wordlists/{available[index]}"
            except:
                print("[!] Opção inválida.")
                sys.exit(1)

    print(f"[*] Wordlist: {wordlist_path}")

    # ───────── Load wordlist ─────────
    try:
        wordlist = load_wordlist(wordlist_path)
    except Exception as e:
        print(f"[!] Erro ao carregar wordlist: {e}")
        sys.exit(1)

    print(f"[*] Entradas: {len(wordlist)}\n")

    # ───────── Scanner ─────────
    print("[*] Iniciando scanner...")

    try:
        if args.use_async:
            responses = scan_async(target, wordlist, threads=args.threads)

            # 🔥 CORREÇÃO MÁGICA (resolve seu erro)
            if asyncio.iscoroutine(responses):
                responses = asyncio.run(responses)

        else:
            responses = scan_directories(target, wordlist)

    except KeyboardInterrupt:
        print("\n[!] Scan interrompido.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Erro durante o scan: {e}")
        sys.exit(1)

    print(f"[+] {len(responses)} endpoints encontrados\n")

    # ───────── Analyzer ─────────
    print("[*] Analisando respostas...")
    results = analyze_multiple(responses, use_ai=args.ai)

    if args.only_findings:
        results = [r for r in results if r["findings"]]

    print_findings(results)

    # ───────── Report ─────────
    if not args.no_report:
        save_report(results, args.output)


if __name__ == "__main__":
    main()
