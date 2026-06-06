import os
import re
import sys
import subprocess
import argparse
import logging
from pathlib import Path
from typing import Optional

try:
    import pandas as pd
except Exception as e:
    print("Dependência ausente: pandas não encontrado. Instale: pip install pandas")
    sys.exit(1)

# Logging
# --------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [VALIDACAO] %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("validacao_cruzada")


# Constantes e configuração de caminhos
# --------------------------------------------

CENARIOS   = ["A", "B", "C"]
PROTOCOLOS = ["tcp", "rudp"]

# Portas usadas pelos protocolos (para filtro tshark)
PORTAS = {
    "tcp":  5001,
    "rudp": 9000,
}

# Colunas obrigatórias que devem existir nos CSVs de cada protocolo
COLUNAS_CSV = {
    "tcp":  ["timestamp", "scenario", "filename", "file_size_bytes", "elapsed_s", "throughput_mbps", "chunks_sent"],
    "rudp": ["timestamp", "scenario", "filename", "file_size_bytes", "elapsed_s", "throughput_mbps", "chunks_sent", "retransmits"],
}


# Helpers de subprocess
# --------------------------------------------

def run_tshark(args: list[str], verbose: bool = False) -> str:
    """
    Executa tshark com os argumentos fornecidos

    Retorna stdout como string. Em caso de erro (arquivo corrompido, vazio,
    tshark ausente) retorna string vazia e loga o aviso - nunca levanta exceção,
    para não interromper o loop de processamento.
    """
    cmd = ["tshark"] + args
    if verbose:
        log.debug("CMD: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,          # pcaps grandes podem demorar
        )
        if result.returncode not in (0, 1):
            log.warning("tshark retornou código %d: %s", result.returncode, result.stderr.strip()[:200])
        return result.stdout.strip()

    except FileNotFoundError:
        log.error("tshark não encontrado. Instale com: apt install tshark")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        log.warning("tshark timeout processando arquivo.")
        return ""
    except Exception as err:
        log.warning("Erro inesperado rodando tshark: %s", err)
        return ""


# Extração de métricas de um arquivo .pcap via tshark
# --------------------------------------------

def extrair_metricas_pcap(
    pcap_path: Path,
    protocolo: str,
    verbose: bool = False,
) -> dict:
    """
    Extrai do arquivo .pcap:
      - tempo_rede_s : duração da captura (último - primeiro pacote) em segundos
      - bytes_rede   : soma de todos os bytes capturados (frame.len)
      - pacotes_rede : contagem de pacotes no fluxo
      - pcap_ok      : True se a extração foi bem-sucedida

    Aplica filtro pela porta do protocolo para isolar apenas o fluxo de teste
    """
    resultado = {
        "tempo_rede_s": None,
        "bytes_rede":   None,
        "pacotes_rede": None,
        "pcap_ok":      False,
        "pcap_erro":    "",
    }

    if not pcap_path.exists():
        resultado["pcap_erro"] = "arquivo não encontrado"
        return resultado

    if pcap_path.stat().st_size < 100:
        resultado["pcap_erro"] = "arquivo vazio ou corrompido (< 100 bytes)"
        log.warning("PCAP ignorado (%s): %s", pcap_path.name, resultado["pcap_erro"])
        return resultado

    porta = PORTAS[protocolo]

    # Filtro tshark por protocolo
    # TCP: filtra pelo número de porta
    # UDP/R-UDP: filtra pelo número de porta
    filtro = f"tcp.port=={porta}" if protocolo == "tcp" else f"udp.port=={porta}"

    # Extrai frame.time_relative e frame.len de cada pacote 
    # Formato de saída: "<time_relative>,<frame_len>"
    saida = run_tshark([
        "-r", str(pcap_path),
        "-Y", filtro,
        "-T", "fields",
        "-e", "frame.time_relative",
        "-e", "frame.len",
        "-E", "separator=,",
        "-E", "quote=n",
    ], verbose=verbose)

    if not saida:
        resultado["pcap_erro"] = "nenhum pacote encontrado com o filtro aplicado"
        log.warning("PCAP sem dados filtrados (%s) — filtro: %s",
                    pcap_path.name, filtro)
        return resultado

    # Parseia as linhas 
    tempos = []
    bytes_lista = []

    for linha in saida.splitlines():
        linha = linha.strip()
        if not linha or "," not in linha:
            continue
        partes = linha.split(",")
        if len(partes) < 2:
            continue
        try:
            t   = float(partes[0])
            byt = int(partes[1])
            tempos.append(t)
            bytes_lista.append(byt)
        except ValueError:
            continue   # linha malformada - ignora

    if len(tempos) < 2:
        resultado["pcap_erro"] = f"poucos pacotes válidos ({len(tempos)})"
        log.warning("PCAP com poucos pacotes (%s): %d pacote(s)",
                    pcap_path.name, len(tempos))
        return resultado

    # Calcula métricas
    resultado["tempo_rede_s"]  = round(max(tempos) - min(tempos), 6)
    resultado["bytes_rede"]    = sum(bytes_lista)
    resultado["pacotes_rede"]  = len(tempos)
    resultado["pcap_ok"]       = True

    log.debug(
        "  pcap=%s | t=%.4fs | bytes=%d | pkts=%d",
        pcap_path.name,
        resultado["tempo_rede_s"],
        resultado["bytes_rede"],
        resultado["pacotes_rede"],
    )

    return resultado


# Leitura e validação dos CSVs da aplicação
# --------------------------------------------

def ler_csv_aplicacao(csv_path: Path, protocolo: str) -> Optional[pd.DataFrame]:
    """
    Lê o CSV gerado pelo cliente Python e valida as colunas obrigatórias

    Retorna DataFrame ou None se o arquivo não existir / estiver inválido
    """
    if not csv_path.exists():
        log.warning("CSV não encontrado: %s", csv_path)
        return None

    try:
        df = pd.read_csv(csv_path)
    except Exception as err:
        log.error("Erro ao ler CSV %s: %s", csv_path, err)
        return None

    if df.empty:
        log.warning("CSV vazio: %s", csv_path)
        return None

    cols_esperadas = COLUNAS_CSV[protocolo]
    faltando = [c for c in cols_esperadas if c not in df.columns]
    if faltando:
        log.warning("CSV %s com colunas faltando: %s", csv_path.name, faltando)

    return df


# Função principal de correlação
# --------------------------------------------

def correlacionar(base_dir: Path, verbose: bool = False) -> pd.DataFrame:
    """
    Varre todas as combinações (protocolo × cenário), cruza os dados do CSV com as métricas extraídas dos .pcap e retorna um DataFrame consolidado
    """
    registros = []

    for protocolo in PROTOCOLOS:
        for cenario in CENARIOS:

            log.info("── Processando: %s | Cenário %s ──", protocolo.upper(), cenario)

            # Caminhos
            csv_path  = base_dir / "logs" / protocolo / \
                        f"logs_{protocolo}_cenario_{cenario}.csv"
            pcap_dir  = base_dir / "pcaps" / protocolo

            # Lê CSV da aplicação 
            df_app = ler_csv_aplicacao(csv_path, protocolo)
            if df_app is None:
                log.warning("Pulando %s cenário %s (CSV ausente/inválido).",
                            protocolo, cenario)
                continue

            n_runs = len(df_app)
            log.info("  %d runs encontrados no CSV.", n_runs)

            # Para cada run, encontra o .pcap correspondente 
            for idx, row in df_app.iterrows():
                run_num  = idx + 1     
                run_fmt  = f"{run_num:02d}"
                pcap_nome = f"cenario_{cenario}_{protocolo}_run{run_fmt}.pcap"
                pcap_path = pcap_dir / pcap_nome

                log.info("  Run %02d → %s", run_num, pcap_nome)

                # Extrai métricas do pcap
                metricas_pcap = extrair_metricas_pcap(pcap_path, protocolo, verbose)

                # Valores da aplicação
                tempo_app   = float(row.get("elapsed_s",       0) or 0)
                tput_app    = float(row.get("throughput_mbps", 0) or 0)
                file_size   = int(  row.get("file_size_bytes", 0) or 0)
                chunks      = int(  row.get("chunks_sent",     0) or 0)
                retransmits = int(  row.get("retransmits",     0) or 0) \
                              if "retransmits" in row.index else None

                # Discrepâncias
                tempo_rede  = metricas_pcap["tempo_rede_s"]
                bytes_rede  = metricas_pcap["bytes_rede"]

                # tempo (absoluto e percentual)
                if tempo_rede is not None and tempo_app > 0:
                    delta_tempo_s   = round(abs(tempo_app - tempo_rede), 6)
                    delta_tempo_pct = round(
                        (delta_tempo_s / tempo_app) * 100, 2
                    )
                else:
                    delta_tempo_s   = None
                    delta_tempo_pct = None

                # Overhead de bytes (rede - payload da aplicação)
                if bytes_rede is not None and file_size > 0:
                    overhead_bytes = bytes_rede - file_size
                    overhead_pct   = round(
                        (overhead_bytes / file_size) * 100, 2
                    )
                else:
                    overhead_bytes = None
                    overhead_pct   = None

                # Throughput calculado a partir da rede (para comparação)
                if bytes_rede is not None and tempo_rede is not None and tempo_rede > 0:
                    throughput_rede_mbps = round(
                        (bytes_rede * 8) / (tempo_rede * 1_000_000), 6
                    )
                else:
                    throughput_rede_mbps = None

                # ─ Monta registro
                registro = {
                    # Identificação
                    "protocolo":           protocolo.upper(),
                    "cenario":             cenario,
                    "run":                 run_num,
                    "timestamp":           row.get("timestamp", ""),
                    "filename":            row.get("filename",  ""),
                    "file_size_bytes":     file_size,
                    # Aplicação
                    "tempo_app_s":         tempo_app,
                    "throughput_app_mbps": tput_app,
                    "chunks_sent":         chunks,
                    "retransmits":         retransmits,
                    # Rede (pcap)
                    "tempo_rede_s":        tempo_rede,
                    "bytes_rede":          bytes_rede,
                    "pacotes_rede":        metricas_pcap["pacotes_rede"],
                    "pcap_ok":             metricas_pcap["pcap_ok"],
                    "pcap_erro":           metricas_pcap["pcap_erro"],
                    # Discrepâncias
                    "delta_tempo_s":       delta_tempo_s,
                    "delta_tempo_pct":     delta_tempo_pct,
                    "overhead_bytes":      overhead_bytes,
                    "overhead_pct":        overhead_pct,
                    "throughput_rede_mbps":throughput_rede_mbps,
                }
                registros.append(registro)

    if not registros:
        log.error("Nenhum dado foi processado. Verifique os caminhos e os arquivos.")
        return pd.DataFrame()

    df = pd.DataFrame(registros)

    # Ordena por protocolo -> cenário -> run para leitura mais clara
    df = df.sort_values(["protocolo", "cenario", "run"]).reset_index(drop=True)

    return df


# Relatório de resumo no terminal
# --------------------------------------------

def imprimir_resumo(df: pd.DataFrame) -> None:
    """Imprime um resumo estatístico da validação cruzada no terminal"""

    print("\n" + "═" * 72)
    print("  RELATÓRIO DE VALIDAÇÃO CRUZADA — RESUMO ESTATÍSTICO")
    print("═" * 72)

    for protocolo in df["protocolo"].unique():
        for cenario in sorted(df["cenario"].unique()):
            subset = df[(df["protocolo"] == protocolo) & (df["cenario"] == cenario)]
            if subset.empty:
                continue

            n_total = len(subset)
            n_ok    = subset["pcap_ok"].sum()
            n_falha = n_total - n_ok

            print(f"\n  ┌── {protocolo} │ Cenário {cenario} "
                  f"({n_total} runs, {n_ok} pcaps válidos, {n_falha} falhas)")

            # Tempo
            t_app  = subset["tempo_app_s"].dropna()
            t_rede = subset["tempo_rede_s"].dropna()
            print(f"  │  Tempo app  → média={t_app.mean():.4f}s  "
                  f"std={t_app.std():.4f}s  "
                  f"min={t_app.min():.4f}s  max={t_app.max():.4f}s")
            if not t_rede.empty:
                print(f"  │  Tempo rede → média={t_rede.mean():.4f}s  "
                      f"std={t_rede.std():.4f}s  "
                      f"min={t_rede.min():.4f}s  max={t_rede.max():.4f}s")

            # delta tempo
            delta = subset["delta_tempo_pct"].dropna()
            if not delta.empty:
                print(f"  │  Δ tempo(%) → média={delta.mean():.2f}%  "
                      f"max={delta.max():.2f}%")

            # Throughput
            tput_app  = subset["throughput_app_mbps"].dropna()
            tput_rede = subset["throughput_rede_mbps"].dropna()
            print(f"  │  Tput app   → média={tput_app.mean():.4f} Mbps  "
                  f"std={tput_app.std():.4f}")
            if not tput_rede.empty:
                print(f"  │  Tput rede  → média={tput_rede.mean():.4f} Mbps")

            # Overhead
            ovhd = subset["overhead_bytes"].dropna()
            if not ovhd.empty:
                print(f"  │  Overhead   → média={ovhd.mean():.0f} bytes  "
                      f"({subset['overhead_pct'].dropna().mean():.2f}%)")

            # Retransmissões (R-UDP)
            if "retransmits" in subset.columns and protocolo == "RUDP":
                rtx = subset["retransmits"].dropna()
                if not rtx.empty:
                    print(f"  │  Retransm.  → total={rtx.sum():.0f}  "
                          f"média/run={rtx.mean():.1f}")

            print(f"  └{'─' * 60}")

    print("\n" + "═" * 72 + "\n")


# Verificações de ambiente
def verificar_dependencias() -> None:
    """Verifica se tshark e pandas estão disponíveis antes de iniciar"""

    # tshark
    try:
        r = subprocess.run(["tshark", "--version"],
                           capture_output=True, text=True, timeout=5)
        versao = r.stdout.splitlines()[0] if r.stdout else "versão desconhecida"
        log.info("tshark OK: %s", versao)
    except FileNotFoundError:
        log.error("tshark não encontrado. Instale: apt install tshark")
        sys.exit(1)

    # pandas
    try:
        import pandas as pd
        log.info("pandas OK: %s", pd.__version__)
    except ImportError:
        log.error("pandas não encontrado. Instale: pip install pandas")
        sys.exit(1)

# CLI
def parse_args():
    p = argparse.ArgumentParser(
        description="Validação Cruzada Aplicação × Rede — Redes II UFPI"
    )
    p.add_argument(
        "--base-dir", default=".",
        help="Diretório raiz onde ficam as pastas logs/ e pcaps/ (padrão: .)"
    )
    p.add_argument(
        "--output", default="metricas_consolidadas.csv",
        help="Caminho do CSV de saída (padrão: metricas_consolidadas.csv)"
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="Exibe cada comando tshark executado"
    )
    return p.parse_args()


# MAIN
# --------------------------------------------

def main():
    args     = parse_args()
    base_dir = Path(args.base_dir).resolve()
    output   = Path(args.output)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("Base dir : %s", base_dir)
    log.info("Saída    : %s", output)

    verificar_dependencias()

    # Executa correlação
    df = correlacionar(base_dir, verbose=args.verbose)

    if df.empty:
        log.error("DataFrame vazio — nenhum dado gerado. Abortando.")
        sys.exit(1)

    # Salva CSV consolidado
    df.to_csv(output, index=False, encoding="utf-8")
    log.info("metricas_consolidadas.csv salvo: %d linhas × %d colunas",
             len(df), len(df.columns))

    #  Imprime resumo no terminal
    imprimir_resumo(df)

    # Preview das primeiras linhas
    print("PREVIEW — primeiras 6 linhas do DataFrame consolidado:")
    print(df.head(6).to_string(index=False))
    print()


if __name__ == "__main__":
    main()