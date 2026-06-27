import argparse
import os
import sys
import warnings
from pathlib import Path

import numpy as np

try:
    import pandas as pd
except ImportError:
    print("[ERRO] pandas não encontrado. Execute: pip install pandas")
    sys.exit(1)

try:
    import matplotlib
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.ticker import MultipleLocator, AutoMinorLocator
    matplotlib.rcParams["figure.dpi"] = 150
except ImportError:
    print("[ERRO] matplotlib não encontrado. Execute: pip install matplotlib")
    sys.exit(1)

warnings.filterwarnings("ignore")

# Paleta de alto contraste - acessível mesmo em impressão P&B
COR_TCP   = "#1f77b4" 
COR_RUDP  = "#d62728" 
COR_REDE  = "#2ca02c"  
COR_APP   = "#ff7f0e"   

ALPHA_BAR      = 0.85
ALPHA_GRID     = 0.45
FONT_TITLE     = 14
FONT_AXIS      = 12
FONT_TICK      = 10
FONT_LEGEND    = 10
FONT_ANNOT     = 8.5
CAPSIZE        = 5  
ERROR_LINEWIDTH = 1.8

# Mapeamento de rótulos para exibição nos gráficos
LABEL_PROTOCOLO = {"TCP": "TCP", "RUDP": "R-UDP"}
LABEL_CENARIO   = {
    "A": "A\n(0% perda / 10ms)",
    "B": "B\n(5% perda / 50ms)",
    "C": "C\n(10% perda / 100ms)",
}

# Ordem canônica dos cenários
CENARIOS_ORDEM = ["A", "B", "C"]


# Configuração Global do Matplotlib 
# -----------------------------------

def configurar_estilo() -> None:
    """Aplica configuração global de estilo para todos os gráficos."""
    plt.rcParams.update({
        # Fonte
        "font.family":          "DejaVu Sans",
        "font.size":            FONT_TICK,
        "axes.titlesize":       FONT_TITLE,
        "axes.labelsize":       FONT_AXIS,
        "xtick.labelsize":      FONT_TICK,
        "ytick.labelsize":      FONT_TICK,
        "legend.fontsize":      FONT_LEGEND,
        # Bordas e grid
        "axes.spines.top":      False,
        "axes.spines.right":    False,
        "axes.grid":            True,
        "grid.linestyle":       "--",
        "grid.alpha":           ALPHA_GRID,
        "grid.color":           "#bbbbbb",
        # Resolução padrão de saída
        "savefig.dpi":          300,
        "savefig.bbox":         "tight",
        "savefig.facecolor":    "white",
        # Legenda
        "legend.framealpha":    0.92,
        "legend.edgecolor":     "#cccccc",
        # Barras de erro
        "errorbar.capsize":     CAPSIZE,
    })


# Funções auxiliares
# -----------------------------------

def _anotar_barras(ax, barras, valores, desvios, fmt="{:.3f}"):
    """
    Adiciona anotação numérica acima de cada barra (valor ± desvio)
    Posiciona o texto acima da barra de erro para não sobrepor
    """
    for barra, val, std in zip(barras, valores, desvios):
        x = barra.get_x() + barra.get_width() / 2
        y = val + std + (max(valores) * 0.02)  # margem acima da barra de erro
        ax.annotate(
            fmt.format(val),
            xy=(x, y),
            ha="center",
            va="bottom",
            fontsize=FONT_ANNOT,
            color="#333333",
            fontweight="bold",
        )


def _agrupa_estatisticas(df: pd.DataFrame, coluna: str) -> pd.DataFrame:
    """
    Agrupa por (protocolo, cenario) e calcula média, std, min, max, count
    para a coluna especificada.

    Retorna DataFrame com colunas: protocolo | cenario | media | std | minimo | maximo | n
    """
    stats = (
        df.groupby(["protocolo", "cenario"])[coluna]
        .agg(
            media="mean",
            std="std",
            minimo="min",
            maximo="max",
            n="count",
        )
        .reset_index()
    )
    # Preenche std NaN (quando n=1) com 0
    stats["std"] = stats["std"].fillna(0)
    return stats


def _posicoes_barras(n_cenarios: int, n_grupos: int, largura: float):
    """
    Calcula as posições X das barras para gráfico agrupado

    Retorna:
      x_base  : posições centrais de cada cenário (array n_cenarios)
      offsets : deslocamentos para cada grupo/protocolo (array n_grupos)
    """
    x_base  = np.arange(n_cenarios)
    offsets = np.linspace(
        -largura * (n_grupos - 1) / 2,
         largura * (n_grupos - 1) / 2,
         n_grupos,
    )
    return x_base, offsets


def _gerar_dados_simulados(seed: int = 42) -> pd.DataFrame:
    """
    Gera dados simulados realistas quando o CSV não é encontrado
    Visualizar e testar o script sem executar os testes de rede
    """
    rng = np.random.default_rng(seed)
    registros = []

    # Parâmetros base (médias esperadas)
    config = {
        # (protocolo, cenario): (throughput_mbps_base, tempo_s_base, fator_variacao)
        ("TCP",  "A"): (95.0,  0.09,  0.05),
        ("TCP",  "B"): (42.0,  0.21,  0.10),
        ("TCP",  "C"): (18.0,  0.52,  0.15),
        ("RUDP", "A"): (11.0,  0.75,  0.08),
        ("RUDP", "B"): (4.5,   1.85,  0.18),
        ("RUDP", "C"): (1.8,   4.60,  0.25),
    }

    for (proto, cenario), (tput_base, tempo_base, fvar) in config.items():
        n_runs = 15
        for run in range(1, n_runs + 1):
            # Jitter gaussiano proporcional
            tput  = max(0.1, rng.normal(tput_base, tput_base * fvar))
            tempo = max(0.01, rng.normal(tempo_base, tempo_base * fvar))

            # Tempo de rede ligeiramente diferente do da aplicação (discrepância)
            delta_fator    = rng.uniform(0.97, 1.05)
            tempo_rede     = tempo * delta_fator
            bytes_rede     = int(1_048_576 * rng.uniform(1.02, 1.12))  # overhead

            registros.append({
                "protocolo":           proto,
                "cenario":             cenario,
                "run":                 run,
                "timestamp":           f"2026-06-01T10:00:{run:02d}",
                "filename":            "test_payload_1MB.bin",
                "file_size_bytes":     1_048_576,
                "tempo_app_s":         round(tempo, 6),
                "throughput_app_mbps": round(tput, 6),
                "chunks_sent":         1024 if proto == "RUDP" else 256,
                "retransmits":         int(rng.poisson(3)) if proto == "RUDP" else None,
                "tempo_rede_s":        round(tempo_rede, 6),
                "bytes_rede":          bytes_rede,
                "pacotes_rede":        int(bytes_rede / 1400),
                "pcap_ok":             True,
                "pcap_erro":           "",
                "delta_tempo_s":       round(abs(tempo - tempo_rede), 6),
                "delta_tempo_pct":     round(abs(tempo - tempo_rede) / tempo * 100, 2),
                "overhead_bytes":      bytes_rede - 1_048_576,
                "overhead_pct":        round((bytes_rede - 1_048_576) / 1_048_576 * 100, 2),
                "throughput_rede_mbps": round((bytes_rede * 8) / (tempo_rede * 1e6), 6),
            })

    return pd.DataFrame(registros)


# Gráfico 1 - Throughput Médio (TCP vs R-UDP)
# ----------------------------------------------

def grafico_throughput(df: pd.DataFrame, output_dir: Path) -> Path:
    """
    Gráfico de barras agrupadas: Throughput médio (Mbps) por cenário e protocolo
    Barras de erro representam o desvio padrão das amostras
    """
    print("[GRÁFICO 1] Throughput Médio — TCP vs R-UDP...")

    stats = _agrupa_estatisticas(df, "throughput_app_mbps")

    # Layout
    fig, ax = plt.subplots(figsize=(9, 5.5))

    largura   = 0.32
    x_base, offsets = _posicoes_barras(len(CENARIOS_ORDEM), 2, largura)

    cores      = {"TCP": COR_TCP, "RUDP": COR_RUDP}
    protocolos = ["TCP", "RUDP"]

    for idx, proto in enumerate(protocolos):
        sub = stats[stats["protocolo"] == proto].set_index("cenario")
        medias  = [sub.loc[c, "media"] if c in sub.index else 0 for c in CENARIOS_ORDEM]
        desvios = [sub.loc[c, "std"]   if c in sub.index else 0 for c in CENARIOS_ORDEM]
        ns      = [int(sub.loc[c, "n"]) if c in sub.index else 0 for c in CENARIOS_ORDEM]

        pos = x_base + offsets[idx]

        barras = ax.bar(
            pos, medias,
            width=largura,
            color=cores[proto],
            alpha=ALPHA_BAR,
            label=LABEL_PROTOCOLO[proto],
            zorder=3,
            edgecolor="white",
            linewidth=0.8,
        )

        # Barras de erro (desvio padrão)
        ax.errorbar(
            pos, medias, yerr=desvios,
            fmt="none",
            color="#222222",
            capsize=CAPSIZE,
            capthick=1.5,
            elinewidth=ERROR_LINEWIDTH,
            zorder=4,
        )

        # Anotações: valor +- std acima de cada barra
        for barra, val, std, n in zip(barras, medias, desvios, ns):
            x = barra.get_x() + barra.get_width() / 2
            topo = val + std
            ax.annotate(
                f"{val:.2f}\n±{std:.2f}",
                xy=(x, topo + max(medias) * 0.015),
                ha="center", va="bottom",
                fontsize=7.5, color="#1a1a1a",
                fontweight="bold",
            )
            # Adiciona n de amostras abaixo
            ax.annotate(
                f"n={n}",
                xy=(x, 0),
                xytext=(x, -max(medias) * 0.04),
                ha="center", va="top",
                fontsize=7, color="#555555",
            )

    # Eixos e decoração 
    ax.set_xticks(x_base)
    ax.set_xticklabels(
        [LABEL_CENARIO[c] for c in CENARIOS_ORDEM],
        fontsize=FONT_TICK,
    )
    ax.set_xlabel("Cenários de Rede", fontsize=FONT_AXIS, labelpad=8)
    ax.set_ylabel("Throughput (Mbps)", fontsize=FONT_AXIS, labelpad=8)

    # Grid apenas no eixo Y
    ax.grid(axis="y", linestyle="--", alpha=ALPHA_GRID, zorder=0)
    ax.set_axisbelow(True)
    ax.yaxis.set_minor_locator(AutoMinorLocator(4))

    # Margem superior para os rótulos
    ymax = stats["media"].max() + stats["std"].max()
    ax.set_ylim(bottom=0, top=ymax * 1.35)

    # Legenda
    legend_patches = [
        mpatches.Patch(color=COR_TCP,  alpha=ALPHA_BAR, label="TCP"),
        mpatches.Patch(color=COR_RUDP, alpha=ALPHA_BAR, label="R-UDP"),
    ]
    ax.legend(
        handles=legend_patches,
        loc="upper right",
        framealpha=0.92,
        fontsize=FONT_LEGEND,
        title="Protocolo",
        title_fontsize=FONT_LEGEND,
    )

    # Rodapé com nota metodológica
    fig.text(
        0.5, -0.03,
        "Nota: Cada barra representa a média de 10–30 execuções independentes "
        "por cenário. Barras de erro indicam ±1 desvio padrão.",
        ha="center", fontsize=7.5, color="#666666", style="italic",
    )

    plt.tight_layout()

    caminho = output_dir / "grafico1_throughput_medio.png"
    fig.savefig(caminho, dpi=300, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"   ✓ Salvo: {caminho}")
    return caminho


# Gráfico 2 - Tempo de Transferência Médio (TCP vs R-UDP)
# ----------------------------------------------

def grafico_tempo(df: pd.DataFrame, output_dir: Path) -> Path:
    """ Gráfico de barras agrupadas: Tempo médio de transferência (s) por cenário """
    print("[GRÁFICO 2] Tempo de Transferência Médio — TCP vs R-UDP...")

    stats = _agrupa_estatisticas(df, "tempo_app_s")

    fig, ax = plt.subplots(figsize=(9, 5.5))

    largura = 0.32
    x_base, offsets = _posicoes_barras(len(CENARIOS_ORDEM), 2, largura)
    cores      = {"TCP": COR_TCP, "RUDP": COR_RUDP}
    protocolos = ["TCP", "RUDP"]

    for idx, proto in enumerate(protocolos):
        sub = stats[stats["protocolo"] == proto].set_index("cenario")
        medias  = [sub.loc[c, "media"] if c in sub.index else 0 for c in CENARIOS_ORDEM]
        desvios = [sub.loc[c, "std"]   if c in sub.index else 0 for c in CENARIOS_ORDEM]
        mins    = [sub.loc[c, "minimo"] if c in sub.index else 0 for c in CENARIOS_ORDEM]
        maxs    = [sub.loc[c, "maximo"] if c in sub.index else 0 for c in CENARIOS_ORDEM]
        ns      = [int(sub.loc[c, "n"]) if c in sub.index else 0 for c in CENARIOS_ORDEM]

        pos = x_base + offsets[idx]

        barras = ax.bar(
            pos, medias,
            width=largura,
            color=cores[proto],
            alpha=ALPHA_BAR,
            label=LABEL_PROTOCOLO[proto],
            zorder=3,
            edgecolor="white",
            linewidth=0.8,
        )

        # Barras de erro
        ax.errorbar(
            pos, medias, yerr=desvios,
            fmt="none",
            color="#222222",
            capsize=CAPSIZE,
            capthick=1.5,
            elinewidth=ERROR_LINEWIDTH,
            zorder=4,
        )

        # Anotações
        for barra, val, std, mn, mx, n in zip(barras, medias, desvios, mins, maxs, ns):
            x = barra.get_x() + barra.get_width() / 2
            topo = val + std
            ax.annotate(
                f"{val:.3f}s\n±{std:.3f}",
                xy=(x, topo + max(medias) * 0.015),
                ha="center", va="bottom",
                fontsize=7.5, color="#1a1a1a", fontweight="bold",
            )
            ax.annotate(
                f"n={n}",
                xy=(x, 0),
                xytext=(x, -max(medias) * 0.04),
                ha="center", va="top",
                fontsize=7, color="#555555",
            )

    #  Eixos e decoração
    ax.set_xticks(x_base)
    ax.set_xticklabels(
        [LABEL_CENARIO[c] for c in CENARIOS_ORDEM],
        fontsize=FONT_TICK,
    )
    ax.set_xlabel("Cenários de Rede", fontsize=FONT_AXIS, labelpad=8)
    ax.set_ylabel("Tempo de Transferência (s)", fontsize=FONT_AXIS, labelpad=8)

    ax.grid(axis="y", linestyle="--", alpha=ALPHA_GRID, zorder=0)
    ax.set_axisbelow(True)
    ax.yaxis.set_minor_locator(AutoMinorLocator(4))

    ymax = stats["media"].max() + stats["std"].max()
    ax.set_ylim(bottom=0, top=ymax * 1.38)

    legend_patches = [
        mpatches.Patch(color=COR_TCP,  alpha=ALPHA_BAR, label="TCP"),
        mpatches.Patch(color=COR_RUDP, alpha=ALPHA_BAR, label="R-UDP"),
    ]
    ax.legend(
        handles=legend_patches,
        loc="upper left",
        framealpha=0.92,
        fontsize=FONT_LEGEND,
        title="Protocolo",
        title_fontsize=FONT_LEGEND,
    )

    fig.text(
        0.5, -0.03,
        "Nota: Valores menores indicam transferência mais rápida. "
        "O aumento esperado de C→A reflete o impacto acumulado de perda e latência.",
        ha="center", fontsize=7.5, color="#666666", style="italic",
    )

    plt.tight_layout()

    caminho = output_dir / "grafico2_tempo_transferencia.png"
    fig.savefig(caminho, dpi=300, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"   ✓ Salvo: {caminho}")
    return caminho


# Gráfico 3 — Discrepância Aplicação vs Rede (Validação Cruzada)
def grafico_discrepancia(df: pd.DataFrame, output_dir: Path) -> Path:
    """
    Gráfico combinado de dois painéis (subplots):

    Painel (a): Tempo medido pela Aplicação (Python) vs Tempo de Rede (pcap/tshark)
                por protocolo e cenário — barras agrupadas duplas

    Painel (b): Discrepância percentual (Δt%) média entre a aplicação e a rede,
                linha com marcadores, separado por protocolo

    Ajuda a responder às Perguntas 1 e 3 do relatório
    """
    print("[GRÁFICO 3] Discrepância Aplicação vs Rede (Validação Cruzada)...")

    # Filtra apenas registros com pcap válido 
    df_ok = df[df["pcap_ok"] == True].copy() if "pcap_ok" in df.columns else df.copy()

    if df_ok.empty or "tempo_rede_s" not in df_ok.columns:
        print("   [AVISO] Sem dados de pcap válidos. Usando apenas dados de aplicação.")
        df_ok = df.copy()
        df_ok["tempo_rede_s"]    = np.nan
        df_ok["delta_tempo_pct"] = np.nan

    # Estatísticas por (protocolo, cenario)
    stats_app  = _agrupa_estatisticas(df_ok, "tempo_app_s")
    stats_rede = _agrupa_estatisticas(df_ok, "tempo_rede_s") if "tempo_rede_s" in df_ok.columns else None
    stats_disc = _agrupa_estatisticas(df_ok, "delta_tempo_pct") if "delta_tempo_pct" in df_ok.columns else None

    # Figura com dois subplots 
    fig, (ax1, ax2) = plt.subplots(
        1, 2,
        figsize=(14, 6),
        gridspec_kw={"width_ratios": [1.5, 1]},
    )
    fig.suptitle(
        "Gráfico 3 — Validação Cruzada: Aplicação vs Rede (Wireshark/TCPDump)",
        fontsize=FONT_TITLE, fontweight="bold", y=1.02,
    )

    # Painel (a): Comparação de tempo App × Rede
    # ----------------------------------------------
    protocolos = ["TCP", "RUDP"]
    largura    = 0.18
    n_cenarios = len(CENARIOS_ORDEM)

    # 4 grupos por posição: TCP-App, TCP-Rede, RUDP-App, RUDP-Rede
    grupos = [
        ("TCP",  "app",  "Tempo App (TCP)",   COR_TCP,  0.90, "///"),
        ("TCP",  "rede", "Tempo Rede (TCP)",   COR_TCP,  0.45, ""),
        ("RUDP", "app",  "Tempo App (R-UDP)",  COR_RUDP, 0.90, "///"),
        ("RUDP", "rede", "Tempo Rede (R-UDP)", COR_RUDP, 0.45, ""),
    ]
    x_base = np.arange(n_cenarios)
    n_grupos = len(grupos)
    offsets  = np.linspace(
        -largura * (n_grupos - 1) / 2,
         largura * (n_grupos - 1) / 2,
         n_grupos,
    )

    for gi, (proto, fonte, rotulo, cor, alpha, hatch) in enumerate(grupos):
        stats_ref = stats_app if fonte == "app" else stats_rede
        if stats_ref is None:
            continue

        sub = stats_ref[stats_ref["protocolo"] == proto].set_index("cenario")
        medias  = [sub.loc[c, "media"] if c in sub.index else np.nan for c in CENARIOS_ORDEM]
        desvios = [sub.loc[c, "std"]   if c in sub.index else 0       for c in CENARIOS_ORDEM]

        pos = x_base + offsets[gi]

        ax1.bar(
            pos, medias,
            width=largura,
            color=cor,
            alpha=alpha,
            label=rotulo,
            hatch=hatch,
            edgecolor="white" if not hatch else cor,
            linewidth=0.5,
            zorder=3,
        )

        # Barras de erro apenas para valores não-NaN
        medias_arr  = np.array(medias, dtype=float)
        desvios_arr = np.array(desvios, dtype=float)
        mask = ~np.isnan(medias_arr)

        if mask.any():
            ax1.errorbar(
                pos[mask], medias_arr[mask], yerr=desvios_arr[mask],
                fmt="none",
                color="#333333",
                capsize=3,
                capthick=1.2,
                elinewidth=1.4,
                zorder=4,
            )

    ax1.set_xticks(x_base)
    ax1.set_xticklabels(
        [LABEL_CENARIO[c] for c in CENARIOS_ORDEM],
        fontsize=FONT_TICK,
    )
    ax1.set_xlabel("Cenários de Rede", fontsize=FONT_AXIS, labelpad=8)
    ax1.set_ylabel("Tempo (s)", fontsize=FONT_AXIS, labelpad=8)
    ax1.grid(axis="y", linestyle="--", alpha=ALPHA_GRID, zorder=0)
    ax1.set_axisbelow(True)
    ax1.legend(
        loc="upper left",
        fontsize=7,
        framealpha=0.92,
        ncol=2,
    )

    # Painel (b): Discrepância percentual (Δt%) por cenário
    # ----------------------------------------------
    cores_proto = {"TCP": COR_TCP, "RUDP": COR_RUDP}
    marcadores  = {"TCP": "o", "RUDP": "s"}

    if stats_disc is not None and not stats_disc["media"].isna().all():
        for proto in protocolos:
            sub  = stats_disc[stats_disc["protocolo"] == proto].set_index("cenario")
            vals = [sub.loc[c, "media"] if c in sub.index else np.nan for c in CENARIOS_ORDEM]
            stds = [sub.loc[c, "std"]   if c in sub.index else 0       for c in CENARIOS_ORDEM]

            vals_arr = np.array(vals, dtype=float)
            stds_arr = np.array(stds, dtype=float)

            ax2.plot(
                CENARIOS_ORDEM, vals_arr,
                color=cores_proto[proto],
                marker=marcadores[proto],
                linewidth=2,
                markersize=8,
                label=LABEL_PROTOCOLO[proto],
                zorder=3,
            )
            ax2.fill_between(
                CENARIOS_ORDEM,
                vals_arr - stds_arr,
                vals_arr + stds_arr,
                color=cores_proto[proto],
                alpha=0.15,
                zorder=2,
            )

            # Anotações dos valores
            for cenario, val, std in zip(CENARIOS_ORDEM, vals_arr, stds_arr):
                if not np.isnan(val):
                    ax2.annotate(
                        f"{val:.1f}%",
                        xy=(cenario, val),
                        xytext=(8, 4),
                        textcoords="offset points",
                        fontsize=8,
                        color=cores_proto[proto],
                        fontweight="bold",
                    )
    else:
        # Sem dados pcap - exibe mensagem informativa no painel
        ax2.text(
            0.5, 0.5,
            "Dados de captura pcap\nnão disponíveis.\n\n"
            "Execute validacao_cruzada.py\napós os testes.",
            ha="center", va="center",
            transform=ax2.transAxes,
            fontsize=10, color="#888888",
            style="italic",
            bbox=dict(boxstyle="round,pad=0.5", facecolor="#f5f5f5", edgecolor="#cccccc"),
        )

    ax2.set_xlabel("Cenários de Rede", fontsize=FONT_AXIS, labelpad=8)
    ax2.set_ylabel("Discrepância Δt (%)", fontsize=FONT_AXIS, labelpad=8)
    ax2.grid(linestyle="--", alpha=ALPHA_GRID, zorder=0)
    ax2.set_axisbelow(True)
    ax2.legend(
        loc="upper left",
        fontsize=FONT_LEGEND,
        framealpha=0.92,
    )
    ax2.yaxis.set_minor_locator(AutoMinorLocator(4))

    # Nota de rodapé 
    fig.text(
        0.5, -0.03,
        "Discrepância esperada: tempo da aplicação inclui overhead de I/O, "
        "chamadas de sistema e bufferização. Tempo de rede reflete apenas os pacotes capturados.",
        ha="center", fontsize=7.5, color="#666666", style="italic",
    )

    plt.tight_layout()

    caminho = output_dir / "grafico3_discrepancia_app_rede.png"
    fig.savefig(caminho, dpi=300, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"   ✓ Salvo: {caminho}")
    return caminho


# Gráfico - Tabela Estatística Completa (Resumo para o Relatório)
# ----------------------------------------------

def grafico_tabela_resumo(df: pd.DataFrame, output_dir: Path) -> Path:
    """ Gera uma tabela visual com as estatísticas completas (min, média, máx, std) de throughput e tempo para cada combinação protocolo × cenário """

    print("[GRÁFICO 4] Tabela Resumo Estatístico...")

    # Agrupa
    grp = df.groupby(["protocolo", "cenario"])

    linhas = []
    for (proto, cenario), sub in grp:
        tput = sub["throughput_app_mbps"].dropna()
        tempo = sub["tempo_app_s"].dropna()
        rtx   = sub["retransmits"].dropna() if "retransmits" in sub.columns else pd.Series(dtype=float)

        linhas.append({
            "Protocolo": LABEL_PROTOCOLO.get(proto, proto),
            "Cenário": cenario,
            "n": len(sub),
            "Tput Mín (Mbps)": f"{tput.min():.4f}" if not tput.empty else "—",
            "Tput Méd (Mbps)": f"{tput.mean():.4f}" if not tput.empty else "—",
            "Tput Máx (Mbps)": f"{tput.max():.4f}" if not tput.empty else "—",
            "Tput DP (Mbps)":  f"{tput.std():.4f}"  if len(tput) > 1 else "—",
            "Tempo Mín (s)":  f"{tempo.min():.4f}"  if not tempo.empty else "—",
            "Tempo Méd (s)":  f"{tempo.mean():.4f}" if not tempo.empty else "—",
            "Tempo Máx (s)":  f"{tempo.max():.4f}"  if not tempo.empty else "—",
            "Tempo DP (s)":   f"{tempo.std():.4f}"  if len(tempo) > 1 else "—",
            "Retransm. Méd": f"{rtx.mean():.1f}" if not rtx.empty else "N/A",
        })

    df_tabela = pd.DataFrame(linhas)
    df_tabela = df_tabela.sort_values(["Protocolo", "Cenário"]).reset_index(drop=True)

    # Renderiza como imagem
    fig, ax = plt.subplots(
        figsize=(16, max(3.5, len(df_tabela) * 0.65 + 1.5))
    )
    ax.axis("off")

    col_labels  = list(df_tabela.columns)
    cell_text   = df_tabela.values.tolist()

    tabela = ax.table(
        cellText=cell_text,
        colLabels=col_labels,
        cellLoc="center",
        loc="center",
    )
    tabela.auto_set_font_size(False)
    tabela.set_fontsize(8.5)
    tabela.scale(1, 1.5)

    # Estiliza cabeçalho
    for j in range(len(col_labels)):
        tabela[0, j].set_facecolor("#2c3e50")
        tabela[0, j].set_text_props(color="white", fontweight="bold")

    # Estiliza linhas alternadas
    for i in range(1, len(df_tabela) + 1):
        proto_val = df_tabela.iloc[i - 1]["Protocolo"]
        cor_linha = "#d6eaf8" if proto_val == "TCP" else "#fde8e8"
        for j in range(len(col_labels)):
            tabela[i, j].set_facecolor(cor_linha)

    plt.tight_layout()

    caminho = output_dir / "tabela_resumo_estatistico.png"
    fig.savefig(caminho, dpi=300, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"   ✓ Salvo: {caminho}")
    return caminho


# Carregamento e Validação do CSV
# ----------------------------------------------

def carregar_csv(caminho_csv: Path, simular: bool = False) -> pd.DataFrame:
    """
    Carrega o metricas_consolidadas.csv
    """
    if not caminho_csv.exists():
        if simular:
            print(f"[AVISO] '{caminho_csv}' não encontrado. Usando dados SIMULADOS para demonstração.")
            print("         Execute os testes reais e rode novamente com o CSV gerado.\n")
            return _gerar_dados_simulados()
        else:
            print(f"[ERRO] Arquivo não encontrado: {caminho_csv}")
            print("       Use --simular para gerar dados demonstrativos.")
            sys.exit(1)

    print(f"[INFO] Carregando: {caminho_csv}")
    df = pd.read_csv(caminho_csv, encoding="utf-8")

    # Valida colunas mínimas obrigatórias 
    colunas_obrigatorias = {
        "protocolo", "cenario", "tempo_app_s", "throughput_app_mbps",
    }
    faltando = colunas_obrigatorias - set(df.columns)
    if faltando:
        print(f"[ERRO] Colunas ausentes no CSV: {faltando}")
        print(f"       Colunas encontradas: {list(df.columns)}")
        sys.exit(1)

    # Normalização de protocolo 
    df["protocolo"] = df["protocolo"].str.upper().str.strip()
    df["cenario"]   = df["cenario"].str.upper().str.strip()

    # Filtra apenas cenários e protocolos conhecidos
    df = df[df["cenario"].isin(CENARIOS_ORDEM)]
    df = df[df["protocolo"].isin(["TCP", "RUDP"])]

    if df.empty:
        print("[ERRO] DataFrame vazio após filtros. Verifique os valores de 'protocolo' e 'cenario'.")
        sys.exit(1)

    #  pcap_ok pode ser string "True"/"False"
    if "pcap_ok" in df.columns:
        df["pcap_ok"] = df["pcap_ok"].map(
            lambda v: str(v).strip().lower() in ("true", "1", "yes")
        )

    print(f"[INFO] Dados carregados: {len(df)} registros | "
          f"Protocolos: {df['protocolo'].unique()} | "
          f"Cenários: {sorted(df['cenario'].unique())}")
    return df


# Interface do terminal e fluxo principal
# ----------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Gera gráficos estatísticos para o Relatório SBC — Redes II UFPI",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  python3 gerar_graficos.py\n"
            "  python3 gerar_graficos.py --csv meus_dados.csv\n"
            "  python3 gerar_graficos.py --simular          # modo demonstração\n"
            "  python3 gerar_graficos.py --show             # exibe na tela\n"
        ),
    )
    p.add_argument(
        "--csv", default="metricas_consolidadas.csv",
        help="Caminho do CSV gerado por validacao_cruzada.py (padrão: metricas_consolidadas.csv)",
    )
    p.add_argument(
        "--out", default="graficos_resultado",
        help="Pasta de saída para os PNGs (padrão: graficos_resultado/)",
    )
    p.add_argument(
        "--simular", action="store_true",
        help="Gera dados simulados se o CSV não existir (modo demonstração)",
    )
    p.add_argument(
        "--show", action="store_true",
        help="Exibe os gráficos na tela após salvar (requer display)",
    )
    p.add_argument(
        "--sem-tabela", action="store_true",
        help="Não gera a tabela resumo (Gráfico 4 bônus)",
    )
    return p.parse_args()


def main():
    args = parse_args()

    configurar_estilo()

    # Prepara diretório de saída
    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n{'═' * 60}")
    print(f"  Gerador de Gráficos — Redes II UFPI")
    print(f"{'═' * 60}")
    print(f"  CSV de entrada : {args.csv}")
    print(f"  Pasta de saída : {output_dir.resolve()}")
    print(f"{'═' * 60}\n")

    #  Carrega dados 
    df = carregar_csv(Path(args.csv), simular=args.simular)

    # Gera gráficos
    arquivos_gerados = []

    arquivos_gerados.append(grafico_throughput(df, output_dir))
    arquivos_gerados.append(grafico_tempo(df, output_dir))
    arquivos_gerados.append(grafico_discrepancia(df, output_dir))

    if not args.sem_tabela:
        arquivos_gerados.append(grafico_tabela_resumo(df, output_dir))

    # Resumo final
    print(f"\n{'═' * 60}")
    print("  GRÁFICOS GERADOS COM SUCESSO")
    print(f"{'═' * 60}")
    for arq in arquivos_gerados:
        tamanho_kb = arq.stat().st_size / 1024
        print(f"  ✓ {arq.name:<45} ({tamanho_kb:.1f} KB)")
    print(f"\n  Pasta: {output_dir.resolve()}")
    print(f"{'═' * 60}\n")

    # Exibe na tela (opcional)
    if args.show:
        try:
            for arq in arquivos_gerados:
                img = plt.imread(str(arq))
                fig, ax = plt.subplots(figsize=(14, 8))
                ax.imshow(img)
                ax.axis("off")
                plt.tight_layout()
            plt.show()
        except Exception as e:
            print(f"[AVISO] Não foi possível exibir na tela: {e}")


if __name__ == "__main__":
    main()