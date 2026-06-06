set -euo pipefail

# Executa o pipeline completo:
#   1. validacao_cruzada.py - logs/dados/metricas_consolidadas.csv
#   2. gerar_graficos.py    - graficos_resultado/

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO ]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN ]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_section() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════${NC}"; \
                echo -e "${BOLD}${CYAN}  $*${NC}"; \
                echo -e "${BOLD}${CYAN}══════════════════════════════════════════════${NC}"; }

# Diretórios
DADOS_DIR="logs/dados"
GRAFICOS_DIR="graficos_resultado"
CSV_SAIDA="${DADOS_DIR}/metricas_consolidadas.csv"

log_section "PIPELINE COMPLETO — Validação + Gráficos"


# Etapa 1: Criar diretório de dados
# ----------------------------
log_info "Criando diretório: ${DADOS_DIR}"
mkdir -p "${DADOS_DIR}"


# Etapa 2: Executar validacao_cruzada.py
# ----------------------------
log_section "ETAPA 1 — Validação Cruzada"
log_info "Executando validacao_cruzada.py..."
log_info "Saída: ${CSV_SAIDA}"

python3 validacao_cruzada.py --output "${CSV_SAIDA}"

if [[ ! -f "${CSV_SAIDA}" ]]; then
    log_error "Arquivo ${CSV_SAIDA} não foi gerado!"
    exit 1
fi

log_info "✓ CSV gerado com sucesso: ${CSV_SAIDA}"
csv_size=$(wc -l < "${CSV_SAIDA}")
log_info "  Linhas: ${csv_size}"


# Etapa 3: Executar gerar_graficos.py
# ----------------------------
log_section "ETAPA 2 — Geração de Gráficos"
log_info "Executando gerar_graficos.py..."
log_info "CSV de entrada: ${CSV_SAIDA}"
log_info "Pasta de saída: ${GRAFICOS_DIR}"

python3 gerar_graficos.py \
    --csv "${CSV_SAIDA}" \
    --out "${GRAFICOS_DIR}"

if [[ ! -d "${GRAFICOS_DIR}" ]]; then
    log_error "Pasta ${GRAFICOS_DIR} não foi criada!"
    exit 1
fi


# Resumo final
# ----------------------------
log_section "PIPELINE CONCLUÍDO COM SUCESSO"
log_info "Dados consolidados  : ${CSV_SAIDA}"
log_info "Gráficos gerados em : $(cd ${GRAFICOS_DIR} && pwd)"
log_info ""
log_info "Arquivos de gráficos:"
ls -lh "${GRAFICOS_DIR}"/*.png 2>/dev/null | awk '{print "  ✓ " $9 " (" $5 ")"}'

echo -e "\n${GREEN}Pronto para análise!${NC}\n"
