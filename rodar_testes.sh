set -euo pipefail   # sai imediatamente em qualquer erro não tratado

# Configurações - lidas do ambiente (definidas no docker-compose.yml) ou com fallback para valores padrão
SERVER_HOST="${SERVER_HOST:-172.20.0.10}"
TCP_PORT="${TCP_PORT:-5001}"
RUDP_PORT="${RUDP_PORT:-9000}"
MATRICULA="${MATRICULA:-20239000313}"
NOME_ALUNO="${NOME_ALUNO:-Marcio Rodrigues}"
ARQUIVO_TESTE="${ARQUIVO_TESTE:-test_payload_1MB.bin}"
NUM_RUNS="${NUM_RUNS:-15}"         # execuções por cenário (10–30)
IFACE="${IFACE:-eth0}"             # interface de rede do container

APP_DIR="/app"
LOG_DIR="${APP_DIR}/logs"
PCAP_DIR="${APP_DIR}/pcaps"

# --------------------------------------
# Cores para output legível no terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'   # No Color


# Funções auxiliares
log_info()    { echo -e "${GREEN}[INFO ]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN ]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_section() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════${NC}"; \
                echo -e "${BOLD}${CYAN}  $*${NC}"; \
                echo -e "${BOLD}${CYAN}══════════════════════════════════════════════${NC}"; }

# Garante que as pastas de saída existam
setup_dirs() {
    mkdir -p "${LOG_DIR}/tcp" \
             "${LOG_DIR}/rudp" \
             "${PCAP_DIR}/tcp" \
             "${PCAP_DIR}/rudp"
    log_info "Diretórios de saída prontos."
}


# tc qdisc - gerenciamento de condições de rede

# Remove qualquer regra tc anterior na interface
tc_clear() {
    log_info "Limpando regras tc em ${IFACE}…"
    tc qdisc del dev "${IFACE}" root 2>/dev/null || true
}

# Aplica as condições do cenário na interface eth0
tc_apply() {
    local loss_pct="$1"   # 0, 5, 10
    local delay_ms="$2"   # 10, 50, 100

    tc_clear

    if [[ "${loss_pct}" == "0" ]]; then
        # Cenário A: apenas delay, sem perda
        tc qdisc add dev "${IFACE}" root netem \
            delay "${delay_ms}ms"
        log_info "tc aplicado → delay=${delay_ms}ms | perda=0%"
    else
        # Cenários B e C: delay + perda
        tc qdisc add dev "${IFACE}" root netem \
            delay "${delay_ms}ms" \
            loss "${loss_pct}%"
        log_info "tc aplicado → delay=${delay_ms}ms | perda=${loss_pct}%"
    fi
}

# Mostra as regras tc ativas (para confirmar no log)
tc_show() {
    echo -e "${CYAN}[tc status]${NC}"
    tc qdisc show dev "${IFACE}"
}


# tcpdump - captura de tráfego
TCPDUMP_PID=""

# Inicia captura em background
# Uso: tcpdump_start <caminho_do_pcap> <porta_de_filtro>
tcpdump_start() {
    local pcap_file="$1"
    local port="$2"

    log_info "Iniciando tcpdump → ${pcap_file}"
    tcpdump -i "${IFACE}" -w "${pcap_file}" \
        "port ${port}" \
        -q --no-promiscuous-mode \
        2>/dev/null &

    TCPDUMP_PID=$!
    sleep 0.5   # pequena pausa para garantir que o tcpdump abriu a interface
    log_info "tcpdump PID=${TCPDUMP_PID}"
}

# Para a captura
tcpdump_stop() {
    if [[ -n "${TCPDUMP_PID}" ]] && kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
        log_info "Parando tcpdump PID=${TCPDUMP_PID}…"
        kill -SIGTERM "${TCPDUMP_PID}" 2>/dev/null || true
        wait "${TCPDUMP_PID}" 2>/dev/null || true
        TCPDUMP_PID=""
    fi
}

# Garante que o tcpdump seja parado mesmo se o script falhar
trap 'tcpdump_stop; tc_clear' EXIT INT TERM

# Execução de um único run TCP
run_tcp() {
    local cenario="$1"
    local run_num="$2"
    local log_csv="$3"
    local run_fmt
    run_fmt=$(printf "%02d" "${run_num}")
    local pcap_file="${PCAP_DIR}/tcp/cenario_${cenario}_tcp_run${run_fmt}.pcap"

    log_info "→ TCP | Cenário ${cenario} | Run ${run_num}/${NUM_RUNS}"

    tcpdump_start "${pcap_file}" "${TCP_PORT}"

    python3 "${APP_DIR}/tcp_client.py" \
        "${APP_DIR}/${ARQUIVO_TESTE}" \
        --host  "${SERVER_HOST}" \
        --port  "${TCP_PORT}" \
        --matricula "${MATRICULA}" \
        --nome  "${NOME_ALUNO}" \
        --scenario "${cenario}" \
        --log-file "${log_csv}" \
        --chunk 4096

    tcpdump_stop
    log_info "Run ${run_num} TCP concluído. pcap: ${pcap_file}"
}

# Execução de um único run R-UDP
run_rudp() {
    local cenario="$1"
    local run_num="$2"
    local log_csv="$3"
    local run_fmt
    run_fmt=$(printf "%02d" "${run_num}")
    local pcap_file="${PCAP_DIR}/rudp/cenario_${cenario}_rudp_run${run_fmt}.pcap"

    log_info "→ R-UDP | Cenário ${cenario} | Run ${run_num}/${NUM_RUNS}"

    tcpdump_start "${pcap_file}" "${RUDP_PORT}"

    python3 "${APP_DIR}/rudp_client.py" \
        "${APP_DIR}/${ARQUIVO_TESTE}" \
        --host  "${SERVER_HOST}" \
        --port  "${RUDP_PORT}" \
        --matricula "${MATRICULA}" \
        --nome  "${NOME_ALUNO}" \
        --timeout 2.0 \
        --retries 10 \
        --chunk 1024 \
        --scenario "${cenario}" \
        --log-file "${log_csv}"

    tcpdump_stop
    log_info "Run ${run_num} R-UDP concluído. pcap: ${pcap_file}"
}

# Loop de cenários e runs
rodar_cenario() {
    local cenario="$1"     # A, B ou C
    local loss_pct="$2"    # 0, 5, 10
    local delay_ms="$3"    # 10, 50, 100

    log_section "CENÁRIO ${cenario} | perda=${loss_pct}% | delay=${delay_ms}ms"

    # Aplica condições de rede
    tc_apply "${loss_pct}" "${delay_ms}"
    tc_show

    local log_tcp="${LOG_DIR}/tcp/logs_tcp_cenario_${cenario}.csv"
    local log_rudp="${LOG_DIR}/rudp/logs_rudp_cenario_${cenario}.csv"

    # Runs TCP 
    log_section "TCP — Cenário ${cenario} (${NUM_RUNS} runs)"
    for (( i=1; i<=NUM_RUNS; i++ )); do
        run_tcp "${cenario}" "${i}" "${log_tcp}"
        sleep 1   # intervalo entre runs para estabilizar a rede
    done
    log_info "TCP Cenário ${cenario}: ${NUM_RUNS} runs concluídos."

    # Runs R-UDP 
    log_section "R-UDP — Cenário ${cenario} (${NUM_RUNS} runs)"
    for (( i=1; i<=NUM_RUNS; i++ )); do
        run_rudp "${cenario}" "${i}" "${log_rudp}"
        sleep 1
    done
    log_info "R-UDP Cenário ${cenario}: ${NUM_RUNS} runs concluídos."
}

# Verificações pré-execução

pre_check() {
    log_section "PRÉ-CHECAGEM"

    # Arquivo de teste existe?
    if [[ ! -f "${APP_DIR}/${ARQUIVO_TESTE}" ]]; then
        log_error "Arquivo de teste '${ARQUIVO_TESTE}' não encontrado em ${APP_DIR}."
        log_error "Gere-o com: python3 gerar_arquivo_teste.py --size 1"
        exit 1
    fi
    log_info "Arquivo de teste: ${APP_DIR}/${ARQUIVO_TESTE} ✓"

    # Servidor TCP acessível?
    if ! python3 -c "
        import socket, sys
        s = socket.socket()
        s.settimeout(3)
        try:
        s.connect(('${SERVER_HOST}', ${TCP_PORT}))
        s.close()
        sys.exit(0)
        except:
        sys.exit(1)
        " 2>/dev/null; then
        log_warn "Servidor TCP (${SERVER_HOST}:${TCP_PORT}) não respondeu — verifique se o servidor está rodando."
        log_warn "Continuando mesmo assim (pode falhar nos testes TCP)."
    else
        log_info "Servidor TCP acessível ✓"
    fi

    # tc disponível?
    if ! command -v tc &>/dev/null; then
        log_error "Comando 'tc' não encontrado. Instale iproute2."
        exit 1
    fi
    log_info "Comando tc: $(tc -V 2>&1 | head -1) ✓"

    # tcpdump disponível?
    if ! command -v tcpdump &>/dev/null; then
        log_error "tcpdump não encontrado."
        exit 1
    fi
    log_info "tcpdump: $(tcpdump --version 2>&1 | head -1) ✓"

    log_info "Pré-checagem concluída."
}

# MAIN
# ------------------------------------

main() {
    log_section "INÍCIO DOS TESTES AUTOMATIZADOS"
    log_info "Servidor     : ${SERVER_HOST}"
    log_info "Arquivo teste: ${ARQUIVO_TESTE}"
    log_info "Runs/cenário : ${NUM_RUNS}"
    log_info "Matrícula    : ${MATRICULA}"
    log_info "Interface    : ${IFACE}"

    setup_dirs
    pre_check

    local inicio
    inicio=$(date +%s)

    # Três cenários
    rodar_cenario "A"  "0"  "10"    # 0% perda / 10ms delay
    rodar_cenario "B"  "5"  "50"    # 5% perda / 50ms delay
    rodar_cenario "C"  "10" "100"   # 10% perda / 100ms delay

    # Limpa regras tc ao final
    tc_clear

    local fim
    fim=$(date +%s)
    local duracao=$(( fim - inicio ))

    log_section "TESTES CONCLUÍDOS"
    log_info "Duração total  : $((duracao / 60))m $((duracao % 60))s"
    log_info "Logs TCP       : ${LOG_DIR}/tcp/"
    log_info "Logs R-UDP     : ${LOG_DIR}/rudp/"
    log_info "Capturas .pcap : ${PCAP_DIR}/"
    log_info ""
    log_info "Próximo passo  : python3 validacao_cruzada.py"
}

main "$@"