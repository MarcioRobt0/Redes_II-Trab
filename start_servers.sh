set -euo pipefail

# Script de bootstrap do container de servidor
# Inicia os dois servidores TCP e R-UDP, e encerra o container se qualquer um dos dois parar

echo "[SERVER] Iniciando servidores..."

python3 tcp_server.py \
  --host 0.0.0.0 \
  --port 5001 \
  --output-dir /app/received_tcp \
  --matricula "${MATRICULA:-20239000313}" \
  --nome "${NOME_ALUNO:-Marcio Rodrigues}" &
PID_TCP=$!

python3 rudp_server.py \
  --host 0.0.0.0 \
  --port 9000 \
  --output-dir /app/received_files \
  --matricula "${MATRICULA:-20239000313}" \
  --nome "${NOME_ALUNO:-Marcio Rodrigues}" &
PID_RUDP=$!

echo "[SERVER] TCP pid=${PID_TCP}"
echo "[SERVER] R-UDP pid=${PID_RUDP}"
echo "[SERVER] Ambos os servidores em execução. Aguardando..."

wait -n ${PID_TCP} ${PID_RUDP}
STATUS=$?

echo "[SERVER] Um servidor terminou com status=${STATUS}. Encerrando ambos..."
kill ${PID_TCP} ${PID_RUDP} 2>/dev/null || true
wait || true
exit ${STATUS}
