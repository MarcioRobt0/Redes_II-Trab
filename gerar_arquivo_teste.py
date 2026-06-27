# Gera um arquivo binário de tamanho configurável para ser usado como payload nos testes de transferência TCP e R-UDP.

import os
import hashlib
import argparse

def gerar(tamanho_mb: float = 1.0, nome: str = "") -> str:
    tamanho_bytes = int(tamanho_mb * 1024 * 1024)
    if not nome:
        # Formata com sufixos corretos dependendo do tamanho
        if tamanho_mb < 1.0:
            nome = f"test_payload_{int(tamanho_mb * 1024)}KB.bin"
        else:
            nome = f"test_payload_{int(tamanho_mb)}MB.bin"

    dados = os.urandom(tamanho_bytes)

    with open(nome, "wb") as f:
        f.write(dados)

    md5 = hashlib.md5(dados).hexdigest()
    print(f"Arquivo criado : {nome}")
    print(f"Tamanho        : {tamanho_bytes:,} bytes")
    print(f"MD5 (referência): {md5}")
    print("\nGuarde o MD5 acima. Após receber o arquivo no servidor,")
    print("calcule o MD5 do arquivo recebido e compare para validar integridade.")
    return nome

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--size", type=float, default=1.0, help="Tamanho em MB (padrão: 1.0)")
    p.add_argument("--name", default="",          help="Nome do arquivo de saída")
    args = p.parse_args()
    gerar(args.size, args.name)