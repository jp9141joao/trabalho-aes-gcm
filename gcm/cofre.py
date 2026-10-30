"""
Cofre de arquivos com AES-256-GCM: aplicação prática do trabalho.

Protege "dados em repouso" (Aula 05) e segue as boas práticas de gestão de chaves:
  - a chave NÃO é a senha: é derivada dela com scrypt + salt aleatório (KDF lento,
    que dificulta força bruta, como o "hash com salt" da Aula 02);
  - o nonce é aleatório e novo a cada cifragem (nunca reutilizado);
  - o cabeçalho (versão, salt, nonce) vai como AAD: viaja em claro, mas é autenticado;
  - usa a AESGCM da biblioteca `cryptography` (auditada), não a versão didática.

Formato do arquivo .cofre:
    MAGICA (9 bytes) | salt (16) | nonce (12) | texto cifrado | tag (16)

Uso:
    python -m gcm.cofre cifrar   relatorio.pdf          -> relatorio.pdf.cofre
    python -m gcm.cofre decifrar relatorio.pdf.cofre    -> relatorio.pdf
"""

import argparse
import getpass
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGICA = b"GCMCOFRE1"
TAM_SALT, TAM_NONCE = 16, 12
TAM_CABECALHO = len(MAGICA) + TAM_SALT + TAM_NONCE

# Custo do scrypt (2^15 => ~32 MiB de memória por tentativa de senha).
CUSTO_SCRYPT = 2**15


class SenhaOuArquivoInvalido(Exception):
    """Senha errada, ou o arquivo foi corrompido/adulterado (o GCM não distingue os dois)."""


def derivar_chave(senha: str, salt: bytes, custo: int = CUSTO_SCRYPT) -> bytes:
    """Transforma a senha em uma chave AES de 256 bits."""
    return Scrypt(salt=salt, length=32, n=custo, r=8, p=1).derive(senha.encode("utf-8"))


def cifrar_bytes(dados: bytes, senha: str, custo: int = CUSTO_SCRYPT) -> bytes:
    salt, nonce = os.urandom(TAM_SALT), os.urandom(TAM_NONCE)
    cabecalho = MAGICA + salt + nonce
    chave = derivar_chave(senha, salt, custo)
    return cabecalho + AESGCM(chave).encrypt(nonce, dados, cabecalho)


def decifrar_bytes(conteudo: bytes, senha: str, custo: int = CUSTO_SCRYPT) -> bytes:
    if len(conteudo) < TAM_CABECALHO + 16 or not conteudo.startswith(MAGICA):
        raise SenhaOuArquivoInvalido("não é um arquivo .cofre válido")
    cabecalho, corpo = conteudo[:TAM_CABECALHO], conteudo[TAM_CABECALHO:]
    salt = cabecalho[len(MAGICA):len(MAGICA) + TAM_SALT]
    nonce = cabecalho[-TAM_NONCE:]
    chave = derivar_chave(senha, salt, custo)
    try:
        return AESGCM(chave).decrypt(nonce, corpo, cabecalho)
    except InvalidTag:
        raise SenhaOuArquivoInvalido("senha incorreta ou arquivo adulterado") from None


def _destino_livre(caminho: Path) -> Path:
    """Evita sobrescrever um arquivo que já existe."""
    if not caminho.exists():
        return caminho
    return caminho.with_name(f"{caminho.stem}.decifrado{caminho.suffix}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Cofre de arquivos com AES-256-GCM")
    parser.add_argument("acao", choices=["cifrar", "decifrar"])
    parser.add_argument("arquivo", type=Path)
    args = parser.parse_args(argv)

    if not args.arquivo.is_file():
        print(f"Arquivo não encontrado: {args.arquivo}", file=sys.stderr)
        return 1

    # getpass não mostra a senha na tela nem a deixa no histórico do terminal.
    senha = getpass.getpass("Senha: ")
    if args.acao == "cifrar":
        if senha != getpass.getpass("Repita a senha: "):
            print("As senhas não conferem.", file=sys.stderr)
            return 1
        destino = args.arquivo.with_name(args.arquivo.name + ".cofre")
        destino.write_bytes(cifrar_bytes(args.arquivo.read_bytes(), senha))
    else:
        try:
            dados = decifrar_bytes(args.arquivo.read_bytes(), senha)
        except SenhaOuArquivoInvalido as erro:
            print(f"Falha: {erro}.", file=sys.stderr)
            return 1
        nome = args.arquivo.name.removesuffix(".cofre")
        destino = _destino_livre(args.arquivo.with_name(nome))
        destino.write_bytes(dados)

    print(f"Pronto: {destino}")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    sys.exit(main())
