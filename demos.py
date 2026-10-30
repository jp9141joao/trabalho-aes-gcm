"""
Demonstrações do trabalho de AES-GCM (para rodar ao vivo na apresentação).

    python demos.py          -> roda as 4 demonstrações em sequência
    python demos.py 3        -> roda só a demonstração 3

1. Básico:      cifrar e decifrar com a implementação didática e conferir com a biblioteca
2. Adulteração: no modo CTR puro o atacante muda o valor de uma transferência; no GCM é detectado
3. ECB x GCM:   a "imagem cifrada" com ECB ainda mostra o desenho; com GCM vira ruído
4. Nonce:       reutilizar o nonce com a mesma chave entrega a mensagem ao atacante
"""

import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gcm import gcm_didatico as gcm

PASTA_IMAGENS = Path(__file__).parent / "imagens"


def titulo(texto: str) -> None:
    print("\n" + "=" * 70 + f"\n  {texto}\n" + "=" * 70)


def hexa(dados: bytes, limite: int = 32) -> str:
    texto = dados.hex(" ")
    return texto if len(dados) <= limite else dados[:limite].hex(" ") + " ..."


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# 1. Básico
# ---------------------------------------------------------------------------

def demo_basico() -> None:
    titulo("1. Cifrar e decifrar com AES-GCM")
    chave = os.urandom(32)          # AES-256
    nonce = os.urandom(12)          # 96 bits: o tamanho recomendado
    mensagem = "Nota final de Engenharia de Segurança: 10".encode()
    aad = b"aluno=joao;disciplina=ENGSOFT8"

    cifrado, tag = gcm.cifrar(chave, nonce, mensagem, aad)
    print(f"Chave (256 bits):   {hexa(chave)}")
    print(f"Nonce (96 bits):    {hexa(nonce)}")
    print(f"AAD (em claro):     {aad.decode()}")
    print(f"Texto original:     {mensagem.decode()}  ({len(mensagem)} bytes)")
    print(f"Texto cifrado:      {hexa(cifrado)}  ({len(cifrado)} bytes, mesmo tamanho: sem padding)")
    print(f"Tag (128 bits):     {hexa(tag)}")

    biblioteca = AESGCM(chave).encrypt(nonce, mensagem, aad)
    print(f"\nIgual à biblioteca `cryptography`? {'SIM' if cifrado + tag == biblioteca else 'NÃO'}")
    print(f"Decifrado:          {gcm.decifrar(chave, nonce, cifrado, tag, aad).decode()}")


# ---------------------------------------------------------------------------
# 2. Adulteração: CTR sem autenticação x GCM
# ---------------------------------------------------------------------------

def trocar_caractere(cifrado: bytes, posicao: int, original: str, novo: str) -> bytes:
    """
    Ataque de maleabilidade: o atacante NÃO conhece a chave, mas sabe (ou chuta)
    o texto original numa posição. Como cifrado = texto XOR keystream, fazer
    XOR com (original XOR novo) troca o caractere no texto decifrado.
    """
    alterado = bytearray(cifrado)
    alterado[posicao] ^= ord(original) ^ ord(novo)
    return bytes(alterado)


def demo_adulteracao() -> None:
    titulo("2. Adulteração: modo CTR puro x GCM")
    chave, nonce = os.urandom(32), os.urandom(12)
    mensagem = b"Transferir R$ 100,00 para a conta 1234-5"
    posicao = mensagem.index(b"100,00")
    print(f"Mensagem original:  {mensagem.decode()}")
    print("O atacante intercepta o texto cifrado e troca o '1' por '9', sem saber a chave.\n")

    # (a) CTR puro: só confidencialidade, nenhuma integridade
    ctr = Cipher(algorithms.AES(chave), modes.CTR(nonce + b"\x00\x00\x00\x02"))
    cifrado = ctr.encryptor().update(mensagem)
    adulterado = trocar_caractere(cifrado, posicao, "1", "9")
    print("[CTR sem autenticação]")
    print(f"  Receptor decifra:  {ctr.decryptor().update(adulterado).decode()}")
    print("  -> aceito sem nenhum aviso! O valor virou R$ 900,00.\n")

    # (b) GCM: a mesma alteração é detectada pela tag
    cifrado, tag = gcm.cifrar(chave, nonce, mensagem)
    adulterado = trocar_caractere(cifrado, posicao, "1", "9")
    print("[AES-GCM]")
    try:
        gcm.decifrar(chave, nonce, adulterado, tag)
    except gcm.TagInvalida as erro:
        print(f"  Receptor recusa:   {erro}")

    # (c) GCM: alterar a AAD (cabeçalho em claro) também é detectado
    aad = b"origem=conta-0001"
    cifrado, tag = gcm.cifrar(chave, nonce, mensagem, aad)
    try:
        gcm.decifrar(chave, nonce, cifrado, tag, b"origem=conta-6666")
    except gcm.TagInvalida:
        print("  Trocar a AAD 'origem=conta-0001' -> 'origem=conta-6666' também é recusado.")


# ---------------------------------------------------------------------------
# 3. ECB x GCM em uma imagem
# ---------------------------------------------------------------------------

def gerar_imagem(largura: int = 512, altura: int = 256):
    """Desenha uma imagem com áreas de cor uniforme (o pior caso para o ECB)."""
    from PIL import Image, ImageDraw, ImageFont

    img = Image.new("RGB", (largura, altura), "white")
    desenho = ImageDraw.Draw(img)
    desenho.ellipse((20, 40, 196, 216), fill=(44, 100, 170))
    desenho.rectangle((330, 30, 490, 120), fill=(82, 172, 52))
    desenho.text((215, 140), "GCM", fill="black", font=ImageFont.load_default(size=96))
    return img


def cifrar_pixels_ecb(chave: bytes, pixels: bytes) -> bytes:
    completo = pixels + b"\x00" * ((-len(pixels)) % 16)
    cifrado = Cipher(algorithms.AES(chave), modes.ECB()).encryptor().update(completo)
    return cifrado[:len(pixels)]


def cifrar_pixels_gcm(chave: bytes, pixels: bytes) -> bytes:
    return AESGCM(chave).encrypt(os.urandom(12), pixels, None)[:len(pixels)]  # sem a tag, só para exibir


def demo_ecb_vs_gcm(pasta: Path = PASTA_IMAGENS) -> Path:
    from PIL import Image, ImageDraw, ImageFont

    titulo("3. Por que o ECB é inseguro: ECB x GCM em uma imagem")
    pasta.mkdir(exist_ok=True)
    chave = os.urandom(32)
    original = gerar_imagem()
    pixels = original.tobytes()

    paineis = {
        "Original": original,
        "AES-ECB": Image.frombytes("RGB", original.size, cifrar_pixels_ecb(chave, pixels)),
        "AES-GCM": Image.frombytes("RGB", original.size, cifrar_pixels_gcm(chave, pixels)),
    }
    fonte = ImageFont.load_default(size=28)
    largura, altura = original.size
    comparacao = Image.new("RGB", (largura * 3 + 40, altura + 60), "white")
    for i, (rotulo, img) in enumerate(paineis.items()):
        x = i * (largura + 20)
        comparacao.paste(img, (x, 50))
        ImageDraw.Draw(comparacao).text((x + 10, 10), rotulo, fill="black", font=fonte)
        img.save(pasta / f"{rotulo.lower().replace('aes-', '')}.png")

    destino = pasta / "comparacao_ecb_gcm.png"
    comparacao.save(destino)
    blocos = [pixels[i:i + 16] for i in range(0, len(pixels), 16)]
    print(f"A imagem tem {len(blocos)} blocos de 16 bytes, mas só {len(set(blocos))} são diferentes.")
    print("No ECB, blocos iguais viram blocos cifrados iguais, então o desenho continua visível.")
    print("No GCM, cada bloco usa um contador diferente, então o resultado parece ruído.")
    print(f"Imagens salvas em: {destino}")
    return destino


# ---------------------------------------------------------------------------
# 4. Reuso de nonce
# ---------------------------------------------------------------------------

def recuperar_com_nonce_repetido(cifrado1: bytes, cifrado2: bytes, texto1_conhecido: bytes) -> bytes:
    """
    Com a mesma chave e o mesmo nonce, as duas mensagens usam o MESMO keystream:
        C1 XOR C2 = (P1 XOR KS) XOR (P2 XOR KS) = P1 XOR P2
    Quem conhece P1 (um cabeçalho padrão, por exemplo) recupera P2 inteira.
    """
    return xor(xor(cifrado1, cifrado2), texto1_conhecido)


def demo_nonce() -> None:
    titulo("4. O erro fatal: reutilizar o nonce")
    chave, nonce = os.urandom(32), os.urandom(12)
    publica = b"Bom dia! Segue o boletim semanal de avisos do curso."
    secreta = b"Senha do servidor de provas: Lb#2026-P1-sigilo!!!!"

    c1, _ = gcm.cifrar(chave, nonce, publica)
    c2, _ = gcm.cifrar(chave, nonce, secreta)      # ERRO: mesmo nonce de novo
    print("Duas mensagens foram cifradas com a MESMA chave e o MESMO nonce.")
    print("O atacante conhece a primeira (é pública) e captura as duas cifradas.\n")
    print(f"Recuperado pelo atacante: {recuperar_com_nonce_repetido(c1, c2, publica).decode()}")

    c2_correto, _ = gcm.cifrar(chave, os.urandom(12), secreta)
    lixo = recuperar_com_nonce_repetido(c1, c2_correto, publica)
    print(f"Com nonce novo, o mesmo ataque dá só lixo: {hexa(lixo, 16)}")
    print("\nAlém de vazar o texto, o reuso também permite descobrir H e forjar tags válidas.")


DEMOS = {"1": demo_basico, "2": demo_adulteracao, "3": demo_ecb_vs_gcm, "4": demo_nonce}

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    escolhidas = sys.argv[1:] or list(DEMOS)
    for numero in escolhidas:
        if numero not in DEMOS:
            sys.exit(f"Demonstração inexistente: {numero} (use 1, 2, 3 ou 4)")
        DEMOS[numero]()
