"""
Implementação DIDÁTICA do modo GCM (Galois/Counter Mode) sobre o AES.

Segue passo a passo a especificação oficial NIST SP 800-38D. O objetivo é
mostrar como o GCM funciona por dentro; em um sistema real, use sempre uma
biblioteca auditada (ver gcm/cofre.py, que usa a AESGCM da `cryptography`).

Da biblioteca usamos apenas o AES "puro" (cifrar UM bloco de 16 bytes).
Todo o resto do GCM está implementado aqui:

    1. H  = AES_K(0^128)                    -> chave de autenticação
    2. J0 = IV || 0^31 || 1                 -> contador inicial
    3. C  = GCTR_K(inc32(J0), P)            -> cifragem (modo contador)
    4. S  = GHASH_H(A || C || tamanhos)     -> "resumo" autenticado em GF(2^128)
    5. T  = GCTR_K(J0, S)                   -> tag de autenticação
"""

import hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TAM_BLOCO = 16  # o AES sempre trabalha com blocos de 128 bits = 16 bytes

# Polinômio que define o corpo de Galois GF(2^128) usado pelo GCM:
#     x^128 + x^7 + x^2 + x + 1
# Na representação "invertida" do GCM ele vira o byte 0xE1 seguido de zeros.
R = 0xE1 << 120


class TagInvalida(Exception):
    """A tag não confere: o texto cifrado, a AAD, o nonce ou a chave foram alterados."""


# ---------------------------------------------------------------------------
# Peças básicas
# ---------------------------------------------------------------------------

def _aes_bloco(chave: bytes):
    """Devolve uma função que cifra UM bloco de 16 bytes com AES (sem modo)."""
    cifrador = Cipher(algorithms.AES(chave), modes.ECB()).encryptor()
    return lambda bloco: cifrador.update(bloco)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _inc32(bloco: bytes) -> bytes:
    """Soma 1 nos 32 bits finais do bloco (módulo 2^32), mantendo os 96 iniciais."""
    prefixo, contador = bloco[:12], int.from_bytes(bloco[12:], "big")
    return prefixo + ((contador + 1) % 2**32).to_bytes(4, "big")


def _blocos(dados: bytes):
    """Divide os dados em blocos de 16 bytes (o último pode ser menor)."""
    return [dados[i:i + TAM_BLOCO] for i in range(0, len(dados), TAM_BLOCO)]


def _completar_com_zeros(dados: bytes) -> bytes:
    """Completa com zeros até um múltiplo de 16 bytes (exigido pelo GHASH)."""
    falta = (-len(dados)) % TAM_BLOCO
    return dados + b"\x00" * falta


# ---------------------------------------------------------------------------
# A parte "Galois": multiplicação em GF(2^128) e GHASH
# ---------------------------------------------------------------------------

def gf_mult(x: int, y: int) -> int:
    """
    Multiplica dois elementos de GF(2^128) (Algoritmo 1 da SP 800-38D).

    Cada bloco de 128 bits é visto como um polinômio com coeficientes 0 ou 1.
    Somar é fazer XOR; multiplicar é "deslocar e somar", e sempre que o grau
    passa de 127 o resultado é reduzido pelo polinômio R. Assim o resultado
    continua cabendo em 128 bits.
    """
    z, v = 0, y
    for i in range(127, -1, -1):        # percorre os bits de x, do mais significativo
        if (x >> i) & 1:
            z ^= v                      # "soma" (XOR) quando o bit de x é 1
        v = (v >> 1) ^ R if v & 1 else v >> 1   # multiplica v por x e reduz
    return z


def ghash(h: bytes, dados: bytes) -> bytes:
    """
    GHASH_H(X1 || X2 || ... || Xm):  Y_i = (Y_{i-1} XOR X_i) * H  em GF(2^128).

    É um "hash com chave": sem conhecer H (que depende da chave do AES),
    o atacante não consegue calcular o valor correto para dados alterados.
    """
    if len(dados) % TAM_BLOCO:
        raise ValueError("GHASH exige um múltiplo de 16 bytes")
    h_int, y = int.from_bytes(h, "big"), 0
    for bloco in _blocos(dados):
        y = gf_mult(y ^ int.from_bytes(bloco, "big"), h_int)
    return y.to_bytes(TAM_BLOCO, "big")


# ---------------------------------------------------------------------------
# A parte "Counter": GCTR (modo contador)
# ---------------------------------------------------------------------------

def gctr(aes, contador_inicial: bytes, dados: bytes) -> bytes:
    """
    Modo contador: cifra os contadores e faz XOR com os dados.

        saída_i = dados_i XOR AES_K(contador_i),   contador_{i+1} = inc32(contador_i)

    Os dados nunca passam pelo AES diretamente; o AES só gera o "fluxo de
    chave" (keystream). Por isso não há padding e cifrar == decifrar.
    """
    saida, contador = bytearray(), contador_inicial
    for bloco in _blocos(dados):
        saida += _xor(bloco, aes(contador))   # _xor trunca o último bloco parcial
        contador = _inc32(contador)
    return bytes(saida)


# ---------------------------------------------------------------------------
# GCM completo
# ---------------------------------------------------------------------------

def _preparar(chave: bytes, iv: bytes):
    aes = _aes_bloco(chave)
    h = aes(b"\x00" * TAM_BLOCO)                         # passo 1: H = AES_K(0^128)
    if len(iv) == 12:                                    # passo 2: J0 (caso recomendado, IV de 96 bits)
        j0 = iv + b"\x00\x00\x00\x01"
    else:                                                # IV de outro tamanho: J0 = GHASH(IV || tamanho)
        j0 = ghash(h, _completar_com_zeros(iv) + b"\x00" * 8 + (len(iv) * 8).to_bytes(8, "big"))
    return aes, h, j0


def _calcular_tag(aes, h: bytes, j0: bytes, aad: bytes, cifrado: bytes) -> bytes:
    tamanhos = (len(aad) * 8).to_bytes(8, "big") + (len(cifrado) * 8).to_bytes(8, "big")
    s = ghash(h, _completar_com_zeros(aad) + _completar_com_zeros(cifrado) + tamanhos)  # passo 4
    return gctr(aes, j0, s)                                                               # passo 5


def cifrar(chave: bytes, iv: bytes, texto: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """
    Cifra `texto` e autentica `texto` + `aad`. Devolve (texto_cifrado, tag).

    - chave: 16, 24 ou 32 bytes (AES-128/192/256)
    - iv:    o nonce. NUNCA repita o mesmo IV com a mesma chave (ver demo 4)
    - aad:   "dados associados": viajam em claro, mas qualquer alteração é detectada
    """
    if not iv:
        raise ValueError("o IV não pode ser vazio")
    aes, h, j0 = _preparar(chave, iv)
    cifrado = gctr(aes, _inc32(j0), texto)              # passo 3: o contador começa em J0+1
    return cifrado, _calcular_tag(aes, h, j0, aad, cifrado)


def decifrar(chave: bytes, iv: bytes, cifrado: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """
    Verifica a tag e só então decifra. Se algo foi alterado, lança TagInvalida
    sem devolver NENHUM byte do texto, porque dado não autenticado não deve ser usado.
    """
    aes, h, j0 = _preparar(chave, iv)
    tag_esperada = _calcular_tag(aes, h, j0, aad, cifrado)
    # compare_digest leva o mesmo tempo acertando ou errando: evita que o
    # atacante descubra a tag byte a byte medindo o tempo de resposta.
    if not hmac.compare_digest(tag_esperada, tag):
        raise TagInvalida("tag de autenticação inválida: os dados foram alterados")
    return gctr(aes, _inc32(j0), cifrado)
