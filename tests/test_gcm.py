"""
Testes do trabalho.  Rodar com:   python -m unittest -v

Provam três coisas:
  1. a implementação didática está correta (vetores oficiais + comparação com a biblioteca);
  2. qualquer alteração (texto, tag, AAD, chave, nonce) é detectada;
  3. os ataques das demonstrações realmente funcionam quando a regra é quebrada.
"""

import os
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import demos
from gcm import cofre
from gcm import gcm_didatico as gcm

x = bytes.fromhex

# Vetores de teste do artigo original do GCM (McGrew & Viega, 2004), casos 1 a 4.
# Formato: (chave, iv, texto, aad, texto_cifrado, tag)
VETORES = [
    ("00" * 16, "00" * 12, "", "", "", "58e2fccefa7e3061367f1d57a4e7455a"),
    ("00" * 16, "00" * 12, "00" * 16, "", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"),
    (
        "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        "",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        "4d5c2af327cd64a62cf35abd2ba6fab4",
    ),
    (
        "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47",
    ),
]


class TestCorretude(unittest.TestCase):
    def test_vetores_oficiais(self):
        for i, (k, iv, p, a, c, t) in enumerate(VETORES, start=1):
            with self.subTest(caso=i):
                cifrado, tag = gcm.cifrar(x(k), x(iv), x(p), x(a))
                self.assertEqual(cifrado.hex(), c)
                self.assertEqual(tag.hex(), t)
                self.assertEqual(gcm.decifrar(x(k), x(iv), cifrado, tag, x(a)), x(p))

    def test_igual_a_biblioteca_em_casos_aleatorios(self):
        # chaves de 128/192/256 bits, IVs de vários tamanhos, textos de 0 a 99 bytes
        for n in range(200):
            chave = os.urandom((16, 24, 32)[n % 3])
            iv = os.urandom((12, 8, 16, 60)[n % 4])
            texto, aad = os.urandom(n % 100), os.urandom(n % 37)
            with self.subTest(n=n):
                cifrado, tag = gcm.cifrar(chave, iv, texto, aad)
                self.assertEqual(cifrado + tag, AESGCM(chave).encrypt(iv, texto, aad))
                self.assertEqual(gcm.decifrar(chave, iv, cifrado, tag, aad), texto)


class TestCorpoDeGalois(unittest.TestCase):
    """Propriedades de GF(2^128) que o GHASH usa."""

    UM = 1 << 127  # o "1" do corpo: no GCM o bit mais significativo é o coeficiente de x^0

    def test_elemento_neutro(self):
        a = int.from_bytes(os.urandom(16), "big")
        self.assertEqual(gcm.gf_mult(a, self.UM), a)

    def test_comutativa_e_distributiva(self):
        a, b, c = (int.from_bytes(os.urandom(16), "big") for _ in range(3))
        self.assertEqual(gcm.gf_mult(a, b), gcm.gf_mult(b, a))
        self.assertEqual(gcm.gf_mult(a, b ^ c), gcm.gf_mult(a, b) ^ gcm.gf_mult(a, c))

    def test_resultado_cabe_em_128_bits(self):
        a, b = (int.from_bytes(os.urandom(16), "big") for _ in range(2))
        self.assertLess(gcm.gf_mult(a, b), 2**128)


class TestAutenticacao(unittest.TestCase):
    def setUp(self):
        self.chave, self.iv = os.urandom(32), os.urandom(12)
        self.aad = b"cabecalho"
        self.cifrado, self.tag = gcm.cifrar(self.chave, self.iv, b"mensagem importante", self.aad)

    def assertRecusa(self, chave=None, iv=None, cifrado=None, tag=None, aad=None):
        with self.assertRaises(gcm.TagInvalida):
            gcm.decifrar(chave or self.chave, iv or self.iv, cifrado or self.cifrado,
                         tag or self.tag, self.aad if aad is None else aad)

    def test_um_bit_alterado_no_texto_cifrado(self):
        for posicao in range(len(self.cifrado)):
            with self.subTest(posicao=posicao):
                self.assertRecusa(cifrado=demos.trocar_caractere(self.cifrado, posicao, "a", "b"))

    def test_tag_alterada(self):
        self.assertRecusa(tag=bytes([self.tag[0] ^ 1]) + self.tag[1:])

    def test_tag_truncada(self):
        self.assertRecusa(tag=self.tag[:12])

    def test_aad_alterada_ou_removida(self):
        self.assertRecusa(aad=b"cabecalhO")
        self.assertRecusa(aad=b"")

    def test_chave_ou_nonce_errados(self):
        self.assertRecusa(chave=os.urandom(32))
        self.assertRecusa(iv=os.urandom(12))


class TestAtaquesDasDemos(unittest.TestCase):
    def test_reuso_de_nonce_revela_a_mensagem(self):
        chave, nonce = os.urandom(16), os.urandom(12)
        conhecida, secreta = b"mensagem publica conhecida!!", b"segredo que deveria ficar ok"
        c1, _ = gcm.cifrar(chave, nonce, conhecida)
        c2, _ = gcm.cifrar(chave, nonce, secreta)
        self.assertEqual(demos.recuperar_com_nonce_repetido(c1, c2, conhecida), secreta)

    def test_nonce_novo_impede_o_ataque(self):
        chave = os.urandom(16)
        conhecida, secreta = b"mensagem publica conhecida!!", b"segredo que deveria ficar ok"
        c1, _ = gcm.cifrar(chave, os.urandom(12), conhecida)
        c2, _ = gcm.cifrar(chave, os.urandom(12), secreta)
        self.assertNotEqual(demos.recuperar_com_nonce_repetido(c1, c2, conhecida), secreta)

    def test_mesma_entrada_nonces_diferentes_dao_saidas_diferentes(self):
        chave, texto = os.urandom(16), b"A" * 32
        c1, _ = gcm.cifrar(chave, os.urandom(12), texto)
        c2, _ = gcm.cifrar(chave, os.urandom(12), texto)
        self.assertNotEqual(c1, c2)
        self.assertNotEqual(c1[:16], c1[16:])  # nem dois blocos iguais repetem (ao contrário do ECB)


class TestCofre(unittest.TestCase):
    CUSTO = 2**10  # scrypt mais leve só para os testes rodarem rápido

    def test_ida_e_volta(self):
        dados = os.urandom(1000)
        protegido = cofre.cifrar_bytes(dados, "senha forte", self.CUSTO)
        self.assertTrue(protegido.startswith(cofre.MAGICA))
        self.assertEqual(cofre.decifrar_bytes(protegido, "senha forte", self.CUSTO), dados)

    def test_senha_errada(self):
        protegido = cofre.cifrar_bytes(b"segredo", "certa", self.CUSTO)
        with self.assertRaises(cofre.SenhaOuArquivoInvalido):
            cofre.decifrar_bytes(protegido, "errada", self.CUSTO)

    def test_arquivo_adulterado(self):
        protegido = bytearray(cofre.cifrar_bytes(b"segredo", "senha", self.CUSTO))
        protegido[-20] ^= 1
        with self.assertRaises(cofre.SenhaOuArquivoInvalido):
            cofre.decifrar_bytes(bytes(protegido), "senha", self.CUSTO)

    def test_cada_cifragem_usa_salt_e_nonce_novos(self):
        a = cofre.cifrar_bytes(b"mesmo texto", "senha", self.CUSTO)
        b = cofre.cifrar_bytes(b"mesmo texto", "senha", self.CUSTO)
        self.assertNotEqual(a[:cofre.TAM_CABECALHO], b[:cofre.TAM_CABECALHO])
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
