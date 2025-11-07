#!/usr/bin/env python3
"""
cipher_klasik.py
Implementasi: Caesar, Vigenere, Affine, Playfair, Hill
"""

from typing import List, Tuple
import math

# ---------------------- Utilities ----------------------
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def clean_text(s: str) -> str:
    return ''.join(ch.upper() for ch in s if ch.isalpha())

def modinv(a: int, m: int) -> int:
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"No modular inverse for {a} mod {m}")

# ---------------------- Caesar Cipher ----------------------
def caesar_encrypt(plaintext: str, shift: int) -> str:
    p = clean_text(plaintext)
    out = []
    for ch in p:
        idx = ALPHABET.index(ch)
        out.append(ALPHABET[(idx + shift) % 26])
    return ''.join(out)

def caesar_decrypt(ciphertext: str, shift: int) -> str:
    return caesar_encrypt(ciphertext, -shift)

# ---------------------- Vigenere Cipher ----------------------
def vigenere_encrypt(plaintext: str, key: str) -> str:
    p = clean_text(plaintext)
    k = clean_text(key)
    if not k:
        raise ValueError('Key must contain letters')
    out = []
    for i, ch in enumerate(p):
        ki = ALPHABET.index(k[i % len(k)])
        ci = (ALPHABET.index(ch) + ki) % 26
        out.append(ALPHABET[ci])
    return ''.join(out)

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    c = clean_text(ciphertext)
    k = clean_text(key)
    out = []
    for i, ch in enumerate(c):
        ki = ALPHABET.index(k[i % len(k)])
        pi = (ALPHABET.index(ch) - ki) % 26
        out.append(ALPHABET[pi])
    return ''.join(out)

# ---------------------- Affine Cipher ----------------------
def affine_encrypt(plaintext: str, a: int, b: int) -> str:
    p = clean_text(plaintext)
    if math.gcd(a, 26) != 1:
        raise ValueError('a must be coprime with 26')
    out = []
    for ch in p:
        x = ALPHABET.index(ch)
        out.append(ALPHABET[(a * x + b) % 26])
    return ''.join(out)

def affine_decrypt(ciphertext: str, a: int, b: int) -> str:
    c = clean_text(ciphertext)
    a_inv = modinv(a, 26)
    out = []
    for ch in c:
        y = ALPHABET.index(ch)
        out.append(ALPHABET[(a_inv * (y - b)) % 26])
    return ''.join(out)

# ---------------------- Playfair Cipher ----------------------
class Playfair:
    def __init__(self, key: str):
        self.key = clean_text(key).replace('J', 'I')
        self.matrix = self._create_matrix()
        self.pos = {self.matrix[r][c]: (r, c) for r in range(5) for c in range(5)}

    def _create_matrix(self) -> List[List[str]]:
        seen = []
        for ch in self.key + ALPHABET:
            if ch == 'J':
                ch = 'I'
            if ch not in seen:
                seen.append(ch)
        seen = seen[:25]
        return [seen[i*5:(i+1)*5] for i in range(5)]

    def _prepare(self, text: str) -> List[Tuple[str, str]]:
        raw = clean_text(text).replace('J', 'I')
        pairs = []
        i = 0
        while i < len(raw):
            a = raw[i]
            b = ''
            if i + 1 < len(raw):
                b = raw[i+1]
            if b == '' or a == b:
                pairs.append((a, 'X'))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        if pairs and len(pairs[-1]) == 1:
            pairs[-1] = (pairs[-1][0], 'X')
        return pairs

    def encrypt(self, plaintext: str) -> str:
        pairs = self._prepare(plaintext)
        out = []
        for a, b in pairs:
            ra, ca = self.pos[a]
            rb, cb = self.pos[b]
            if ra == rb:
                out.append(self.matrix[ra][(ca+1)%5])
                out.append(self.matrix[rb][(cb+1)%5])
            elif ca == cb:
                out.append(self.matrix[(ra+1)%5][ca])
                out.append(self.matrix[(rb+1)%5][cb])
            else:
                out.append(self.matrix[ra][cb])
                out.append(self.matrix[rb][ca])
        return ''.join(out)

    def decrypt(self, ciphertext: str) -> str:
        c = clean_text(ciphertext)
        pairs = [(c[i], c[i+1]) for i in range(0, len(c), 2)]
        out = []
        for a, b in pairs:
            ra, ca = self.pos[a]
            rb, cb = self.pos[b]
            if ra == rb:
                out.append(self.matrix[ra][(ca-1)%5])
                out.append(self.matrix[rb][(cb-1)%5])
            elif ca == cb:
                out.append(self.matrix[(ra-1)%5][ca])
                out.append(self.matrix[(rb-1)%5][cb])
            else:
                out.append(self.matrix[ra][cb])
                out.append(self.matrix[rb][ca])
        return ''.join(out)

# ---------------------- Hill Cipher ----------------------
def _matrix_mod_inv(matrix: List[List[int]], m: int) -> List[List[int]]:
    n = len(matrix)
    if n == 2:
        a, b = matrix[0]
        c, d = matrix[1]
        det = (a*d - b*c) % m
        det_inv = modinv(det, m)
        inv = [[d * det_inv % m, (-b) * det_inv % m],
               [(-c) * det_inv % m, a * det_inv % m]]
        return [[x % m for x in row] for row in inv]
    else:
        raise ValueError("Only 2x2 matrices supported in this example.")

def hill_encrypt(plaintext: str, key_matrix: List[List[int]]) -> str:
    p = clean_text(plaintext)
    n = len(key_matrix)
    while len(p) % n != 0:
        p += 'X'
    out = []
    for i in range(0, len(p), n):
        block = p[i:i+n]
        vec = [ALPHABET.index(ch) for ch in block]
        res = [sum(key_matrix[r][c] * vec[c] for c in range(n)) % 26 for r in range(n)]
        out += [ALPHABET[x] for x in res]
    return ''.join(out)

def hill_decrypt(ciphertext: str, key_matrix: List[List[int]]) -> str:
    c = clean_text(ciphertext)
    n = len(key_matrix)
    inv = _matrix_mod_inv(key_matrix, 26)
    out = []
    for i in range(0, len(c), n):
        block = c[i:i+n]
        vec = [ALPHABET.index(ch) for ch in block]
        res = [sum(inv[r][c2] * vec[c2] for c2 in range(n)) % 26 for r in range(n)]
        out += [ALPHABET[x] for x in res]
    return ''.join(out)

# ---------------------- Demo ----------------------
if __name__ == '__main__':
    print('--- Demo: Cipher Klasik ---')
    pt = 'ATTACKATDAWN'
    print('Plaintext:', pt)

    print('\nCaesar (shift=3):', caesar_encrypt(pt, 3))
    key_v = 'LEMON'
    print('Vigenere (key=LEMON):', vigenere_encrypt(pt, key_v))
    print('Affine (a=5,b=8):', affine_encrypt(pt, 5, 8))

    pf = Playfair('MONARCHY')
    pf_ct = pf.encrypt('INSTRUMENTS')
    print('Playfair (key=MONARCHY), encrypt INSTRUMENTS ->', pf_ct)
    print('Playfair decrypt ->', pf.decrypt(pf_ct))

    hill_k2 = [[3, 3], [2, 5]]
    hill_ct = hill_encrypt('HELP', hill_k2)
    print('Hill 2x2 (key [[3,3],[2,5]]) encrypt HELP ->', hill_ct)
    print('Hill decrypt ->', hill_decrypt(hill_ct, hill_k2))
