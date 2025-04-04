import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Constants
BLOCK_SIZE = 16  # AES block size in bytes

# substitute box for AES encryption
s_box = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
# lookup table for the SubBytes step

# inverse substitute box for AES decryption
inverse_s_box = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]

# Key expansion process to generate round keys
Rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


# byte wise XOR operation between 2 byte sequences
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# converts 16 byte blcok into 4x4 state matrix for AES
def text_to_matrix(text):
    matrix = []
    for i in range(4):
        matrix.append(list(text[i * 4: (i + 1) * 4]))
    return matrix


# converts 4x4 state metrix back into a 16 byte block
def matrix_to_text(matrix):
    text = b""

    for i in range(4):
        text += bytes(matrix[i])
    return text


# XORs the state matrix with round key
def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]


# substitute each byte in the state matrix using S-box
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = s_box[state[i][j]]


# substitute each byte in the state matrix using inverse S-box
def inverse_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = inverse_s_box[state[i][j]]


# shifts row of the state matrix for the shiftrows step
def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


# performs the inverse shiftrows operation during decryption
def inverse_shift_rows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]


# multiplies 2 numbers in the Galois Field (GF(2^8))
def multiply(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xff
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p & 0xff

# used in the MixColums step for efficient computation

mul9 = [0] * 256
mul11 = [0] * 256
mul13 = [0] * 256
mul14 = [0] * 256

# used in the MixColumns step for efficient computation
for i in range(256):
    mul9[i] = multiply(i, 0x09)
    mul11[i] = multiply(i, 0x0B)
    mul13[i] = multiply(i, 0x0D)
    mul14[i] = multiply(i, 0x0E)

mul2 = [0] * 256
mul3 = [0] * 256

for i in range(256):
    mul2[i] = multiply(i, 2)
    mul3[i] = multiply(i, 3)


# mixes columns of the state matrix for the MixColumns step
def mix_columns(state):
    for c in range(4):
        # 2*a?:
        a0 = state[0][c]
        a1 = state[1][c]
        a2 = state[2][c]
        a3 = state[3][c]
        # 3*a? == (2*a?) ^ a?
        state[0][c] = mul2[a0] ^ mul3[a1] ^ a2 ^ a3
        state[1][c] = a0 ^ mul2[a1] ^ mul3[a2] ^ a3
        state[2][c] = a0 ^ a1 ^ mul2[a2] ^ mul3[a3]
        state[3][c] = mul3[a0] ^ a1 ^ a2 ^ mul2[a3]


# performs the inverse MixColumns operation during decryption
def inverse_mix_columns(state):
    for c in range(4):
        a0 = state[0][c]
        a1 = state[1][c]
        a2 = state[2][c]
        a3 = state[3][c]

        state[0][c] = (
                mul14[a0] ^ mul11[a1] ^ mul13[a2] ^ mul9[a3]
        )
        state[1][c] = (
                mul9[a0] ^ mul14[a1] ^ mul11[a2] ^ mul13[a3]

        )
        state[2][c] = (
                mul13[a0] ^ mul9[a1] ^ mul14[a2] ^ mul11[a3]

        )
        state[3][c] = (
                mul11[a0] ^ mul13[a1] ^ mul9[a2] ^ mul14[a3]

        )


# pads data to a multiple of the block size using PKCS#7 padding
def pkcs7_pad(data):
    # calculates padding length
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)

    # append padding bytes
    return data + bytes([pad_len] * pad_len)


# removes PKCS#7 padding from data
def pkcs7_unpad(data):
    # get padding length from the last byte
    pad_len = data[-1]
    # remove padding bytes
    return data[:-pad_len]


class aes:
    def __init__(self, user_key, aes_mode):

        # 128 bit key
        if aes_mode == 128:
            self.key = user_key[:16]
            self.Nk = 4
            self.Nr = 10
        else:
            # 256 bit key
            self.key = user_key[:32]
            self.Nk = 8
            self.Nr = 14

        # number of columns in the state
        self.Nb = 4
        self.round_keys = [text_to_matrix(round_key) for round_key in self.key_expansion(self.key)]

    def key_expansion(self, key):
        key_symbols = [k for k in key]

        for i in range(self.Nk, self.Nb * (self.Nr + 1)):
            temp = key_symbols[-4:]
            if i % self.Nk == 0:
                # rotate word
                temp = temp[1:] + temp[:1]
                # substitute bytes
                temp = [s_box[b] for b in temp]
                # XOR with round constant
                temp[0] ^= Rcon[i // self.Nk]

            elif (self.Nk == 8) and (i % self.Nk == 4):
                # substitute bytes for 256 bit key
                temp = [s_box[b] for b in temp]

            # Correct XOR with prior word
            new_word = [
                key_symbols[len(key_symbols) - self.Nk * 4 + j] ^ temp[j]
                for j in range(4)
            ]
            key_symbols.extend(new_word)

        return [
            key_symbols[i:i + 16]
            for i in range(0, len(key_symbols), 16)
        ]

    def cipher(self, block):
        state = text_to_matrix(block)
        # initial round key addition
        add_round_key(state, self.round_keys[0])
        for i in range(1, self.Nr):
            # substitute bytes
            sub_bytes(state)
            # shift rows
            shift_rows(state)
            # mix columns
            mix_columns(state)
            # add round key
            add_round_key(state, self.round_keys[i])

        sub_bytes(state)
        shift_rows(state)
        # final round key addition
        add_round_key(state, self.round_keys[-1])

        return matrix_to_text(state)

    def inverse_cipher(self, block):
        state = text_to_matrix(block)
        # final round key addition
        add_round_key(state, self.round_keys[-1])
        # inverse shift rows
        inverse_shift_rows(state)
        # inverse substitute bytes
        inverse_sub_bytes(state)

        for i in range(self.Nr - 1, 0, -1):
            # add round key
            add_round_key(state, self.round_keys[i])
            # inverse mix columns
            inverse_mix_columns(state)
            # inverse shifts rows
            inverse_shift_rows(state)
            # inverse substitute bytes
            inverse_sub_bytes(state)

        # initial round key addition
        add_round_key(state, self.round_keys[0])
        return matrix_to_text(state)

    def encrypt(self, plaintext: bytes, salt: bytes, progress_callback=None) -> bytes:
        # pad plaintext
        plaintext = pkcs7_pad(plaintext)
        # generate random IV
        iv = os.urandom(16)
        ciphertext = b""
        previous_block = iv
        total_blocks = len(plaintext) // 16
        iteration = 0
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]
            # encrypt block
            encrypted_block = self.cipher(xor_bytes(block, previous_block))
            ciphertext += encrypted_block
            previous_block = encrypted_block

            iteration += 1
            if progress_callback:
                # update progress
                progress_callback(iteration, total_blocks)

        # Return SALT (16 bytes) + IV (16 bytes) + ciphertext
        return salt + iv + ciphertext

    def decrypt(self, combined: bytes, progress_callback=None) -> bytes:
        # extract IV
        iv = combined[16:32]

        # extract ciphertext
        ciphertext = combined[32:]

        plaintext = b""
        previous_block = iv

        total_blocks = len(ciphertext) // 16
        iteration = 0

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            # decrypt block
            decrypted_block = xor_bytes(self.inverse_cipher(block), previous_block)
            plaintext += decrypted_block
            previous_block = block

            iteration += 1
            if progress_callback:
                # update progress
                progress_callback(iteration, total_blocks)

        # remove padding and return plaintext
        return pkcs7_unpad(plaintext)

    def password_encode(password_provided, salt, length):
        password = str(password_provided).encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Hash algorithm for key derivation
            length=length,  # key length for AES and HMAC
            salt=salt,  # Random salt (stored with the encrypted data)
            iterations=500_000,
            backend=default_backend()
        )
        return kdf.derive(password)  # Returns 32 byte AES key
