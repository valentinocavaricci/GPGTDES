##### CORE, DES, TRIPLE DES #####

class DES_Core:
    """These are all the essential methods to DES, I put these in the CORE class i know that wasn't your listed option but it still works"""

    def add_padding(self, message: bytes) -> bytes:
        block_size = 8
        pad_len = block_size - (len(message) % block_size)
        if pad_len == 0:
            pad_len = block_size
        return message + bytes([pad_len]) * pad_len

    def rem_padding(self, message: bytes) -> bytes:
        pad_len = message[-1]
        if pad_len < 1 or pad_len > 8:
            raise ValueError("Invalid pad length.")
        if len(message) < pad_len:
            raise ValueError("Padding longer than message.")
        if message[-pad_len:] != bytes([pad_len]) * pad_len:
            raise ValueError("Invalid padding bytes.")
        return message[:-pad_len]

    def bytes_to_bit_array(self, byte_string: bytes) -> list[int]:
        bits = []
        for b in byte_string:
            for i in range(7, -1, -1):
                bits.append((b >> i) & 1)
        return bits

    def bit_array_to_bytes(self, bit_array: list[int]) -> bytes:
        if len(bit_array) % 8 != 0:
            raise ValueError("Bit array length must be multiple of 8.")
        out = bytearray()
        for i in range(0, len(bit_array), 8):
            byte = 0
            for bit in bit_array[i:i+8]:
                byte = (byte << 1) | (bit & 1)
            out.append(byte)
        return bytes(out)

    def nsplit(self, data, split_size: int = 64):
        return [data[i:i+split_size] for i in range(0, len(data), split_size)]

    def permute(self, block, table: list[int]):
        if max(table) >= len(block):
            raise ValueError("Permutation table index out of range.")
        return [block[i] for i in table]

    def lshift(self, seq: list[int], n: int) -> list[int]:
        if not seq:
            return []
        n = n % len(seq)
        return seq[n:] + seq[:n]

    def xor(self, x: list[int], y: list[int]) -> list[int]:
        if len(x) != len(y):
            raise ValueError("XOR operands must be same length")
        return [(a ^ b) for a, b in zip(x, y)]


###### SINGLE DES ###########
class DES(DES_Core):
    key_permutation = [
        56, 48, 40, 32, 24, 16, 8,
        0, 57, 49, 41, 33, 25, 17,
        9, 1, 58, 50, 42, 34, 26,
        18, 10, 2, 59, 51, 43, 35,
        62, 54, 46, 38, 30, 22, 14,
        6, 61, 53, 45, 37, 29, 21,
        13, 5, 60, 52, 44, 36, 28,
        20, 12, 4, 27, 19, 11, 3
    ]

    key_permutation2 = [
        13, 16, 10, 23, 0, 4,
        2, 27, 14, 5, 20, 9,
        22, 18, 11, 3, 25, 7,
        15, 6, 26, 19, 12, 1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]

    key_shift = [
        1, 1, 2, 2, 2, 2, 2, 2,
        1, 2, 2, 2, 2, 2, 2, 1
    ]

    perm1 = [
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8, 0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ]

    final_perm = [
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
        32, 0, 40, 8, 48, 16, 56, 24
    ]

    _EXPANSION_TABLE = [
        31, 0, 1, 2, 3, 4,
        3, 4, 5, 6, 7, 8,
        7, 8, 9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31, 0
    ]

    _P_BOX = [
        15, 6, 19, 20, 28, 11, 27, 16,
        0, 14, 22, 25, 4, 17, 30, 9,
        1, 7, 23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10, 3, 24
    ]

 
    _S_BOXES = [
        # S1
        [
            [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
            [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
            [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
            [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
        ],
        # S2
        [
            [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
            [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
            [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
            [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
        ],
        # S3
        [
            [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
            [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
            [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
            [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
        ],
        # S4
        [
            [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
            [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
            [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
            [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
        ],
        # S5
        [
            [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
            [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
            [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
            [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
        ],
        # S6
        [
            [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
            [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
            [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
            [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
        ],
        # S7
        [
            [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
            [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
            [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
            [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
        ],
        # S8
        [
            [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
            [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
            [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
            [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
        ],
    ]
    def _substitute(self, bits):
        output = []
        for i in range(8):
            block = bits[i*6:(i+1)*6]
            row = (block[0] << 1) | block[5]
            col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
            val = self._S_BOXES[i][row][col]
            for j in range(3, -1, -1):
                output.append((val >> j) & 1)
        return output

    def _generate_subkeys(self, key: bytes):
        key_bits = self.bytes_to_bit_array(key)
        permuted = self.permute(key_bits, self.key_permutation)
        L, R = permuted[:28], permuted[28:]
        subkeys = []
        for shift in self.key_shift:
            L = self.lshift(L, shift)
            R = self.lshift(R, shift)
            combined = L + R
            subkeys.append(self.permute(combined, self.key_permutation2))
        return subkeys

    def _f(self, R, subkey):
        expanded = self.permute(R, self._EXPANSION_TABLE)
        mixed = self.xor(expanded, subkey)
        substituted = self._substitute(mixed)
        return self.permute(substituted, self._P_BOX)

    def _crypt_block(self, block, subkeys):
        permuted = self.permute(block, self.perm1)
        L, R = permuted[:32], permuted[32:]
        for subkey in subkeys:
            temp = self._f(R, subkey)
            L, R = R, self.xor(L, temp)
        return self.permute(R + L, self.final_perm)
    



###### TRIPLE DES ###########
class TDES(DES):

    def __init__(self, key, mode: str = "ECB", iv=None):
        if len(key) != 24:
            raise ValueError("Key must be 24 bytes or 192 bits!")
        self.key1 = key[0:8]
        self.key2 = key[8:16]
        self.key3 = key[16:24]
        self.mode = mode
        self.iv = iv

    def encrypt(self, data: bytes, key: bytes, mode="ECB", iv=None) -> bytes:
        subkeys1 = self._generate_subkeys(self.key1)
        subkeys2 = self._generate_subkeys(self.key2)
        subkeys3 = self._generate_subkeys(self.key3)
        ciphertext_bits = []

        if mode == "ECB":
            padded = self.add_padding(data)
            bits = self.bytes_to_bit_array(padded)
            for block in self.nsplit(bits):
                block = self._crypt_block(block, subkeys1)
                block = self._crypt_block(block, list(reversed(subkeys2)))
                block = self._crypt_block(block, subkeys3)
                ciphertext_bits += block
            return self.bit_array_to_bytes(ciphertext_bits)

        elif mode == "CBC":
            iv_bits = self.bytes_to_bit_array(iv)
            padded = self.add_padding(data)
            bits = self.bytes_to_bit_array(padded)
            for block in self.nsplit(bits):
                block = self.xor(block, iv_bits)
                block = self._crypt_block(block, subkeys1)
                block = self._crypt_block(block, list(reversed(subkeys2)))
                cipher_block = self._crypt_block(block, subkeys3)
                ciphertext_bits += cipher_block
                iv_bits = cipher_block
            return self.bit_array_to_bytes(ciphertext_bits)

        elif mode == "OFB":
            iv_bits = self.bytes_to_bit_array(iv)
            bits = self.bytes_to_bit_array(data)
            for block in self.nsplit(bits):
                iv_bits = self._crypt_block(iv_bits, subkeys1)
                iv_bits = self._crypt_block(iv_bits, list(reversed(subkeys2)))
                iv_bits = self._crypt_block(iv_bits, subkeys3)
                cipher_block = self.xor(block, iv_bits)
                ciphertext_bits.extend(cipher_block)
            return self.bit_array_to_bytes(ciphertext_bits)
        
       


    def decrypt(self, ciphertext: bytes, key: bytes, mode="ECB", iv=None) -> bytes:
        subkeys1 = self._generate_subkeys(self.key1)
        subkeys2 = self._generate_subkeys(self.key2)
        subkeys3 = self._generate_subkeys(self.key3)
        bits = self.bytes_to_bit_array(ciphertext)
        plaintext_bits = []

        if mode == "ECB":
            for block in self.nsplit(bits):
                block = self._crypt_block(block, list(reversed(subkeys3)))
                block = self._crypt_block(block, subkeys2)
                block = self._crypt_block(block, list(reversed(subkeys1)))
                plaintext_bits += block
            return self.rem_padding(self.bit_array_to_bytes(plaintext_bits))

        elif mode == "CBC":
            iv_bits = self.bytes_to_bit_array(iv)
            for block in self.nsplit(bits):
                temp_block = self._crypt_block(block, list(reversed(subkeys3)))
                temp_block = self._crypt_block(temp_block, subkeys2)
                temp_block = self._crypt_block(temp_block, list(reversed(subkeys1)))
                plain_block = self.xor(temp_block, iv_bits)
                plaintext_bits += plain_block
                iv_bits = block
            return self.rem_padding(self.bit_array_to_bytes(plaintext_bits))

        elif mode == "OFB":
            iv_bits = self.bytes_to_bit_array(iv)
            for block in self.nsplit(bits):
                if len(block) < 64:
                    block += [0] * (64 - len(block)) ## had to add this because the text you provided was not long enough but idk if this is always necessasry
                iv_bits = self._crypt_block(iv_bits, subkeys1)
                iv_bits = self._crypt_block(iv_bits, list(reversed(subkeys2)))
                iv_bits = self._crypt_block(iv_bits, subkeys3)
                plain_block = self.xor(block, iv_bits)
                plaintext_bits += plain_block

            return self.bit_array_to_bytes(plaintext_bits)
        
        elif mode == "GPG":
            subkeys1 = self._generate_subkeys(self.key1)
            subkeys2 = self._generate_subkeys(self.key2)
            subkeys3 = self._generate_subkeys(self.key3)

            iv_bits = self.bytes_to_bit_array(b'\x00' * 8)

            enc_iv = self._crypt_block(iv_bits, subkeys1)
            enc_iv = self._crypt_block(enc_iv, list(reversed(subkeys2)))
            enc_iv = self._crypt_block(enc_iv, subkeys3)

            block1 = self.xor(enc_iv, bits[0:64])

            iv_bits = bits[0:64]   

            enc_iv = self._crypt_block(iv_bits, subkeys1)
            enc_iv = self._crypt_block(enc_iv, list(reversed(subkeys2)))
            enc_iv = self._crypt_block(enc_iv, subkeys3)

            block2 = self.xor(enc_iv, bits[64:128])

            if block1[48:64] != block2[0:16]:
                raise ValueError("Invalid passphrase or corrupted data")

            result = block1 + block2

            iv_bits = bits[64:128]

            for ctblock in self.nsplit(bits[128:], 64):
                if len(ctblock) < 64:
                    ctblock = ctblock + [0] * (64 - len(ctblock))

                enc_iv = self._crypt_block(iv_bits, subkeys1)
                enc_iv = self._crypt_block(enc_iv, list(reversed(subkeys2)))
                enc_iv = self._crypt_block(enc_iv, subkeys3)

                plain_block = self.xor(enc_iv, ctblock)
                result += plain_block
                iv_bits = ctblock

            return self.bit_array_to_bytes(result)


            
def encrypt_block(key8: bytes, block8: bytes) -> bytes:
    engine = DES()  
    subkeys = engine._generate_subkeys(key8)
    bits = engine.bytes_to_bit_array(block8)
    out_bits = engine._crypt_block(bits, subkeys)
    return engine.bit_array_to_bytes(out_bits)





