P10_data = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8_data = [6, 3, 7, 4, 8, 5, 10, 9]
LS1_data = [2, 3, 4, 5, 1]
LS2_data = [3, 4, 5, 1, 2]
IP_data = [2, 6, 3, 1, 4, 8, 5, 7]
IPinv_data = [4, 1, 3, 5, 7, 2, 8, 6]
EP_data = [4, 1, 2, 3, 2, 3, 4, 1]
P4_data = [2, 4, 3, 1]
SW_data = [5, 6, 7, 8, 1, 2, 3, 4]

S0_data = [[1, 0, 3, 2],
           [3, 2, 1, 0],
           [0, 2, 1, 3],
           [3, 1, 3, 2]]
S1_data = [[0, 1, 2, 3],
           [2, 0, 1, 3],
           [3, 0, 1, 0],
           [2, 1, 0, 3]]


def apply_permutation(X, permutation):
    return [X[i - 1] for i in permutation]


def apply_sbox(X, SBox):
    r = 2 * X[0] + X[3]
    c = 2 * X[1] + X[2]
    o = SBox[r][c]
    return [(o >> 1) & 1, o & 1]


def concatenate(left, right):
    return left + right


def left_half_bits(block):
    return block[:len(block) // 2]


def right_half_bits(block):
    return block[len(block) // 2:]


def xor_block(block1, block2):
    if len(block1) != len(block2):
        raise ValueError("XorBlock arguments must be the same length")
    return [(b1 + b2) % 2 for b1, b2 in zip(block1, block2)]


def sdes_key_schedule(K):
    temp_K = apply_permutation(K, P10_data)
    left_temp_K = left_half_bits(temp_K)
    right_temp_K = right_half_bits(temp_K)

    K1left = apply_permutation(left_temp_K, LS1_data)
    K1right = apply_permutation(right_temp_K, LS1_data)
    K1 = apply_permutation(concatenate(K1left, K1right), P8_data)

    K2left = apply_permutation(K1left, LS2_data)
    K2right = apply_permutation(K1right, LS2_data)
    K2 = apply_permutation(concatenate(K2left, K2right), P8_data)

    return K1, K2


def f_k(block, K):
    left_block = left_half_bits(block)
    right_block = right_half_bits(block)
    temp_block1 = apply_permutation(right_block, EP_data)
    temp_block2 = xor_block(temp_block1, K)
    left_temp_block2 = left_half_bits(temp_block2)
    right_temp_block2 = right_half_bits(temp_block2)
    S0_out = apply_sbox(left_temp_block2, S0_data)
    S1_out = apply_sbox(right_temp_block2, S1_data)
    temp_block3 = concatenate(S0_out, S1_out)
    temp_block4 = apply_permutation(temp_block3, P4_data)
    temp_block5 = xor_block(temp_block4, left_block)
    return concatenate(temp_block5, right_block)


def sdes_encrypt(plaintext_block, K):
    K1, K2 = sdes_key_schedule(K)
    temp_block1 = apply_permutation(plaintext_block, IP_data)
    temp_block2 = f_k(temp_block1, K1)
    temp_block3 = apply_permutation(temp_block2, SW_data)
    temp_block4 = f_k(temp_block3, K2)
    return apply_permutation(temp_block4, IPinv_data)


def brute_force_sdes(plaintext_ciphertext_pairs):
    """
    Finds a key that works for ALL given plaintext-ciphertext pairs

    Args:
    plaintext_ciphertext_pairs: List of tuples [(plaintext1, ciphertext1), (plaintext2, ciphertext2), ...]

    Returns:
    The 10-bit key that encrypts all plaintext pairs to their respective ciphertexts
    """
    for key in range(1024):  # 10-bit keys from 0 to 1023
        key_bits = [int(b) for b in format(key, '010b')]

        # Check if this key works for ALL plaintext-ciphertext pairs
        if all(sdes_encrypt(plaintext, key_bits) == ciphertext
               for plaintext, ciphertext in plaintext_ciphertext_pairs):
            return key_bits

    return None


def main():
    # Allow multiple plaintext-ciphertext pairs
    plaintext_ciphertext_pairs = []

    while True:
        plaintext = input("Enter 8-bit plaintext (or press Enter to finish): ")
        if not plaintext:
            break

        ciphertext = input("Enter corresponding 8-bit ciphertext: ")

        plaintext_bits = [int(b) for b in plaintext]
        ciphertext_bits = [int(b) for b in ciphertext]

        plaintext_ciphertext_pairs.append((plaintext_bits, ciphertext_bits))

    if not plaintext_ciphertext_pairs:
        print("No pairs entered.")
        return

    found_key = brute_force_sdes(plaintext_ciphertext_pairs)

    if found_key:
        print("Found 10-bit key:", ''.join(map(str, found_key)))
    else:
        print("No single key found that works for all plaintext-ciphertext pairs.")


if __name__ == "__main__":
    main()