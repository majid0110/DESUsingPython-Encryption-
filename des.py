import binascii
from bitarray import bitarray

# Initial Permutation Table
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Inverse Initial Permutation Table
IP_inv = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

# Expansion (E) Table
E = [32, 1, 2, 3, 4, 5, 4, 5,
     6, 7, 8, 9, 8, 9, 10, 11,
     12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21,
     22, 23, 24, 25, 24, 25, 26, 27,
     28, 29, 28, 29, 30, 31, 32, 1]

# S-boxes (S1 to S8)
S_boxes = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Permutation (P) Table
P = [16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25]

# Permuted Choice 1 Table
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Permuted Choice 2 Table
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

left_shifts = [1]

def string_to_bitarray(data):
    """Convert a string to a bit array."""
    bits = bitarray()
    bits.frombytes(data.encode('ascii'))
    return bits

def bitarray_to_string(bits):
    """Convert a bit array to a string."""
    return bits.tobytes().decode('ascii')

def permute(block, table):
    """Permute block using a given table."""
    return bitarray([block[x-1] for x in table])

def xor(bitarray1, bitarray2):
    """XOR two bit arrays."""
    return bitarray(bitarray1) ^ bitarray(bitarray2)

def sbox_substitution(bits):
    """Perform S-box substitution."""
    output = bitarray()
    for i in range(8):
        chunk = bits[i*6:(i+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        value = S_boxes[i][row][col]
        output.frombytes(value.to_bytes(1, 'big')[0:1])
    return output

def f_function(right, subkey):
    """Feistel function."""
    expanded_right = permute(right, E)
    print("Expanded Right:", expanded_right)
    
    xor_output = xor(expanded_right, subkey)
    print("XOR with Subkey:", xor_output)
    
    sbox_output = sbox_substitution(xor_output)
    print("S-Box Output:", sbox_output)
    
    permuted_output = permute(sbox_output, P)
    print("Permutation P Output:", permuted_output)
    
    return permuted_output

def generate_subkeys(key):
    key = permute(key, PC1)
    print("After PC1:", key)
    
    left, right = key[:28], key[28:]
    subkeys = []
    for shift in left_shifts:
        left = left[shift:] + left[:shift]
        right = right[shift:] + right[:shift]
        subkey = permute(left + right, PC2)
        subkeys.append(subkey)
    return subkeys

def des_encrypt(plaintext, key):
    """Encrypt plaintext using DES algorithm with 1 round."""
    

    print("\n==================== DES Encryption Process ====================")
    print("\n==================== Developed By Majid Khan ====================")
    
    plaintext_bits = string_to_bitarray(plaintext)
    key_bits = string_to_bitarray(key)
    
    print("\n----- Step 1: Binary Conversion -----")
    print("Converting Plaintext (ASCII to Binary):\n", plaintext_bits,"\n\n")
    print("Converting Key (ASCII to Binary):\n", key_bits,"\n")
    
    initial_permuted_text = permute(plaintext_bits, IP)
    print("\n----- Step 2: Initial Permutation (IP) -----")
    print("Initial Permutation on PT:\n", initial_permuted_text)
    
    left, right = initial_permuted_text[:32], initial_permuted_text[32:]
    print("\n----- Step 3: Splitting into Halves -----")
    print("Left Half:", left)
    print("Right Half:", right)
    
    subkeys = generate_subkeys(key_bits)
    print("\n----- Step 4: Subkey Generation -----")
    print("Subkey for Round 1:", subkeys[0])
    
    print("\n----- Step 5: Feistel Function -----")
    feistel_output = f_function(right, subkeys[0])
    new_right = xor(left, feistel_output)
    print("New Right Half:", new_right)
    
    combined = right + new_right
    print("\n----- Step 6: Combine Halves -----")
    print("Combined before IP-1:", combined)
    
    ciphertext_bits = permute(combined, IP_inv)
    print("\n----- Step 7: Inverse Initial Permutation (IP-1) -----")
    print("Ciphertext Bits:", ciphertext_bits)
    
    # Convert bit array to hexadecimal string
    ciphertext = bitarray_to_hex(ciphertext_bits)
    print("\n----- Final Ciphertext (Hexadecimal) -----")
    print("Ciphertext (hex):", ciphertext)
    
    print("\n===============================================================")
    
    return ciphertext

# Function to convert bit array to hex string
def bitarray_to_hex(bits):
    """Convert a bit array to a hexadecimal string."""
    return bits.tobytes().hex()

def main():
    print("Welcome to DES Encryption (1 Round) Demonstration")
    plaintext = input("Enter plaintext (8 characters): ")
    key = input("Enter key (8 characters): ")
    
    if len(plaintext) != 8 or len(key) != 8:
        print("Both plaintext and key must be 8 characters long.")
        return
    
    ciphertext = des_encrypt(plaintext, key)
    print("\nFinal Ciphertext:", ciphertext)

if __name__ == "__main__":
    main()
