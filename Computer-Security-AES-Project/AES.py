"""
AES-128 Encryption Implementation from Scratch
Shows step-by-step: Key Expansion, S-box, and 10 Rounds of Encryption
"""

# S-box for SubBytes transformation
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Round constants for key expansion
RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

def print_state(state, label):
    """Print the state matrix in a readable format"""
    print(f"\n{label}:")
    for row in range(4):
        print("  ", end="")
        for col in range(4):
            print(f"{state[row][col]:02x} ", end="")
        print()

def bytes_to_state(data):
    """Convert 16 bytes to 4x4 state matrix (column-major order)"""
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state

def state_to_bytes(state):
    """Convert 4x4 state matrix to 16 bytes (column-major order)"""
    data = []
    for col in range(4):
        for row in range(4):
            data.append(state[row][col])
    return bytes(data)

def sub_bytes(state):
    """Apply S-box substitution to each byte in the state"""
    print("\n  -> Applying SubBytes (S-box substitution)...")
    for row in range(4):
        for col in range(4):
            state[row][col] = S_BOX[state[row][col]]
    return state

def shift_rows(state):
    """Shift rows cyclically to the left"""
    print("  -> Applying ShiftRows...")
    state[1] = state[1][1:] + state[1][:1]  # Shift row 1 by 1
    state[2] = state[2][2:] + state[2][:2]  # Shift row 2 by 2
    state[3] = state[3][3:] + state[3][:3]  # Shift row 3 by 3
    return state

def galois_mult(a, b):
    """Galois field multiplication"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b  # Reduce with AES polynomial
        b >>= 1
    return p & 0xFF

def mix_columns(state):
    """Mix columns transformation"""
    print("  -> Applying MixColumns...")
    for col in range(4):
        s0, s1, s2, s3 = state[0][col], state[1][col], state[2][col], state[3][col]
        state[0][col] = galois_mult(0x02, s0) ^ galois_mult(0x03, s1) ^ s2 ^ s3
        state[1][col] = s0 ^ galois_mult(0x02, s1) ^ galois_mult(0x03, s2) ^ s3
        state[2][col] = s0 ^ s1 ^ galois_mult(0x02, s2) ^ galois_mult(0x03, s3)
        state[3][col] = galois_mult(0x03, s0) ^ s1 ^ s2 ^ galois_mult(0x02, s3)
    return state

def add_round_key(state, round_key):
    """XOR state with round key"""
    print("  -> Applying AddRoundKey...")
    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]
    return state

def key_expansion(key):
    """Generate round keys from the original key"""
    print("\n" + "="*60)
    print("STEP 1: KEY EXPANSION")
    print("="*60)
    print(f"Original Key: {key.hex()}")
    
    # Initialize key schedule with original key
    key_schedule = [key[i:i+4] for i in range(0, 16, 4)]
    
    for round_num in range(1, 11):
        # Take last word
        temp = list(key_schedule[-1])
        
        # RotWord: rotate left by 1 byte
        temp = temp[1:] + temp[:1]
        
        # SubWord: apply S-box
        temp = [S_BOX[b] for b in temp]
        
        # XOR with round constant
        temp[0] ^= RCON[round_num]
        
        # XOR with word from 4 positions back
        new_word = bytes([temp[i] ^ key_schedule[-4][i] for i in range(4)])
        key_schedule.append(new_word)
        
        # Generate remaining 3 words for this round
        for _ in range(3):
            new_word = bytes([key_schedule[-1][i] ^ key_schedule[-4][i] for i in range(4)])
            key_schedule.append(new_word)
    
    # Convert to round keys (11 keys total: initial + 10 rounds)
    round_keys = []
    for i in range(0, 44, 4):
        round_key = bytes_to_state(b''.join(key_schedule[i:i+4]))
        round_keys.append(round_key)
        print(f"\nRound Key {i//4}: {b''.join(key_schedule[i:i+4]).hex()}")
    
    return round_keys

def pkcs7_pad(data, block_size=16):
    """Add PKCS7 padding to data"""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(data):
    """Remove PKCS7 padding from data"""
    padding_length = data[-1]
    return data[:-padding_length]

def aes_encrypt_block(plaintext_block, key, round_keys, block_num=1, show_details=True):
    """
    Encrypt a single 16-byte block
    
    Args:
        plaintext_block: Exactly 16 bytes
        key: 16 bytes encryption key
        round_keys: Pre-generated round keys
        block_num: Block number for display
        show_details: Whether to print detailed steps
    
    Returns:
        16 bytes of encrypted ciphertext
    """
    if show_details:
        print("\n" + "="*60)
        print(f"ENCRYPTING BLOCK {block_num}")
        print("="*60)
        print(f"Block plaintext: {plaintext_block.hex()}")
    
    # Convert plaintext to state
    state = bytes_to_state(plaintext_block)
    if show_details:
        print_state(state, "Initial State")
    
    # Initial round - just AddRoundKey
    if show_details:
        print("\n" + "="*60)
        print("INITIAL ROUND")
        print("="*60)
    state = add_round_key(state, round_keys[0])
    if show_details:
        print_state(state, "After Initial AddRoundKey")
    
    # Main rounds (1-9)
    for round_num in range(1, 10):
        if show_details:
            print("\n" + "="*60)
            print(f"ROUND {round_num}")
            print("="*60)
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])
        if show_details:
            print_state(state, f"State after Round {round_num}")
    
    # Final round (10) - no MixColumns
    if show_details:
        print("\n" + "="*60)
        print("ROUND 10 (FINAL)")
        print("="*60)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    if show_details:
        print_state(state, "Final State")
    
    # Convert state to bytes
    ciphertext = state_to_bytes(state)
    
    if show_details:
        print(f"\nBlock ciphertext: {ciphertext.hex()}")
    
    return ciphertext

def aes_encrypt(plaintext, key, show_details=True):
    """
    AES-128 Encryption (handles any length plaintext)
    
    Args:
        plaintext: Data to encrypt (any length)
        key: 16 bytes encryption key
        show_details: Whether to print detailed steps
    
    Returns:
        Encrypted ciphertext (padded to multiple of 16 bytes)
    """
    
    print("\n" + "="*60)
    print("AES-128 ENCRYPTION PROCESS")
    print("="*60)
    
    if len(key) != 16:
        raise ValueError("Key must be exactly 16 bytes (128 bits)")
    
    original_length = len(plaintext)
    plaintext_padded = pkcs7_pad(plaintext)
    
    print(f"\nOriginal plaintext length: {original_length} bytes")
    print(f"Padded plaintext length:   {len(plaintext_padded)} bytes")
    print(f"Plaintext (padded): {plaintext_padded.hex()}")
    print(f"Key:                {key.hex()}")
    
    round_keys = key_expansion(key)
    
    ciphertext = b""
    num_blocks = len(plaintext_padded) // 16
    
    print(f"\nNumber of blocks to encrypt: {num_blocks}")
    
    for i in range(num_blocks):
        block_start = i * 16
        block_end = block_start + 16
        plaintext_block = plaintext_padded[block_start:block_end]
        
        
        ciphertext_block = aes_encrypt_block(
            plaintext_block, 
            key, 
            round_keys, 
            block_num=i+1,
            show_details=(show_details and i == 0)
        )
        
        if i > 0 and show_details:
            print(f"\nBlock {i+1} ciphertext: {ciphertext_block.hex()}")
        
        ciphertext += ciphertext_block
    
    print("\n" + "="*60)
    print("RESULT")
    print("="*60)
    print(f"Total Ciphertext: {ciphertext.hex()}")
    
    return ciphertext

if __name__ == "__main__":
    print("\n" + "="*60)
    print("EXAMPLE 1: Short Message (needs padding)")
    print("="*60)
    plaintext = b"Hello!"  # Only 6 bytes
    key = b"MySecretKey12345"  # 16 bytes
    
    ciphertext = aes_encrypt(plaintext, key)
    
    print("\n" + "="*60)
    print("SUMMARY - EXAMPLE 1")
    print("="*60)
    print(f"Original plaintext: {plaintext} ({len(plaintext)} bytes)")
    print(f"Key:                {key}")
    print(f"Ciphertext:         {ciphertext.hex()}")
    
    