#!/usr/bin/python3 
import socket
from binascii import hexlify, unhexlify

def xor(first, second):
    """XOR two bytearrays element-wise"""
    return bytearray(x^y for x,y in zip(first, second))


class PaddingOracle:
    """
    Client to communicate with a padding oracle server.
    The oracle reveals whether decrypted ciphertext has valid PKCS#7 padding.
    """
    def __init__(self, host, port) -> None:
        # Establish TCP connection to the oracle server
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

        # Receive the initial ciphertext (IV + encrypted data) from server
        ciphertext = self.s.recv(4096).decode().strip()
        # Convert hex string to bytes for processing
        self.ctext = unhexlify(ciphertext)

    def decrypt(self, ctext: bytes) -> str:
        """
        Send ciphertext to oracle and get validation response.
        Returns: "Valid" if padding is correct, other response if invalid
        """
        self._send(hexlify(ctext))
        return self._recv()

    def _recv(self):
        """Receive response from oracle"""
        return self.s.recv(4096).decode().strip()

    def _send(self, hexstr: bytes):
        """Send hex-encoded data to oracle with newline terminator"""
        self.s.send(hexstr + b'\n')

    def __del__(self):
        """Clean up socket connection"""
        self.s.close()


def oracle_attack(oracle, IV, C_prev, C_current):
    """
    Decrypt one 16-byte block using padding oracle attack.
    
    How it works:
    1. We manipulate the previous ciphertext block (C_prev)
    2. This changes how C_current decrypts due to CBC mode
    3. We probe different values until we get valid padding
    4. Valid padding reveals information about the plaintext
    
    Args:
        oracle: PaddingOracle instance for validation queries
        IV: Initialization Vector (needed for oracle to decrypt)
        C_prev: Previous ciphertext block (affects decryption of C_current)
        C_current: Current ciphertext block to decrypt
    
    Returns:
        Plaintext block (bytearray of 16 bytes)
    """
    # D2: Intermediate decryption state (what comes out before XOR with C_prev)
    # In CBC mode: Plaintext = D2 XOR C_prev
    D2 = bytearray(16)
    
    # CC1: Modified version of C_prev that we send to the oracle
    CC1 = bytearray(16)
    
    # Attack bytes from right to left (byte 15 down to byte 0)
    # K represents the padding value we're trying to create
    for K in range(1, 17):
        # Step 1: Set up already-known bytes to produce valid padding
        # For padding K, the last K bytes must all equal K
        for j in range(16-K+1, 16):
            # Set CC1 so that: D2[j] XOR CC1[j] = K (valid padding)
            CC1[j] = D2[j] ^ K
        
        # Step 2: Brute force the current unknown byte (position 16-K)
        for i in range(256):
            CC1[16-K] = i
            
            # Step 3: Query the oracle with modified ciphertext
            # Send: IV + CC1 (modified) + C_current
            status = oracle.decrypt(IV + CC1 + C_current)
            
            # Step 4: Valid padding means we found the correct value
            if status == "Valid":
                # If padding is valid, then: D2[16-K] XOR i = K
                # Therefore: D2[16-K] = i XOR K
                D2[16-K] = i ^ K
                print(f"Byte {16-K}: Valid with i=0x{i:02x}, D2[{16-K}]=0x{D2[16-K]:02x}")
                break
    
    # Step 5: Recover plaintext by XORing intermediate state with actual C_prev
    # Remember: Plaintext = D2 XOR C_prev (CBC mode decryption)
    plaintext = xor(C_prev, D2)
    return plaintext


def remove_padding(data):
    """
    Remove PKCS#7 padding from decrypted data.
    
    PKCS#7 padding works as follows:
    - If N bytes of padding are needed, add N bytes each with value N
    - Example: [..., 0x03, 0x03, 0x03] means remove last 3 bytes
    """
    padding_length = data[-1]  # Last byte indicates padding length
    return data[:-padding_length]


def extract_blocks(data, block_size=16):
    """
    Split data into fixed-size blocks.
    
    Args:
        data: Bytearray to split
        block_size: Size of each block (default 16 for AES)
    
    Returns:
        List of blocks (each is a bytearray)
    """
    blocks = []
    for i in range(0, len(data), block_size):
        blocks.append(data[i:i+block_size])
    return blocks


def decrypt_all_blocks(oracle, IV, ciphertext_blocks):
    """
    Decrypt all ciphertext blocks using padding oracle attack.
    
    Args:
        oracle: PaddingOracle instance
        IV: Initialization Vector
        ciphertext_blocks: List of ciphertext blocks
    
    Returns:
        Full plaintext as bytearray
    """
    plaintext_blocks = []
    
    for i, C_current in enumerate(ciphertext_blocks):
        print(f"\n--- Decrypting Block {i+1}/{len(ciphertext_blocks)} ---")
        
        # Determine the previous block for CBC XOR operation
        # First block uses IV, subsequent blocks use previous ciphertext
        C_prev = IV if i == 0 else ciphertext_blocks[i-1]
        
        # Decrypt current block
        plaintext_block = oracle_attack(oracle, IV, C_prev, C_current)
        plaintext_blocks.append(plaintext_block)
        
        print(f"Block {i+1} plaintext (hex): {plaintext_block.hex()}")
    
    # Combine all decrypted blocks into single bytearray
    full_plaintext = bytearray()
    for block in plaintext_blocks:
        full_plaintext.extend(block)
    
    return full_plaintext


if __name__ == "__main__":
    # Step 1: Connect to the padding oracle server
    oracle = PaddingOracle('10.9.0.80', 6000)

    # Step 2: Receive and parse IV + Ciphertext
    iv_and_ctext = bytearray(oracle.ctext)
    
    # First 16 bytes are the Initialization Vector
    IV = iv_and_ctext[0:16]
    print("IV: " + IV.hex())
    
    # Remaining bytes are the ciphertext
    ciphertext_data = iv_and_ctext[16:]
    num_blocks = len(ciphertext_data) // 16
    print(f"Number of ciphertext blocks: {num_blocks}")
    
    # Step 3: Extract ciphertext blocks
    ciphertext_blocks = extract_blocks(ciphertext_data, block_size=16)
    for i, block in enumerate(ciphertext_blocks):
        print(f"C{i+1}: {block.hex()}")
    
    print("\n" + "="*60)
    print("Starting Padding Oracle Attack...")
    print("="*60 + "\n")
    
    # Step 4: Decrypt all blocks using the oracle
    full_plaintext = decrypt_all_blocks(oracle, IV, ciphertext_blocks)
    
    print("\n" + "="*60)
    print("Attack Complete!")
    print("="*60)
    
    # Step 5: Display results
    print(f"\nFull plaintext with padding (hex):")
    print(full_plaintext.hex())
    
    # Step 6: Remove PKCS#7 padding to get actual message
    plaintext_no_padding = remove_padding(full_plaintext)
    
    print(f"\nFull plaintext without padding (hex):")
    print(plaintext_no_padding.hex())
    
    # Step 7: Convert to readable text
    try:
        message = plaintext_no_padding.decode('utf-8')
        print(f"\nDecrypted message: {message}")
    except:
        print(f"\nDecrypted message (raw bytes): {plaintext_no_padding}")
