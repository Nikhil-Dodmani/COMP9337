from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys
import binascii
import time

def encrypt_aes_cbc(iv, key, inputfile, outputfile):
    iv_bytes = binascii.unhexlify(iv)
    key_bytes = binascii.unhexlify(key)
    
    # Ensure the key is 16, 24, or 32 bytes long
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("Incorrect AES key length (%d bytes)" % len(key_bytes))
    
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

    with open(inputfile, 'rb') as f:
        plaintext = f.read()

    padded_plaintext = pad(plaintext, AES.block_size)

    start_time = time.time()
    ciphertext = cipher.encrypt(padded_plaintext)
    encryption_time = time.time() - start_time

    with open(outputfile, 'wb') as f:
        f.write(ciphertext)

    print(f"Encryption complete. Time taken: {encryption_time * 1e6:.2f} microseconds")
    return encryption_time

def decrypt_aes_cbc(iv, key, inputfile, outputfile):
    iv_bytes = binascii.unhexlify(iv)
    key_bytes = binascii.unhexlify(key)
    
    # Ensure the key is 16, 24, or 32 bytes long
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("Incorrect AES key length (%d bytes)" % len(key_bytes))
    
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

    with open(inputfile, 'rb') as f:
        ciphertext = f.read()

    start_time = time.time()
    padded_plaintext = cipher.decrypt(ciphertext)
    decryption_time = time.time() - start_time

    plaintext = unpad(padded_plaintext, AES.block_size)

    with open(outputfile, 'wb') as f:
        f.write(plaintext)

    print(f"Decryption complete. Time taken: {decryption_time * 1e6:.2f} microseconds")
    return decryption_time

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python3 tempaes.py <mode> <iv> <key> <inputfile> <outputfile>")
        print("mode: 'encrypt' or 'decrypt'")
        sys.exit(1)

    mode = sys.argv[1]
    iv = sys.argv[2]
    key = sys.argv[3]
    inputfile = sys.argv[4]
    outputfile = sys.argv[5]

    if mode == 'encrypt':
        encrypt_aes_cbc(iv, key, inputfile, outputfile)
    elif mode == 'decrypt':
        decrypt_aes_cbc(iv, key, inputfile, outputfile)
    else:
        print("Invalid mode. Use 'encrypt' or 'decrypt'")
