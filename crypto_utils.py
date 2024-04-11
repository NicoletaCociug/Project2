from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import os

def generate_keys_for_user():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key.decode(), private_key.decode()

def encrypt_private_key(private_key, password):
    """
    Encrypt a private RSA key using a password.
    """
    salt = get_random_bytes(16)  # Random salt for key derivation
    key = PBKDF2(password, salt, dkLen=32, count=1000000)  # Derive a key from the password
    cipher = AES.new(key, AES.MODE_EAX)  # Create a new AES cipher in EAX mode
    private_key_bytes = private_key.exportKey('PEM')  # Export the private key to bytes
    ciphertext, tag = cipher.encrypt_and_digest(private_key_bytes)  # Encrypt and get the MAC tag
    encrypted_private_key = salt + cipher.nonce + tag + ciphertext  # Concatenate salt, nonce, tag, and ciphertext for storage
    return encrypted_private_key

def save_encrypted_private_key(username, encrypted_private_key):
    """
    Save an encrypted private key to a file.
    """
    file_path = os.path.join(os.getcwd(), f"{username}_private_key.pem")  # Define the file path
    with open(file_path, 'wb') as file_out:  # Open the file in write-binary mode
        file_out.write(encrypted_private_key)  # Write the encrypted key
    return file_path


def generate_symmetric_key_for_group():
    return get_random_bytes(16)

def encrypt_symmetric_key(symmetric_key, public_key):
    #RSA encryption of the symmetric key with the public key
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(symmetric_key)
    return base64.b64encode(encrypted_key).decode('utf-8')

def encrypt_message_with_symmetric_key(message, symmetric_key):
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(pad(message.encode('utf-8'), AES.block_size))
    return base64.b64encode(cipher_aes.nonce + tag + ciphertext).decode('utf-8')

def decrypt_message_with_symmetric_key(encrypted_message, symmetric_key):
    try:
        encrypted_message = base64.b64decode(encrypted_message)
        nonce, tag, ciphertext = encrypted_message[:16], encrypted_message[16:32], encrypted_message[32:]
        cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
        plaintext = unpad(cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError):
        return "***Unable to decrypt message***"

def decrypt_symmetric_key(encrypted_symmetric_key,  private_key_pem):
    encrypted_symmetric_key = base64.b64decode(encrypted_symmetric_key)
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_symmetric_key = cipher_rsa.decrypt(encrypted_symmetric_key)
    return decrypted_symmetric_key

#function to load and decrypt the user's private key
def load_and_decrypt_private_key(username, password):
    file_path = os.path.join(os.getcwd(), f"{username}_private_key.pem")
    try:
        with open(file_path, 'rb') as file_in:
            encrypted_private_key = file_in.read()
            salt = encrypted_private_key[:16]
            nonce = encrypted_private_key[16:32]
            tag = encrypted_private_key[32:48]
            ciphertext = encrypted_private_key[48:]
            
            key = PBKDF2(password, salt, dkLen=32, count=1000000)  # Derive the key from the password
            cipher = AES.new(key, AES.MODE_EAX, nonce)  # Create a new AES cipher in EAX mode
            private_key_bytes = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt the ciphertext and verify with the tag
            
            return RSA.import_key(private_key_bytes)  # Convert bytes to RSA key
    except ValueError as e:
        print(f"Incorrect decryption key or corrupted data: {e}")
    except Exception as e:
        print(f"General error in decryption: {e}")

    return None



# The rest of your cryptographic functions go here (e.g., encrypt_private_key, save_encrypted_private_key)
