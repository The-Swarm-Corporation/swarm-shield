from web3 import Web3, Account
from eth_keys import keys
from eth_utils import decode_hex, encode_hex, is_checksum_address
from eth_account.messages import encode_defunct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json
import hashlib

import logging

from message import EncryptedMessage


class WalletConfig:
    DEFAULT_KEY_PATH = './wallet.json'
    ENCRYPTION_ITERATIONS = 100_000
    
class Wallet:
    def __init__(self, key_path: str = WalletConfig.DEFAULT_KEY_PATH):
        """Initialize a wallet with a private key or generate a new one."""
        try:
            directory = os.path.dirname(key_path)
            if directory:
                if not os.path.exists(directory):
                    os.makedirs(directory)
            
            if os.path.exists(key_path):
                with open(key_path, 'r') as file:
                    key_json = json.load(file)
                    if "private_key" not in key_json:
                        raise ValueError("Invalid key file: 'private_key' field is missing.")
                    private_key = key_json['private_key']
                    self.load(private_key)
            else:
                self.create()
                self.save_as_json(key_path)
        except (IOError, json.JSONDecodeError) as e:
            raise ValueError(f"Error reading wallet file: {e}")

    def load(self, private_key: str) -> None:
        """Initialize a wallet with a private key."""
        try:
            self.private_key = keys.PrivateKey(decode_hex(private_key))
            self.public_key = self.private_key.public_key
            self.address = Web3.to_checksum_address(Web3.keccak(self.public_key.to_bytes())[12:])
        except Exception as e:
            raise ValueError(f"Error loading private key: {e}")

    def create(self) -> None:
        """Generate a new wallet with a private key, public key, and Ethereum address."""
        try:
            self.private_key = keys.PrivateKey(os.urandom(32))
            self.public_key = self.private_key.public_key
            self.address = Web3.to_checksum_address(Web3.keccak(self.public_key.to_bytes())[12:])
            logging.info("Wallet created: %s", self.address)
        except Exception as e:
            raise RuntimeError(f"Error creating wallet: {e}")

    def save_as_json(self, key_path: str) -> None:
        """Save the wallet's private key to a file."""
        try:
            key_json = {
                "private_key": encode_hex(self.private_key.to_bytes())
            }
            with open(key_path, 'w') as f:
                json.dump(key_json, f)
        except IOError as e:
            raise IOError(f"Error saving wallet file: {e}")

    def sign_message(self, message: bytes) -> str:
        """Sign a message using the wallet's private key with Ethereum's standard prefix."""
        try:
            eth_message = encode_defunct(message)
            signature = Account.sign_message(eth_message, private_key=encode_hex(self.private_key.to_bytes()))
            return encode_hex(signature.signature)  # Ensure signature is hex-encoded
        except Exception as e:
            raise ValueError(f"Error signing message: {e}")

    def encrypt_message(self, recipient_address: str, message: str) -> EncryptedMessage:
        """Encrypt a message for the recipient using their Ethereum address."""
        if not is_checksum_address(recipient_address):
            raise ValueError("Invalid recipient Ethereum address.")
        
        if not message:
            raise ValueError("Message cannot be empty.")

        nonce = os.urandom(16)  # Generate a random nonce
        shared_secret = Wallet._derive_shared_secret(self.address, recipient_address, nonce)

        iv = os.urandom(16)
        try:
            cipher = Cipher(algorithms.AES(shared_secret), modes.CFB(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        except Exception as e:
            logging.error("Encryption failed: %s", str(e))
            raise ValueError(f"Error during encryption: {e}")

        signature = self.sign_message(ciphertext)

        # Return an EncryptedMessage instance
        return EncryptedMessage(
            sender=self.address,
            iv=encode_hex(iv),
            ciphertext=encode_hex(ciphertext),
            signature=signature,
            nonce=encode_hex(nonce),
        )

    def decrypt_message(self, sender_address: str, encrypted_data: EncryptedMessage) -> str:
        """Decrypt a message and verify the sender using their Ethereum address."""
        if not is_checksum_address(sender_address):
            raise ValueError("Invalid sender Ethereum address.")
        
        iv = decode_hex(encrypted_data.iv)
        ciphertext_str = encrypted_data.ciphertext
        ciphertext = decode_hex(ciphertext_str)
        signature = encrypted_data.signature
        nonce = decode_hex(encrypted_data.nonce)

        shared_secret = Wallet._derive_shared_secret(sender_address, self.address, nonce)

        if not Wallet.verify_sender_with_address(sender_address, ciphertext_str, signature):
            raise ValueError("Invalid sender signature.")

        try:
            cipher = Cipher(algorithms.AES(shared_secret), modes.CFB(iv))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            raise ValueError(f"Error during decryption: {e}")

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Decryption produced invalid UTF-8 output. Check keys and ciphertext integrity.")

    @staticmethod
    def _derive_shared_secret(sender_address: str, recipient_address: str, nonce: bytes) -> bytes:
        """Derive a shared secret using HMAC for better extensibility."""
        import hmac

        secret_key = b"wallet-shared-secret-key"
        input_data = (sender_address.lower() + recipient_address.lower()).encode() + nonce
        shared_secret = hmac.new(secret_key, input_data, hashlib.sha256).digest()
        logging.debug("Deriving shared secret for addresses: %s -> %s", sender_address, recipient_address)
        return shared_secret

    @staticmethod
    def verify_sender_with_address(sender_address: str, message_str: str, signature: str) -> bool:
        """Verify that the encrypted message was sent by the claimed sender using their Ethereum address."""
        try:
            message = decode_hex(message_str)
            eth_message = encode_defunct(message)
            recovered_address = Account.recover_message(eth_message, signature=signature)
            return Web3.to_checksum_address(recovered_address) == sender_address
        except Exception as e:
            raise ValueError(f"Error verifying sender signature: {e}")
        


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
    
    try:
        wallet_a = Wallet("./data/wallet_a.json")
        wallet_b = Wallet("./data/wallet_b.json")

        logging.info("Wallet A Address: %s"%wallet_a.address)
        logging.info("Wallet B Address: %s"%wallet_b.address)

        message = "hello world"
        encrypted_message = wallet_a.encrypt_message(wallet_b.address, message)
        logging.info("Encrypted Message: %s"%encrypted_message)

        try:
            # Perform web3 operation
            is_valid = Wallet.verify_sender_with_address(wallet_a.address, encrypted_message.ciphertext, encrypted_message.signature)
            logging.info("Is the sender verified using address?: %s"%is_valid)
            
            if is_valid:
                decrypted_message = wallet_b.decrypt_message(wallet_a.address, encrypted_message)
                logging.info("Decrypted Message: %s", decrypted_message)
            else:
                logging.warning("Failed to verify the sender.")
            
        except ValueError as e:
            raise ValueError(f"Decryption failed for message from {wallet_a.address}: {e}")
        except Web3.exceptions.InvalidAddress as e:
            logging.error(f"Invalid Ethereum address: {e}")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
