
import logging
from typing import Dict
from wallet import Wallet
from message import EncryptedMessage
from eth_utils import is_checksum_address


class Shield:
    def __init__(self, wallet: Wallet):
        """
        Shield class for secure message encryption, decryption, and verification.
        Args:
            wallet (Wallet): An instance of the Wallet class.
        """
        self.wallet = wallet

    def encrypt(self, message: str, recipient_address: str) -> EncryptedMessage:
        """
        Encrypt a message for the recipient.
        Args:
            message (str): The plaintext message to encrypt.
            recipient_address (str): The recipient's Ethereum address.

        Returns:
            EncryptedMessage: An encrypted message object.
        """
        if not message:
            raise ValueError("Message cannot be empty.")
        if not is_checksum_address(recipient_address):
            raise ValueError(f"Invalid recipient Ethereum address: {recipient_address}")

        try:
            encrypted_message = self.wallet.encrypt_message(recipient_address, message)
            logging.debug(f"Message encrypted for recipient: {recipient_address}")
            return encrypted_message
        except Exception as e:
            logging.error(f"Failed to encrypt message: {e}")
            raise RuntimeError(f"Encryption failed: {e}")

    def decrypt(self, sender_address: str, encrypted_data: EncryptedMessage) -> str:
        """
        Decrypt a message from the sender.
        Args:
            sender_address (str): The sender's Ethereum address.
            encrypted_data (EncryptedMessage): The encrypted message object.

        Returns:
            str: The decrypted plaintext message.
        """
        if not is_checksum_address(sender_address):
            raise ValueError(f"Invalid sender Ethereum address: {sender_address}")

        try:
            decrypted_message = self.wallet.decrypt_message(sender_address, encrypted_data)
            logging.debug(f"Message decrypted from sender: {sender_address}")
            return decrypted_message
        except Exception as e:
            logging.error(f"Failed to decrypt message: {e}")
            raise RuntimeError(f"Decryption failed: {e}")

    def verify(self, sender_address: str, message: str, signature: str) -> bool:
        """
        Verify the sender's signature for a message.
        Args:
            sender_address (str): The sender's Ethereum address.
            message (str): The plaintext message.
            signature (str): The signature to verify.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        if not is_checksum_address(sender_address):
            raise ValueError(f"Invalid sender Ethereum address: {sender_address}")

        try:
            is_valid = self.wallet.verify_sender_with_address(sender_address, message, signature)
            if is_valid:
                logging.debug(f"Signature verified for sender: {sender_address}")
            else:
                logging.warning(f"Failed to verify signature for sender: {sender_address}")
            return is_valid
        except Exception as e:
            logging.error(f"Failed to verify signature: {e}")
            raise RuntimeError(f"Verification failed: {e}")
