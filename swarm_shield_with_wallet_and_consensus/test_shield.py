import unittest
from unittest.mock import MagicMock
from shield import Shield
from wallet import Wallet
from message import EncryptedMessage
from web3 import Web3


class TestShield(unittest.TestCase):
    def setUp(self):
        """Set up a mock Wallet and Shield instance for testing."""
        self.test_sender_wallet_path = "./data/test_sender_wallet.json"
        self.sender_wallet = Wallet(self.test_sender_wallet_path)
        self.test_receipt_wallet_path = "./data/test_receipt_wallet.json"
        self.receipt_wallet = Wallet(self.test_receipt_wallet_path)
        
        self.shield_sender = Shield(self.sender_wallet)
        self.shield_receipt = Shield(self.receipt_wallet)


    def test_encrypt_for_recipient_success(self):
        """Test successful encryption for a recipient."""
        recipient_address = self.receipt_wallet.address
        message = "hello world"
        result = self.shield_sender.encrypt(message, recipient_address)
        self.assertIsInstance(result, EncryptedMessage)
        self.assertEqual(result.sender, self.sender_wallet.address)

    def test_decrypt_from_sender_success(self):
        """Test successful decryption from a sender."""
        sender_address = self.sender_wallet.address
        message = "hello world"
        encrypted_data = self.shield_sender.encrypt(message, self.receipt_wallet.address)
        result = self.shield_receipt.decrypt(sender_address, encrypted_data)
        self.assertEqual(result, "hello world")

    def test_verify_sender_success(self):
        """Test successful sender verification."""
        sender_address = self.sender_wallet.address
        message = "hello world"
        encrypted_data = self.shield_sender.encrypt(message, self.receipt_wallet.address)
        result = self.shield_receipt.verify(sender_address, encrypted_data.ciphertext, encrypted_data.signature)
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
