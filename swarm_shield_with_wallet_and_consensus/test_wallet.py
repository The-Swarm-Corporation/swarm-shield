import unittest
import os
from wallet import Wallet


class TestWallet(unittest.TestCase):
    def setUp(self):
        """Set up resources for each test."""
        self.test_wallet_path = "./data/test_wallet.json"
        self.wallet = Wallet(self.test_wallet_path)

    def tearDown(self):
        """Clean up resources after each test."""
        if os.path.exists(self.test_wallet_path):
            os.remove(self.test_wallet_path)

    def test_wallet_creation(self):
        """Test if a wallet is created successfully."""
        self.assertTrue(os.path.exists(self.test_wallet_path))
        self.assertTrue(self.wallet.address.startswith("0x"))

    def test_wallet_sign_message(self):
        """Test the wallet's ability to sign a message."""
        message = b"Test message"
        signature = self.wallet.sign_message(message)
        self.assertIsInstance(signature, str)
        self.assertTrue(signature.startswith("0x"))

    def test_wallet_encrypt_decrypt(self):
        """Test the wallet's encryption and decryption."""
        recipient_wallet = Wallet("./data/recipient_wallet.json")
        try:
            message = "Secret message"
            encrypted_message = self.wallet.encrypt_message(recipient_wallet.address, message)
            decrypted_message = recipient_wallet.decrypt_message(self.wallet.address, encrypted_message)
            self.assertEqual(decrypted_message, message)
        finally:
            if os.path.exists("./data/recipient_wallet.json"):
                os.remove("./data/recipient_wallet.json")

    def test_wallet_invalid_decryption(self):
        """Test decryption with tampered data."""
        recipient_wallet = Wallet("./data/recipient_wallet.json")
        try:
            message = "Another secret"
            encrypted_message = self.wallet.encrypt_message(recipient_wallet.address, message)
            encrypted_message.ciphertext = "0xdeadbeef"  # Tamper with the ciphertext

            with self.assertRaises(ValueError):
                recipient_wallet.decrypt_message(self.wallet.address, encrypted_message)
        finally:
            if os.path.exists("./data/recipient_wallet.json"):
                os.remove("./data/recipient_wallet.json")


if __name__ == "__main__":
    unittest.main()
