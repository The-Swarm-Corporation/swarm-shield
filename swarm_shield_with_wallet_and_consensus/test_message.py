import unittest
from message import EncryptedMessage


class TestEncryptedMessage(unittest.TestCase):
    def test_valid_message(self):
        """Test creating a valid EncryptedMessage instance."""
        data = {
            "sender": "0x9C5a850A35298A2fB2A430C68f8Eb4360f41A9f2",
            "iv": "0x415fed95af8c22fa8bf58a86c37b7ba8",
            "ciphertext": "0x75c989da084931b47c0cb5",
            "signature": "0x3fd826fbd0fe87222fe48b8017ad0fce82711a5515274707e5c5a47723ad530f4ddc7581fa8ba1ec3b1e3840ad9b0bdb39f9d6a1fb13259d1870907d518cddbb1b",
            "nonce": "0x931d963cf4c697343db59f38993e7ef0",
        }
        message = EncryptedMessage.from_dict(data)
        self.assertEqual(message.sender, data["sender"])
        self.assertEqual(message.to_dict(), data)

    def test_missing_fields(self):
        """Test creating an EncryptedMessage with missing fields."""
        data = {
            "sender": "0x9C5a850A35298A2fB2A430C68f8Eb4360f41A9f2",
            "iv": "0x415fed95af8c22fa8bf58a86c37b7ba8",
            "ciphertext": "0x75c989da084931b47c0cb5"
        }
        with self.assertRaises(ValueError) as context:
            EncryptedMessage.from_dict(data)
        self.assertIn("Missing required fields", str(context.exception))

    def test_invalid_sender(self):
        """Test invalid Ethereum address."""
        data = {
            "sender": "invalid_address",
            "iv": "0x1a2b3c",
            "ciphertext": "0xdeadbeef",
            "signature": "0xabcdef",
            "nonce": "0xbeefdead",
        }
        with self.assertRaises(ValueError) as context:
            EncryptedMessage.from_dict(data)
        self.assertIn("Invalid Ethereum address", str(context.exception))

    def test_invalid_hex(self):
        """Test invalid hexadecimal values."""
        data = {
            "sender": "0x9C5a850A35298A2fB2A430C68f8Eb4360f41A9f2",
            "iv": "invalid_hex",
            "ciphertext": "0x75c989da084931b47c0cb5",
            "signature": "0x3fd826fbd0fe87222fe48b8017ad0fce82711a5515274707e5c5a47723ad530f4ddc7581fa8ba1ec3b1e3840ad9b0bdb39f9d6a1fb13259d1870907d518cddbb1b",
            "nonce": "0x931d963cf4c697343db59f38993e7ef0",
        }
        with self.assertRaises(ValueError) as context:
            EncryptedMessage.from_dict(data)
        self.assertIn("Invalid hexadecimal value for iv", str(context.exception))


if __name__ == "__main__":
    unittest.main()
