from dataclasses import dataclass
from typing import Dict
import re
from eth_utils import is_checksum_address

@dataclass
class EncryptedMessage:
    sender: str       # The Ethereum address of the sender
    iv: str           # Hex-encoded initialization vector
    ciphertext: str   # Hex-encoded encrypted message
    signature: str    # Hex-encoded signature
    nonce: str        # Hex-encoded nonce
    #version: str = "1.0"  # Optional field with a default value
    #timestamp: int = None  # Optional field for when the message was created

    HEX_PATTERN = re.compile(r"^0x[a-fA-F0-9]+$")

    def __post_init__(self):
        """Perform validation after initialization."""
        if not is_checksum_address(self.sender):
            raise ValueError(f"Invalid Ethereum address: {self.sender}")
        for field_name, value in [("iv", self.iv), ("ciphertext", self.ciphertext), 
                                  ("signature", self.signature), ("nonce", self.nonce)]:
            if not self.HEX_PATTERN.match(value):
                raise ValueError(f"Invalid hexadecimal value for {field_name}: {value}")

    def from_dict(data: Dict[str, str]) -> "EncryptedMessage":
        """Create an EncryptedMessage instance from a dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected a dictionary, got {type(data).__name__} instead.")
        
        required_fields = {"sender", "iv", "ciphertext", "signature", "nonce"}
        missing = required_fields - data.keys()
        if missing:
            raise ValueError(f"Missing required fields: {missing}. Provided fields: {list(data.keys())}")

        return EncryptedMessage(
            sender=data["sender"],
            iv=data["iv"],
            ciphertext=data["ciphertext"],
            signature=data["signature"],
            nonce=data["nonce"],
        )

        
    def to_dict(self) -> Dict[str, str]:
        """Convert the EncryptedMessage instance to a dictionary."""
        result = {
            "sender": self.sender,
            "iv": self.iv,
            "ciphertext": self.ciphertext,
            "signature": self.signature,
            "nonce": self.nonce,
            #"version": self.version,
        }
        #if self.timestamp is not None:
        #    result["timestamp"] = self.timestamp
        return result
