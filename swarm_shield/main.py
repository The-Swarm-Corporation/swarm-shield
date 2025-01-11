from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from loguru import logger


class EncryptionStrength(Enum):
    """Encryption strength levels"""
    STANDARD = "standard"    # AES-256
    ENHANCED = "enhanced"    # AES-256 + SHA-512
    MAXIMUM = "maximum"      # AES-256 + SHA-512 + HMAC

class SwarmShield:
    """
    SwarmShield: Advanced security system for swarm agents
    
    Features:
    - Multi-layer message encryption
    - Secure conversation storage
    - Automatic key rotation
    - Message integrity verification
    """
    
    def __init__(
        self,
        encryption_strength: EncryptionStrength = EncryptionStrength.MAXIMUM,
        key_rotation_interval: int = 3600,  # 1 hour
        storage_path: Optional[str] = None
    ):
        """Initialize SwarmShield with security settings"""
        self.encryption_strength = encryption_strength
        self.key_rotation_interval = key_rotation_interval
        self.storage_path = Path(storage_path or "swarm_shield_storage")
        
        # Initialize storage and locks
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._conv_lock = threading.Lock()
        self._conversations: Dict[str, List[Dict]] = {}
        
        # Initialize security components
        self._initialize_security()
        self._load_conversations()
        
        logger.info(f"SwarmShield initialized with {encryption_strength.value} encryption")
    
    def _initialize_security(self) -> None:
        """Set up encryption keys and components"""
        try:
            # Generate master key and salt
            self.master_key = secrets.token_bytes(32)
            self.salt = os.urandom(16)
            
            # Initialize key derivation
            self.kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=self.salt,
                iterations=600000,
                backend=default_backend()
            )
            
            # Generate initial keys
            self._rotate_keys()
            self.hmac_key = secrets.token_bytes(32)
            
        except Exception as e:
            logger.error(f"Security initialization failed: {e}")
            raise
    
    def _rotate_keys(self) -> None:
        """Perform security key rotation"""
        try:
            self.encryption_key = self.kdf.derive(self.master_key)
            self.iv = os.urandom(16)
            self.last_rotation = time.time()
            logger.debug("Security keys rotated successfully")
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            raise
    
    def _check_rotation(self) -> None:
        """Check and perform key rotation if needed"""
        if time.time() - self.last_rotation >= self.key_rotation_interval:
            self._rotate_keys()
    
    def _load_conversations(self) -> None:
        """Load existing conversations from storage"""
        try:
            for file_path in self.storage_path.glob("*.conv"):
                try:
                    with open(file_path, "rb") as f:
                        encrypted_data = f.read()
                    conversation_id = file_path.stem
                    
                    # Decrypt conversation data
                    cipher = Cipher(
                        algorithms.AES(self.encryption_key),
                        modes.GCM(self.iv),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    json_data = decryptor.update(encrypted_data) + decryptor.finalize()
                    
                    self._conversations[conversation_id] = json.loads(json_data)
                    logger.debug(f"Loaded conversation {conversation_id}")
                    
                except Exception as e:
                    logger.error(f"Failed to load conversation {file_path}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Failed to load conversations: {e}")
            raise
    
    def _save_conversation(self, conversation_id: str) -> None:
        """Save conversation to encrypted storage"""
        try:
            if conversation_id not in self._conversations:
                return
                
            # Encrypt conversation data
            json_data = json.dumps(self._conversations[conversation_id]).encode()
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(self.iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(json_data) + encryptor.finalize()
            
            # Save atomically using temporary file
            conv_path = self.storage_path / f"{conversation_id}.conv"
            temp_path = conv_path.with_suffix('.tmp')
            
            with open(temp_path, "wb") as f:
                f.write(encrypted_data)
            temp_path.replace(conv_path)
            
            logger.debug(f"Saved conversation {conversation_id}")
            
        except Exception as e:
            logger.error(f"Failed to save conversation: {e}")
            raise
    
    def protect_message(self, agent_name: str, message: str) -> str:
        """
        Encrypt a message with multiple security layers
        
        Args:
            agent_name: Name of the sending agent
            message: Message to encrypt
            
        Returns:
            Encrypted message string
        """
        try:
            self._check_rotation()
            
            # Validate inputs
            if not isinstance(agent_name, str) or not isinstance(message, str):
                raise ValueError("Agent name and message must be strings")
            if not agent_name.strip() or not message.strip():
                raise ValueError("Agent name and message cannot be empty")
            
            # Generate message ID and timestamp
            message_id = secrets.token_hex(16)
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Encrypt message content
            message_bytes = message.encode()
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(self.iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
            
            # Calculate message hash
            message_hash = hashlib.sha512(message_bytes).hexdigest()
            
            # Generate HMAC if maximum security
            hmac_signature = None
            if self.encryption_strength == EncryptionStrength.MAXIMUM:
                h = hmac.new(self.hmac_key, ciphertext, hashlib.sha512)
                hmac_signature = h.digest()
            
            # Create secure package
            secure_package = {
                "id": message_id,
                "time": timestamp,
                "agent": agent_name,
                "cipher": base64.b64encode(ciphertext).decode(),
                "tag": base64.b64encode(encryptor.tag).decode(),
                "hash": message_hash,
                "hmac": base64.b64encode(hmac_signature).decode() if hmac_signature else None
            }
            
            return base64.b64encode(json.dumps(secure_package).encode()).decode()
            
        except Exception as e:
            logger.error(f"Failed to protect message: {e}")
            raise
    
    def retrieve_message(self, encrypted_str: str) -> Tuple[str, str]:
        """
        Decrypt and verify a message
        
        Args:
            encrypted_str: Encrypted message string
            
        Returns:
            Tuple of (agent_name, message)
        """
        try:
            # Decode secure package
            secure_package = json.loads(base64.b64decode(encrypted_str))
            
            # Get components
            ciphertext = base64.b64decode(secure_package["cipher"])
            tag = base64.b64decode(secure_package["tag"])
            
            # Verify HMAC if present
            if secure_package["hmac"]:
                hmac_signature = base64.b64decode(secure_package["hmac"])
                h = hmac.new(self.hmac_key, ciphertext, hashlib.sha512)
                if not hmac.compare_digest(hmac_signature, h.digest()):
                    raise ValueError("HMAC verification failed")
            
            # Decrypt message
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(self.iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Verify hash
            if hashlib.sha512(decrypted_data).hexdigest() != secure_package["hash"]:
                raise ValueError("Message hash verification failed")
            
            return secure_package["agent"], decrypted_data.decode()
            
        except Exception as e:
            logger.error(f"Failed to retrieve message: {e}")
            raise
    
    def create_conversation(self, name: str = "") -> str:
        """Create a new secure conversation"""
        conversation_id = str(uuid.uuid4())
        with self._conv_lock:
            self._conversations[conversation_id] = {
                "id": conversation_id,
                "name": name,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "messages": []
            }
            self._save_conversation(conversation_id)
        logger.info(f"Created conversation {conversation_id}")
        return conversation_id
    
    def add_message(self, conversation_id: str, agent_name: str, message: str) -> None:
        """
        Add an encrypted message to a conversation
        
        Args:
            conversation_id: Target conversation ID
            agent_name: Name of the sending agent
            message: Message content
        """
        try:
            # Encrypt message
            encrypted = self.protect_message(agent_name, message)
            
            # Add to conversation
            with self._conv_lock:
                if conversation_id not in self._conversations:
                    raise ValueError(f"Invalid conversation ID: {conversation_id}")
                
                self._conversations[conversation_id]["messages"].append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": encrypted
                })
                
                # Save changes
                self._save_conversation(conversation_id)
            
            logger.info(f"Added message to conversation {conversation_id}")
            
        except Exception as e:
            logger.error(f"Failed to add message: {e}")
            raise
    
    def get_messages(self, conversation_id: str) -> List[Tuple[str, str, datetime]]:
        """
        Get decrypted messages from a conversation
        
        Args:
            conversation_id: Target conversation ID
            
        Returns:
            List of (agent_name, message, timestamp) tuples
        """
        try:
            with self._conv_lock:
                if conversation_id not in self._conversations:
                    raise ValueError(f"Invalid conversation ID: {conversation_id}")
                
                history = []
                for msg in self._conversations[conversation_id]["messages"]:
                    agent_name, message = self.retrieve_message(msg["data"])
                    timestamp = datetime.fromisoformat(msg["timestamp"])
                    history.append((agent_name, message, timestamp))
                
                return sorted(history, key=lambda x: x[2])
                
        except Exception as e:
            logger.error(f"Failed to get messages: {e}")
            raise
    
    def delete_conversation(self, conversation_id: str) -> None:
        """Delete a conversation and its encrypted storage"""
        try:
            with self._conv_lock:
                if conversation_id not in self._conversations:
                    raise ValueError(f"Invalid conversation ID: {conversation_id}")
                
                # Remove from memory
                del self._conversations[conversation_id]
                
                # Remove from disk
                conv_path = self.storage_path / f"{conversation_id}.conv"
                if conv_path.exists():
                    conv_path.unlink()
                
            logger.info(f"Deleted conversation {conversation_id}")
            
        except Exception as e:
            logger.error(f"Failed to delete conversation: {e}")
            raise

    def query_conversations(
        self,
        agent_name: Optional[str] = None,
        text: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: Optional[int] = None
    ) -> List[Dict]:
        """
        Search conversations with various filters
        
        Args:
            agent_name: Filter by agent name
            text: Search message content
            start_date: Filter messages after this date
            end_date: Filter messages before this date
            limit: Maximum number of results
            
        Returns:
            List of matching conversation details
        """
        try:
            matching_convs = []
            
            with self._conv_lock:
                for conv_id, conv_data in self._conversations.items():
                    messages = []
                    match_found = False
                    
                    for msg in conv_data["messages"]:
                        # Decrypt and check message
                        agent, content = self.retrieve_message(msg["data"])
                        timestamp = datetime.fromisoformat(msg["timestamp"])
                        
                        # Apply filters
                        if agent_name and agent != agent_name:
                            continue
                        if text and text.lower() not in content.lower():
                            continue
                        if start_date and timestamp < start_date:
                            continue
                        if end_date and timestamp > end_date:
                            continue
                            
                        match_found = True
                        messages.append({
                            "agent": agent,
                            "content": content,
                            "timestamp": timestamp
                        })
                    
                    if match_found:
                        matching_convs.append({
                            "id": conv_id,
                            "name": conv_data["name"],
                            "created_at": conv_data["created_at"],
                            "messages": messages
                        })
                        
                        if limit and len(matching_convs) >= limit:
                            break
            
            return matching_convs
            
        except Exception as e:
            logger.error(f"Failed to query conversations: {e}")
            raise

    def get_agent_stats(self, agent_name: str) -> Dict:
        """
        Get statistics for a specific agent
        
        Args:
            agent_name: Name of the agent
            
        Returns:
            Dictionary with agent statistics
        """
        try:
            stats = {
                "total_messages": 0,
                "conversations": 0,
                "first_message": None,
                "last_message": None,
                "avg_message_length": 0
            }
            
            with self._conv_lock:
                total_length = 0
                
                for conv_data in self._conversations.values():
                    agent_found = False
                    
                    for msg in conv_data["messages"]:
                        agent, content = self.retrieve_message(msg["data"])
                        if agent == agent_name:
                            timestamp = datetime.fromisoformat(msg["timestamp"])
                            
                            stats["total_messages"] += 1
                            total_length += len(content)
                            
                            if not stats["first_message"] or timestamp < stats["first_message"]:
                                stats["first_message"] = timestamp
                            if not stats["last_message"] or timestamp > stats["last_message"]:
                                stats["last_message"] = timestamp
                                
                            agent_found = True
                    
                    if agent_found:
                        stats["conversations"] += 1
                
                if stats["total_messages"] > 0:
                    stats["avg_message_length"] = total_length / stats["total_messages"]
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get agent stats: {e}")
            raise

    def get_conversation_summary(self, conversation_id: str) -> Dict:
        """
        Get summary statistics for a conversation
        
        Args:
            conversation_id: Target conversation ID
            
        Returns:
            Dictionary with conversation summary
        """
        try:
            with self._conv_lock:
                if conversation_id not in self._conversations:
                    raise ValueError(f"Invalid conversation ID: {conversation_id}")
                
                conv_data = self._conversations[conversation_id]
                
                summary = {
                    "id": conversation_id,
                    "name": conv_data["name"],
                    "created_at": conv_data["created_at"],
                    "message_count": len(conv_data["messages"]),
                    "agents": set(),
                    "last_message": None
                }
                
                for msg in conv_data["messages"]:
                    agent, _ = self.retrieve_message(msg["data"])
                    timestamp = datetime.fromisoformat(msg["timestamp"])
                    
                    summary["agents"].add(agent)
                    if not summary["last_message"] or timestamp > summary["last_message"]:
                        summary["last_message"] = timestamp
                
                summary["agents"] = list(summary["agents"])
                return summary
                
        except Exception as e:
            logger.error(f"Failed to get conversation summary: {e}")
            raise

    def export_conversation(
        self,
        conversation_id: str,
        format: str = "json",
        path: Optional[str] = None
    ) -> Union[str, Dict]:
        """
        Export conversation data in various formats
        
        Args:
            conversation_id: Target conversation ID
            format: Export format ("json" or "text")
            path: Optional file path to save export
            
        Returns:
            Exported conversation data
        """
        try:
            messages = self.get_messages(conversation_id)
            
            if format == "json":
                export_data = {
                    "conversation_id": conversation_id,
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "messages": [
                        {
                            "agent": agent,
                            "message": message,
                            "timestamp": timestamp.isoformat()
                        }
                        for agent, message, timestamp in messages
                    ]
                }
                
                if path:
                    with open(path, "w") as f:
                        json.dump(export_data, f, indent=2)
                
                return export_data
                
            elif format == "text":
                export_text = []
                for agent, message, timestamp in messages:
                    export_text.append(f"[{timestamp.isoformat()}] {agent}: {message}")
                
                export_data = "\n".join(export_text)
                
                if path:
                    with open(path, "w") as f:
                        f.write(export_data)
                
                return export_data
                
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            logger.error(f"Failed to export conversation: {e}")
            raise

    def backup_conversations(self, backup_dir: Optional[str] = None) -> str:
        """
        Create encrypted backup of all conversations
        
        Args:
            backup_dir: Optional backup directory path
            
        Returns:
            Path to backup directory
        """
        try:
            # Create backup directory
            backup_path = Path(backup_dir or self.storage_path / "backups")
            backup_path.mkdir(parents=True, exist_ok=True)
            
            # Create timestamped backup directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = backup_path / f"backup_{timestamp}"
            backup_dir.mkdir()
            
            with self._conv_lock:
                # Copy encrypted conversation files
                for conv_path in self.storage_path.glob("*.conv"):
                    backup_file = backup_dir / conv_path.name
                    backup_file.write_bytes(conv_path.read_bytes())
            
            logger.info(f"Created backup at {backup_dir}")
            return str(backup_dir)
            
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise
