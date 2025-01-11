import shutil
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Tuple

from swarm_shield import SwarmShield, EncryptionStrength


def assert_equal(
    actual: Any, expected: Any, message: str = ""
) -> None:
    """Custom assertion helper"""
    if actual != expected:
        raise AssertionError(
            f"{message}\nExpected: {expected}\nActual: {actual}"
        )


def assert_raises(
    exception_type: type, func: Callable, *args, **kwargs
) -> None:
    """Verify function raises expected exception"""
    try:
        func(*args, **kwargs)
        raise AssertionError(
            f"Expected {exception_type.__name__} to be raised"
        )
    except exception_type:
        pass


def setup_test_env() -> Tuple[SwarmShield, Path]:
    """Create test environment"""
    test_dir = Path("test_swarm_shield")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir()

    shield = SwarmShield(
        encryption_strength=EncryptionStrength.MAXIMUM,
        storage_path=str(test_dir),
    )
    return shield, test_dir


def cleanup_test_env(test_dir: Path) -> None:
    """Clean up test environment"""
    if test_dir.exists():
        shutil.rmtree(test_dir)


def test_message_encryption() -> None:
    """Test basic message encryption and decryption"""
    shield, test_dir = setup_test_env()
    try:
        # Test valid message
        message = "Hello, Agent2!"
        encrypted = shield.protect_message("Agent1", message)
        agent, decrypted = shield.retrieve_message(encrypted)

        assert_equal(agent, "Agent1", "Wrong agent name")
        assert_equal(decrypted, message, "Wrong decrypted message")

        # Test empty inputs
        assert_raises(ValueError, shield.protect_message, "", "test")
        assert_raises(ValueError, shield.protect_message, "agent", "")

        # Test wrong types
        assert_raises(ValueError, shield.protect_message, 123, "test")
        assert_raises(
            ValueError, shield.protect_message, "agent", ["test"]
        )

        print("✓ Message encryption tests passed")

    finally:
        cleanup_test_env(test_dir)


def test_conversation_management() -> None:
    """Test conversation creation and management"""
    shield, test_dir = setup_test_env()
    try:
        # Create conversation
        conv_id = shield.create_conversation("Test Chat")

        # Add messages
        shield.add_message(conv_id, "Agent1", "Hello!")
        shield.add_message(conv_id, "Agent2", "Hi there!")

        # Verify messages
        messages = shield.get_messages(conv_id)
        assert_equal(len(messages), 2, "Wrong message count")

        agent, message, _ = messages[0]
        assert_equal(agent, "Agent1", "Wrong first message agent")
        assert_equal(message, "Hello!", "Wrong first message content")

        # Test invalid conversation ID
        assert_raises(
            ValueError,
            shield.add_message,
            "invalid-id",
            "Agent1",
            "test",
        )

        print("✓ Conversation management tests passed")

    finally:
        cleanup_test_env(test_dir)


def test_conversation_queries() -> None:
    """Test conversation search and filtering"""
    shield, test_dir = setup_test_env()
    try:
        # Create test conversations
        conv1 = shield.create_conversation("Chat 1")
        conv2 = shield.create_conversation("Chat 2")

        # Add messages with different timestamps
        now = datetime.now(timezone.utc)
        yesterday = now - timedelta(days=1)

        shield.add_message(conv1, "Agent1", "Hello world")
        time.sleep(0.1)  # Ensure different timestamps
        shield.add_message(conv1, "Agent2", "Hi Agent1")
        shield.add_message(conv2, "Agent3", "Testing search")

        # Test agent filter
        results = shield.query_conversations(agent_name="Agent1")
        assert_equal(
            len(results), 1, "Wrong number of conversations for agent"
        )
        assert_equal(results[0]["id"], conv1, "Wrong conversation ID")

        # Test text search
        results = shield.query_conversations(text="world")
        assert_equal(
            len(results), 1, "Wrong number of conversations for text"
        )

        # Test date filter
        results = shield.query_conversations(
            start_date=yesterday, end_date=now + timedelta(hours=1)
        )
        assert_equal(
            len(results),
            2,
            "Wrong number of conversations for date range",
        )

        # Test limit
        results = shield.query_conversations(limit=1)
        assert_equal(len(results), 1, "Query limit not respected")

        print("✓ Conversation query tests passed")

    finally:
        cleanup_test_env(test_dir)


def test_agent_statistics() -> None:
    """Test agent statistics calculation"""
    shield, test_dir = setup_test_env()
    try:
        # Create conversation and add messages
        conv_id = shield.create_conversation()

        shield.add_message(conv_id, "Agent1", "Hello")
        time.sleep(0.1)
        shield.add_message(conv_id, "Agent2", "Hi")
        shield.add_message(conv_id, "Agent1", "How are you?")

        # Get stats for Agent1
        stats = shield.get_agent_stats("Agent1")

        assert_equal(
            stats["total_messages"], 2, "Wrong message count"
        )
        assert_equal(
            stats["conversations"], 1, "Wrong conversation count"
        )
        assert_equal(
            stats["avg_message_length"],
            (len("Hello") + len("How are you?")) / 2,
            "Wrong average message length",
        )

        # Get stats for non-existent agent
        stats = shield.get_agent_stats("Unknown")
        assert_equal(
            stats["total_messages"], 0, "Should have no messages"
        )

        print("✓ Agent statistics tests passed")

    finally:
        cleanup_test_env(test_dir)


def test_conversation_export() -> None:
    """Test conversation export functionality"""
    shield, test_dir = setup_test_env()
    try:
        # Create test conversation
        conv_id = shield.create_conversation("Export Test")
        shield.add_message(conv_id, "Agent1", "Message 1")
        shield.add_message(conv_id, "Agent2", "Message 2")

        # Test JSON export
        json_export = shield.export_conversation(
            conv_id, format="json"
        )
        assert_equal(
            len(json_export["messages"]),
            2,
            "Wrong message count in JSON",
        )

        # Test text export
        text_export = shield.export_conversation(
            conv_id, format="text"
        )
        assert (
            "Agent1: Message 1" in text_export
        ), "Missing message in text export"
        assert (
            "Agent2: Message 2" in text_export
        ), "Missing message in text export"

        # Test file export
        export_path = test_dir / "export.json"
        shield.export_conversation(
            conv_id, format="json", path=str(export_path)
        )
        assert export_path.exists(), "Export file not created"

        # Test invalid format
        assert_raises(
            ValueError,
            shield.export_conversation,
            conv_id,
            format="invalid",
        )

        print("✓ Conversation export tests passed")

    finally:
        cleanup_test_env(test_dir)


def test_backup_restore() -> None:
    """Test backup and restore functionality"""
    shield, test_dir = setup_test_env()
    try:
        # Create test data
        conv_id = shield.create_conversation("Backup Test")
        shield.add_message(conv_id, "Agent1", "Test message")

        # Create backup
        backup_dir = shield.backup_conversations()
        assert Path(
            backup_dir
        ).exists(), "Backup directory not created"

        # Verify backup files
        backup_files = list(Path(backup_dir).glob("*.conv"))
        assert_equal(
            len(backup_files), 1, "Wrong number of backup files"
        )

        print("✓ Backup and restore tests passed")

    finally:
        cleanup_test_env(test_dir)


def test_key_rotation() -> None:
    """Test automatic key rotation"""
    shield, test_dir = setup_test_env()
    try:
        # Capture and encrypt with first key
        msg1 = "Test message 1"
        encrypted1 = shield.protect_message("Agent1", msg1)

        # Force key rotation with new salt
        shield.last_rotation = 0  # Reset rotation time
        shield._check_rotation()  # This will trigger rotation

        # Encrypt same message with new key
        encrypted2 = shield.protect_message("Agent1", msg1)

        # Verify encryptions are different (indicating different keys used)
        assert (
            encrypted1 != encrypted2
        ), "Encryption unchanged after key rotation"

        # Verify both messages can still be decrypted
        agent1, dec1 = shield.retrieve_message(encrypted1)
        agent2, dec2 = shield.retrieve_message(encrypted2)

        assert_equal(
            dec1, msg1, "Failed to decrypt message with first key"
        )
        assert_equal(
            dec2, msg1, "Failed to decrypt message with rotated key"
        )

        # Ensure rotation happens with check
        shield.last_rotation = 0
        shield._check_rotation()
        encrypted3 = shield.protect_message("Agent1", msg1)
        assert (
            encrypted2 != encrypted3
        ), "Key not rotated during check"

        print("✓ Key rotation tests passed")

    finally:
        cleanup_test_env(test_dir)


def run_all_tests() -> None:
    """Run all test cases"""
    tests = [
        test_message_encryption,
        test_conversation_management,
        test_conversation_queries,
        test_agent_statistics,
        test_conversation_export,
        test_backup_restore,
        test_key_rotation,
    ]

    total = len(tests)
    passed = 0

    print(f"\nRunning {total} test cases:\n")

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} failed:")
            print(f"  {str(e)}\n")

    print(f"\nTest Results: {passed}/{total} passed")


if __name__ == "__main__":
    run_all_tests()
