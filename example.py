# Usage Example
from loguru import logger
from swarm_shield.main import EncryptionStrength, SwarmShield


if __name__ == "__main__":
    try:
        # Initialize SwarmShield
        shield = SwarmShield(
            encryption_strength=EncryptionStrength.MAXIMUM
        )

        # Create a conversation
        conversation_id = shield.create_conversation("Test Chat")

        # protect message
        shield.protect_message(
            "agent_name", "We generated 3000000k this month "
        )

        # Add messages
        shield.add_message(
            conversation_id, "Agent1", "Hello, Agent2!"
        )
        shield.add_message(
            conversation_id, "Agent2", "Hi Agent1, how are you?"
        )

        # Get message history
        print("\nConversation History:")
        for agent, message, timestamp in shield.get_messages(
            conversation_id
        ):
            print(f"{timestamp} - {agent}: {message}")

        # Get conversation overview
        summary = shield.get_conversation_summary(conversation_id)
        print(f"Messages: {summary['message_count']}")
        print(f"Participants: {summary['agents']}")

        # Export conversation
        shield.export_conversation(
            conversation_id, format="json", path="chat.json"
        )

        # Backup all conversations
        backup_path = shield.backup_conversations()

        # Get agent activity stats
        stats = shield.get_agent_stats("Agent1")
        print(f"Total messages: {stats['total_messages']}")
        print(f"Active in {stats['conversations']} conversations")

        # Delete conversation
        shield.delete_conversation(conversation_id)

    except Exception as e:
        logger.error(f"Example failed: {e}")
        raise
