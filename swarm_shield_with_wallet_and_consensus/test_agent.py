import unittest
from unittest.mock import MagicMock
from message import EncryptedMessage
from agent import PredictionAgent, ConsensusAgent


class TestAgents(unittest.TestCase):
    def setUp(self):
        """Set up mock instances and test data."""
        pass

    def test_prediction_agent(self):
        """Test PredictionAgent prediction and encryption."""
        agent = PredictionAgent("TestAgent", "./agent1_wallet.json", lambda: 42)
        encrypted = agent.predict_and_encrypt("0x9C5a850A35298A2fB2A430C68f8Eb4360f41A9f2")
        self.assertEqual(encrypted.sender, agent.wallet.address)

    def test_consensus_agent(self):
        """Test ConsensusAgent consensus calculation."""
        agent0 = ConsensusAgent("ConsensusAgent", "./agent2_wallet.json")
        
        agent1 = PredictionAgent("TestAgent", "./agent1_wallet.json", lambda: 42)
        encrypted1 = agent1.predict_and_encrypt(agent0.wallet.address)
        
        encrypted_messages = [encrypted1, encrypted1, encrypted1]
        result = agent0.consensus(encrypted_messages)
        self.assertEqual(result, 42)


if __name__ == "__main__":
    unittest.main()
