import unittest
from unittest.mock import MagicMock
from swarm_consensus import ConsensusSwarm


class TestConsensusSwarm(unittest.TestCase):
    def setUp(self):
        """Set up mock agents and ConsensusSwarm for testing."""
        self.prediction_functions = [lambda: 11000, lambda: 10000, lambda: 9000]
        self.wallet_paths = [
            "./data/agent1_wallet.json",
            "./data/agent2_wallet.json",
            "./data/agent3_wallet.json",
        ]
        self.consensus_wallet_path = "./data/agent5_wallet.json"
        self.swarm = ConsensusSwarm(self.prediction_functions, self.wallet_paths, self.consensus_wallet_path)

    def test_run_success(self):
        """Test the successful execution of the ConsensusSwarm."""
        result = self.swarm.run("please predict BTC price with consensus")
        self.assertEqual(result, 10000)

    def test_mismatched_inputs(self):
        """Test mismatched prediction functions and wallet paths."""
        with self.assertRaises(ValueError):
            ConsensusSwarm([lambda: 11000], ["./data/agent1_wallet.json", "./data/agent2_wallet.json"], self.consensus_wallet_path)


if __name__ == "__main__":
    unittest.main()
