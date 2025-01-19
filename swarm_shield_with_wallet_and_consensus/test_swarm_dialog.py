import unittest
from unittest.mock import MagicMock
from swarm_dialog import DialogSwarm


class TestDialogSwarm(unittest.TestCase):
    def setUp(self):
        """Set up mock agents and DialogSwarm for testing."""
        self.dialog_swarm = DialogSwarm(prediction_function=lambda: 42)

    def test_run_success(self):
        """Test DialogSwarm run method with successful prediction and decryption."""
        # Run DialogSwarm
        prompt = "please predict BTC price"
        result = self.dialog_swarm.run(prompt)

        # Verify results and interactions
        self.assertEqual(result, "42")

    def test_default_prediction_function(self):
        """Test the default prediction function."""
        swarm = DialogSwarm()
        self.assertEqual(swarm.run(), str(10000))


if __name__ == "__main__":
    unittest.main()
