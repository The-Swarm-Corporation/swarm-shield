from agent import PredictionAgent, ConsensusAgent
from typing import Callable, List
import logging

class ConsensusSwarm:
    def __init__(self, prediction_functions: List[Callable[[], int]], wallet_paths: List[str], consensus_wallet_path: str):
        """
        Initialize the ConsensusSwarm with multiple prediction agents and a consensus agent.
        Args:
            prediction_functions (List[Callable[[], int]]): List of prediction functions for each agent.
            wallet_paths (List[str]): List of wallet paths for prediction agents.
            consensus_wallet_path (str): Wallet path for the consensus agent.
        """
        if len(prediction_functions) != len(wallet_paths):
            raise ValueError("Number of prediction functions and wallet paths must be equal.")
        
        self.predict_agents = [
            PredictionAgent(f"agent{i+1}_voter", wallet_path, predict_fn)
            for i, (wallet_path, predict_fn) in enumerate(zip(wallet_paths, prediction_functions))
        ]
        self.consensus_agent = ConsensusAgent("agent_consensus", consensus_wallet_path)

    def run(self, prompt: str = "please predict BTC price with consensus") -> int:
        """
        Execute the consensus swarm process.
        Args:
            prompt (str): Prompt to pass to the prediction agents.

        Returns:
            int: The consensused prediction result.
        """
        try:
            # Collect encrypted predictions
            encrypted_predictions = []
            logging.info(f"Running prompt: {prompt}")
            for agent in self.predict_agents:
                encrypted_prediction = agent.predict_and_encrypt(self.consensus_agent.wallet.address)
                logging.debug(f"Encrypted Prediction by {agent.name} ({agent.wallet.address}): {encrypted_prediction}")
                encrypted_predictions.append(encrypted_prediction)

            # Perform consensus
            consensused_prediction = self.consensus_agent.consensus(encrypted_predictions)
            logging.info(f"Consensused prediction by {self.consensus_agent.name} ({self.consensus_agent.wallet.address}): {consensused_prediction}")
            return consensused_prediction
        except Exception as e:
            logging.error(f"ConsensusSwarm encountered an error: {e}")
            raise


# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

    # Define prediction functions
    prediction_functions = [
        lambda: 11000,
        lambda: 10000,
        lambda: 9000,
    ]

    # Define wallet paths for prediction agents
    wallet_paths = [
        "./data/agent1_wallet.json",
        "./data/agent2_wallet.json",
        "./data/agent3_wallet.json",
    ]

    # Define wallet path for the consensus agent
    consensus_wallet_path = "./data/agent5_wallet.json"

    try:
        # Initialize ConsensusSwarm
        consensus_swarm = ConsensusSwarm(prediction_functions, wallet_paths, consensus_wallet_path)
        prompt = "please predict BTC price with consensus"
        logging.info(f"Prompt: {prompt}")
        response = consensus_swarm.run(prompt)
        logging.info(f"Response: {response}")
    except Exception as e:
        logging.error(f"An error occurred while running ConsensusSwarm: {e}")