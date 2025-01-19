from agent import PredictionAgent, DecryptAgent
from typing import Callable
import logging

class DialogSwarm:
    def __init__(self, prediction_function: Callable[[], int] = None):
        """
        Initialize the DialogSwarm with a prediction agent and a decryption agent.
        Args:
            prediction_function (Callable[[], int], optional): The prediction function for the PredictionAgent.
        """
        try:
            self.predict_agent = PredictionAgent(
                name="agent1_voter",
                wallet_path="./data/agent1_wallet.json",
                predict_callback=prediction_function or self.default_prediction_function,
            )
            self.decrypt_agent = DecryptAgent(name="agent4_decrypt", wallet_path="./data/agent4_wallet.json")
        except Exception as e:
            logging.error(f"Failed to initialize DialogSwarm agents: {e}")
            raise

    @staticmethod
    def default_prediction_function() -> int:
        """Default prediction function."""
        return 10000

    def run(self, prompt: str = "please predict BTC price") -> str:
        """
        Run the dialog swarm to predict and decrypt a response.
        Args:
            prompt (str): The prompt for the prediction agent.

        Returns:
            str: The decrypted prediction response.
        """
        try:
            # Predict
            logging.info(f"Running prompt: {prompt}")
            encrypted_prediction = self.predict_agent.predict_and_encrypt(self.decrypt_agent.wallet.address)
            logging.debug(
                f"Encrypted Prediction by {self.predict_agent.name} "
                f"(Wallet: {self.predict_agent.wallet.address}): {encrypted_prediction}"
            )

            # Decrypt
            prediction = self.decrypt_agent.receive_and_decrypt(encrypted_prediction)
            logging.debug(
                f"Decrypted prediction by {self.decrypt_agent.name} "
                f"(Wallet: {self.decrypt_agent.wallet.address}): {prediction}"
            )

            return prediction
        except Exception as e:
            logging.error(f"DialogSwarm encountered an error: {e}")
            raise


# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

    try:
        # Example custom prediction function
        def btc_price_prediction() -> int:
            return 10000  # Example prediction logic

        dialog_swarm = DialogSwarm(prediction_function=btc_price_prediction)
        prompt = "please predict BTC price"
        logging.info(f"Prompt: {prompt}")
        response = dialog_swarm.run(prompt)
        logging.info(f"Response: {response}")
    except Exception as e:
        logging.error(f"An error occurred while running DialogSwarm: {e}")