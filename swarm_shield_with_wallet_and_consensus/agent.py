from wallet import Wallet
from shield import Shield
from message import EncryptedMessage
import logging
from typing import Callable, List


class DecryptAgent:
    def __init__(self, name: str, wallet_path: str):
        """
        Initialize a DecryptAgent with a name and a wallet.
        Args:
            name (str): The name of the agent.
            wallet_path (str): Path to the wallet file.
        """
        self.name = name
        self.wallet = self._initialize_wallet(wallet_path)
        self.shield = Shield(self.wallet)
        self.id = self.wallet.address

    def _initialize_wallet(self, wallet_path: str) -> Wallet:
        """
        Initialize the wallet.
        Args:
            wallet_path (str): Path to the wallet file.

        Returns:
            Wallet: Initialized wallet instance.
        """
        try:
            return Wallet(wallet_path)
        except Exception as e:
            raise ValueError(f"Failed to initialize wallet: {e}")

    def receive_and_decrypt(self, encrypted_data: EncryptedMessage) -> str:
        """
        Receive and decrypt a message from another agent.
        Args:
            encrypted_data (EncryptedMessage): Encrypted message data.

        Returns:
            str: The decrypted plaintext message.
        """
        try:
            sender_address = encrypted_data.sender
            if not self.shield.verify(sender_address, encrypted_data.ciphertext, encrypted_data.signature):
                raise ValueError(f"Invalid signature from sender: {sender_address}")
            return self.shield.decrypt(sender_address, encrypted_data)
        except Exception as e:
            raise RuntimeError(f"Receive and decrypt failed: {e}")


class PredictionAgent(DecryptAgent):
    def __init__(self, name: str, wallet_path: str, predict_callback: Callable[[], int]):
        """
        Initialize a PredictionAgent with a name, a wallet, and a prediction callback.
        Args:
            name (str): The name of the agent.
            wallet_path (str): Path to the wallet file.
            predict_callback (Callable[[], int]): A function to generate predictions.
        """
        super().__init__(name, wallet_path)
        if not callable(predict_callback):
            raise TypeError("predict_callback must be a callable function.")
        self.predictor = predict_callback

    def predict(self) -> int:
        """
        Execute the prediction callback and return the result.
        Returns:
            int: The prediction result.
        """
        try:
            return self.predictor()
        except Exception as e:
            raise RuntimeError(f"Prediction failed: {e}")

    def predict_and_encrypt(self, recipient_address: str) -> EncryptedMessage:
        """
        Generate a prediction and encrypt it for another agent.
        Args:
            recipient_address (str): The recipient's Ethereum address.

        Returns:
            EncryptedMessage: An encrypted message containing the prediction.
        """
        try:
            prediction = str(self.predict())
            encrypted_data = self.shield.encrypt(prediction, recipient_address)
            return encrypted_data
        except Exception as e:
            raise RuntimeError(f"Prediction and encryption failed: {e}")


class ConsensusAgent(DecryptAgent):
    def consensus(self, encrypted_datas: List[EncryptedMessage]) -> int:
        """
        Perform consensus based on decrypted votes.
        Args:
            encrypted_datas (List[EncryptedMessage]): List of encrypted message data.

        Returns:
            int: The consensus result (average of votes).
        """
        try:
            votes = []
            for encrypted_data in encrypted_datas:
                response = self.receive_and_decrypt(encrypted_data)
                try:
                    vote = int(response)
                    if vote > 0:
                        votes.append(vote)
                except ValueError:
                    logging.warning(f"Ignoring invalid vote: {response}")
            if not votes:
                raise ValueError("No valid votes received.")
            logging.debug(f"Decrypted votes: {votes}")
            consensus_result = sum(votes) // len(votes)
            logging.info(f"Consensus result: {consensus_result}")
            return consensus_result
        except Exception as e:
            raise RuntimeError(f"Consensus failed: {e}")


if __name__ == "__main__":
    # Set up logging configuration
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Example prediction function
    def my_prediction_function() -> int:
        return 10000

    try:
        # Initialize PredictionAgent
        logging.info("please predict BTC price:")
        agent = PredictionAgent("Agent1", "./agent1_wallet.json", my_prediction_function)
        prediction = agent.predict()
        logging.info(f"{agent.name} predicted: {prediction}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
