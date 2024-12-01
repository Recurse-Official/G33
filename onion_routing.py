import os
import base64
from kyber_py.kyber import Kyber512
from dilithium_py.dilithium import Dilithium2
from typing import List, Tuple, Optional, Dict, Any


class OnionNode:
    def __init__(self, node_id: str):
        # Node identifier
        self.node_id = node_id

        # Kyber key for encryption/decryption
        self.pk_kyber, self.sk_kyber = Kyber512.keygen()

        # Dilithium key for signing
        self.pk_dilithium, self.sk_dilithium = Dilithium2.keygen()

    def decrypt_layer(self, challenge: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
        """
        Decrypt a layer of the onion message using Kyber decapsulation
        """
        try:
            # Decapsulate the challenge to get the shared secret
            decrypted_next_hop = Kyber512.decaps(self.sk_kyber, challenge)
            print(f"Node {self.node_id} - Decrypted Layer:")
            print(f"  Decrypted Next Hop: {base64.b64encode(decrypted_next_hop).decode()}")
            return decrypted_next_hop, challenge
        except Exception as e:
            print(f"Decryption error at node {self.node_id}: {e}")
            return None, None

    def sign_layer(self, layer_data: bytes) -> bytes:
        """
        Sign the layer data using Dilithium
        """
        signature = Dilithium2.sign(self.sk_dilithium, layer_data)
        print(f"Node {self.node_id} - Layer Signature:")
        print(f"  Signature: {base64.b64encode(signature).decode()}")
        return signature


class OnionRouter:
    def __init__(self, num_nodes: int = 3):
        """
        Initialize onion routing network with specified number of nodes
        """
        self.nodes = [OnionNode(f"Node-{i + 1}") for i in range(num_nodes)]

    def prepare_onion_message(self, message: str, recipient_public_key: bytes) -> Dict[str, Any]:
        """
        Prepare an onion-encrypted message to be routed through multiple nodes
        """
        # Reverse the nodes for proper onion layer construction
        routing_nodes = list(reversed(self.nodes))

        # Start with the recipient's public key
        current_pk = recipient_public_key

        # Layers of encryption and routing information
        layers = []
        final_challenges = []

        print("Sender Preparation Phase:")
        print("------------------------")

        # Prepare layers for each node
        for node in routing_nodes:
            # Generate encryption for next hop
            key, challenge = Kyber512.encaps(current_pk)

            # Update current public key for next iteration
            current_pk = node.pk_kyber

            # Store encryption challenges
            final_challenges.append(challenge)

            # Create a layer with routing information
            layer = {
                'next_hop_pk': current_pk,
                'encrypted_payload': key
            }
            layers.append(layer)

            print(f"Layer for {node.node_id}:")
            print(f"  Next Hop Public Key: {base64.b64encode(current_pk).decode()}")
            print(f"  Encrypted Payload: {base64.b64encode(key).decode()}")
            print(f"  Challenge: {base64.b64encode(challenge).decode()}")

        # Final layer contains the actual message
        final_layer = {
            'message': message.encode('utf-8'),
            'recipient_pk': recipient_public_key
        }
        layers.append(final_layer)

        print("\nFinal Layer:")
        print(f"  Message: {message}")
        print(f"  Recipient Public Key: {base64.b64encode(recipient_public_key).decode()}")

        return {
            'layers': layers,
            'challenges': final_challenges
        }

    def route_message(self, onion_message: Dict[str, Any]) -> Optional[str]:
        """
        Route the onion-encrypted message through nodes
        """
        print("\nRouting Phase:")
        print("-------------")

        layers = onion_message['layers'].copy()
        challenges = onion_message.get('challenges', [])

        # Simulate routing through nodes
        for node_index, node in enumerate(self.nodes):
            if not layers:
                break

            print(f"\nProcessing {node.node_id}:")

            # Get the current challenge
            current_challenge = challenges[node_index] if node_index < len(challenges) else None

            if current_challenge is None:
                print(f"No challenge for {node.node_id}")
                return None

            # Decrypt current layer
            decrypted_next_hop, _ = node.decrypt_layer(current_challenge)

            if decrypted_next_hop is None:
                print(f"Decryption failed at {node.node_id}")
                return None

            # Sign the layer
            node_signature = node.sign_layer(decrypted_next_hop)

            # Remove the current layer
            current_layer = layers.pop(0)

        # Reached final destination
        if layers and 'message' in layers[0]:
            received_message = layers[0]['message'].decode('utf-8')
            print("\nFinal Receiver:")
            print("---------------")
            print(f"Received Message: {received_message}")
            return received_message

        return None


def main():
    # Create router and nodes
    router = OnionRouter(num_nodes=3)

    # Simulate recipient
    recipient = OnionNode("Recipient")

    print("\nOnion Routing Demonstration")
    print("==========================")

    # Prepare onion-encrypted message
    message = "Secret communication via onion routing"
    onion_message = router.prepare_onion_message(
        message,
        recipient_public_key=recipient.pk_kyber
    )

    # Print keys for reference
    print("\nKey Information:")
    print("---------------")
    print("Router Nodes:")
    for node in router.nodes:
        print(f"{node.node_id}:")
        print(f"  Kyber Public Key: {base64.b64encode(node.pk_kyber).decode()}")
        print(f"  Kyber Private Key: {base64.b64encode(node.sk_kyber).decode()}")
        print(f"  Dilithium Public Key: {base64.b64encode(node.pk_dilithium).decode()}")
        print(f"  Dilithium Private Key: {base64.b64encode(node.sk_dilithium).decode()}")

    print("\nRecipient:")
    print(f"  Kyber Public Key: {base64.b64encode(recipient.pk_kyber).decode()}")
    print(f"  Kyber Private Key: {base64.b64encode(recipient.sk_kyber).decode()}")
    print(f"  Dilithium Public Key: {base64.b64encode(recipient.pk_dilithium).decode()}")
    print(f"  Dilithium Private Key: {base64.b64encode(recipient.sk_dilithium).decode()}")

    # Route the message
    received_message = router.route_message(onion_message)


if __name__ == "__main__":
    main()