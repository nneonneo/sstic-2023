from secret import FLASK_SECRET_KEY, OWNER_PRIVKEY


MUSIG2_PUBKEY = (0xd0d3f2dee4d2b1cc8ba192e3661d634a6cd96588e8dd69f1ae68ff30e29f0fbc , 0x2515e48b55903d4ca2dfdea3c2fb0d830f26df1c917807a30d15a8842ddcaadf)

SESSION_DURATION = 5 # In minutes
BUY_WINDOW_DURATION = 15 # In minutes
ADMIN_TBS_STRING = "We hereby authorize an admin session of {duration} minutes starting from {now} (nonce: {nonce})."




# Smart contract

from starknet_py.net import KeyPair
from starknet_py.net.account.account import Account
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net.gateway_client import GatewayClient

OWNER_ADDRESS = 0x4ece2bf9ab3bdb76e689eea5662dc5c07964dc5f00f745972f264df991d8b4d
OWNER_PUBKEY = "0x77e5b939a4fadd64f44d6b30884098078c08c0e99b37cf4e5986e5d41ba062b"



RPC_REMOTE_IP = "blockchain.quatre-qu.art"
RPC_URL = f"https://{RPC_REMOTE_IP}"
CLIENT = GatewayClient(RPC_URL)

## If we need to interact without binding to a specific account
#from starknet_py.net.full_node_client import FullNodeClient
#FULL_NODE_CLIENT = FullNodeClient(node_url=URL + "/rpc", net="testnet")

def get_owner_account():
    keypair = KeyPair.from_private_key(OWNER_PRIVKEY)

    account = Account(
            client=CLIENT,
            address=OWNER_ADDRESS,
            key_pair=keypair,
            chain=StarknetChainId.TESTNET,
            )

    return account
