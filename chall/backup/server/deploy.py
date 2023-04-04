from starknet_py.contract import Contract

import sys
from time import sleep
import os
from pathlib import Path
import requests

import config

def wait_for_RPC():
    while True:
        try:
            ans = requests.get(config.RPC_URL + '/is_alive').text.lower()
            if "alive" not in ans:
                raise Exception
            break
        except:
            print("Waiting for RPC...", file=sys.stderr)
            sleep(5)

def declare(contract_path):
    owner = config.get_owner_account()

    declare_result = Contract.declare_sync(
            account=owner,
            compiled_contract=contract_path.read_text(),
            max_fee=int(1e16),
            )
    declare_result.wait_for_acceptance_sync()

    return declare_result

def deploy(declare_result):
    nonce = int.from_bytes(os.urandom(16), "big")
    deploy_result = declare_result.deploy_sync(
            unique=False,
            salt=0x1337,
            constructor_args=[config.OWNER_ADDRESS, nonce],
            max_fee=int(1e16),
            )
    deploy_result.wait_for_acceptance_sync()

    contract = deploy_result.deployed_contract
    with open("/tmp/contract_address", "w") as f:
        f.write(f"{hex(contract.address)}")

    print(f"{hex(contract.address)}")

    return contract

def run():
    wait_for_RPC()
    declare_result = declare(Path("/app/internal/challenge.json"))
    contract = deploy(declare_result)

    print("Deployement done!", file=sys.stderr)

if __name__ == "__main__":
    print("Starting deployement...", file=sys.stderr)
    run()
