import os

from starknet_py.contract import Contract

import config
import deploy

def get_contract() -> Contract:
    if not os.path.isfile("/tmp/contract_address"):
        deploy.run()

    owner = config.get_owner_account()
    while True:
        with open("/tmp/contract_address", "r") as f:
            contract_address = int(f.read(), 16)
        try:
            contract = Contract.from_address_sync(provider=owner, address=contract_address)
            break
        except:
            # Something's wrong, redeploy and try again
            deploy.run()
            continue

    return contract

def is_valid(ans: int, code: list[int], a: int, b: int) -> bool:
    contract = get_contract()

    try:
        invocation = contract.functions["validate"].invoke_sync(ans, code, a, b, max_fee=int(1e16))
        invocation.wait_for_acceptance_sync()

        return True
    except Exception as e:
        print(e)
        return False

