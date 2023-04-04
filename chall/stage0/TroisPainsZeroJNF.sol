// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./ERC1155.sol";

contract TroisPainsZeroJNF is ERC1155 {
    /*//////////////////////////////////////////////////////////////
                          CONSTANTS/IMMUTABLES
    //////////////////////////////////////////////////////////////*/
    string constant BASE_URI =
        'data:application/json;base64,eyJuYW1lIjogIlRyb2lzIFBhaW5zIFplcm8iLAogICAgICAgICAgImRlc2NyaXB0aW9uIjogIkxvYnN0ZXJkb2cgcGFzdHJ5IGNoZWYuIiwKICAgICAgICAgICJpbWFnZSI6ICJodHRwczovL25mdC5xdWF0cmUtcXUuYXJ0L25mdC1saWJyYXJ5LnBocD9pZD0xMiIsCiAgICAgICAgICAiZXh0ZXJuYWxfdXJsIjogImh0dHBzOi8vbmZ0LnF1YXRyZS1xdS5hcnQvbmZ0LWxpYnJhcnkucGhwP2lkPTEyIn0K';
    bytes constant MINT_DATA = bytes("");
    uint256 public constant COLLECTION_ID = 1;
    address payable public immutable OWNER;

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/
    error NotOwner();

    constructor(address payable _owner) {
        OWNER = _owner;
    }

    modifier onlyOwner() {
        if (msg.sender != OWNER) revert NotOwner();
        _;
    }

    /// @notice Get the URI of a token. The param is unused as we only have one collection.
    /** @dev The EIP-1155 suppose that the URI is the same for all tokens of a collection.
     ** As we only plan to use one collection for our challenge, I decided to override the param for gas efficiency. */
    function uri(uint256) public pure override returns (string memory) {
        return BASE_URI;
    }

    /** @notice Do a transfer of tokens from the owner reserve. Only the owner can do a transfer.
        The first and third parameter (from and ID) are enforced in the function
        as only the owner can transfer token AND we only plan to use one collection in our challenge */
    /// @param to address to transfer to
    /// @param amount amount of tokens to transfer. Must be 1 for our challenge
    /// @param data data to send to the receiver. Must be empty for our challenge
    function safeTransferFrom(
        address,
        address to,
        uint256,
        uint256 amount,
        bytes calldata data
    ) public override onlyOwner {
        super.safeTransferFrom(OWNER, to, COLLECTION_ID, amount, data);
    }

    /// @notice Do a batch transfer of token from the owner reserves. Only the owner can do a batch transfer.
    /// @param tos addresses to transfer to
    /// @param data data to send to the receiver. Must be empty for our challenge
    /// @dev Keep in mind this function uses a loop, which means it is susceptible to trigger an out-of-gas error.
    function batchSafeTransferFrom(
        address[] calldata tos,
        bytes calldata data
    ) external onlyOwner {
        uint256 length = tos.length;
        uint256 i;

        for (i; i < length; ) {
            super.safeTransferFrom(OWNER, tos[i], COLLECTION_ID, 1, data);

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Disable the safeBatchTransferFrom function as we only have one collection for our challenge
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) public override onlyOwner {
        // useless as we will only use one collection for our challenge
    }

    /** @notice Mint new tokens to the owner. Only the owner can mint new tokens.
        As we only have one collection for our challenge, the id param is enforced. */
    function mint(uint256 amount) external onlyOwner {
        _mint(OWNER, COLLECTION_ID, amount, MINT_DATA);
    }

    /// @notice Destruct the smart-contract
    /// @dev The function uses the deprecated selfdestruct() opcode. Funds are send to the owner.
    function destruct() external onlyOwner {
        // destruct the smart-contract and send the potential
        // ethers holded by the smart-contract to the owner
        selfdestruct(OWNER);
    }
}
