// SPDX-License-Identifier: GPL-3.0-only
pragma solidity >=0.8.0;

import "./Upgradeable.sol";

/**
 * @title Proxy
 * @notice This contract is a proxy that delegates all calls to an implementation address. It allows for upgradability by changing the implementation address.
 * @dev Inherits from the `Upgradeable` contract, which provides the `replaceImplementation` function to update the implementation.
 */
contract Proxy is Upgradeable {

    /**
     * @notice Initializes the Proxy contract with the initial implementation address.
     * @param impl_ The address of the initial implementation contract.
     */
    constructor(address impl_) {
        replaceImplementation(impl_);
    }

    /**
     * @notice Fallback function that delegates all calls to the current implementation.
     * @dev Uses assembly to forward the calldata, delegate the call to the implementation, and return the result.
     *      - Copies the input calldata to memory.
     *      - Calls the implementation using `delegatecall`.
     *      - Copies the returned data and either reverts or returns based on the call result.
     */
    fallback() external virtual payable {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            calldatacopy(0, 0, calldatasize())  // Copy input calldata to memory starting at position 0
            let result := delegatecall(gas(), sload(slot), 0, calldatasize(), 0, 0)  // Perform delegatecall to the implementation address
            returndatacopy(0, 0, returndatasize())  // Copy the returned data to memory
            switch result  // Check the result of the delegatecall
            case 0 { revert(0, returndatasize()) }  // If the call failed, revert with the returned data
            default { return(0, returndatasize()) }  // If successful, return the returned data
        }
    }

    /**
     * @notice Receives Ether without data.
     * @dev This function is needed to handle direct ETH transfers to the contract.
     */
    receive() external virtual payable {
        (bool result,) = implementation().delegatecall("");
        assembly {
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
