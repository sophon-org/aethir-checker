// SPDX-License-Identifier: GPL-3.0-only
pragma solidity >=0.8.0;

import "./Upgradeable2Step.sol";

/**
 * @title Proxy2Step
 * @notice This contract serves as a proxy that delegates all calls to an implementation address, supporting a two-step upgradeable pattern.
 * @dev Inherits from `Upgradeable2Step` and allows implementation updates through a two-step process.
 */
contract Proxy2Step is Upgradeable2Step {

    /**
     * @notice Initializes the Proxy2Step contract with the initial implementation address.
     * @param impl_ The address of the initial implementation contract.
     */
    constructor(address impl_) {
        require(impl_ != address(0), "impl_ is zero address");
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, impl_)
        }
    }

    /**
     * @notice Fallback function that delegates all calls to the current implementation.
     * @dev Forwards all calldata to the implementation address and returns the result.
     * @dev Uses `delegatecall` to execute functions in the context of the implementation.
     */
    fallback() external virtual payable {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), sload(slot), 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /**
     * @notice Receives Ether sent to the contract.
     * @dev This function is used to handle direct ETH transfers without data.
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
