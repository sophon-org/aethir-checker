// SPDX-License-Identifier: GPL-3.0-only
pragma solidity >=0.8.0;

import "./UpgradeableAccessControl.sol";

/**
 * @title ProxyAccessControl
 * @notice This contract is a proxy with role-based access control, allowing an admin to upgrade the implementation contract.
 * @dev Inherits from `UpgradeableAccessControl` for role-based permissions and supports upgradeability through `replaceImplementation`.
 */
contract ProxyAccessControl is UpgradeableAccessControl {

    /**
     * @notice Initializes the ProxyAccessControl contract with the initial implementation address and optional initialization data.
     * @dev Calls `replaceImplementation` to set up the implementation and execute any provided initialization logic.
     * @param impl_ The address of the initial implementation contract.
     * @param initData_ Optional initialization data to be passed to the new implementation using delegatecall.
     */
    constructor(address impl_, bytes memory initData_) {
        replaceImplementation(impl_, initData_);
    }

    /**
     * @notice Fallback function that delegates all calls to the current implementation.
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
     * @dev Used to handle direct ETH transfers without data.
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
