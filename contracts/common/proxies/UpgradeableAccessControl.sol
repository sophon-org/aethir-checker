// SPDX-License-Identifier: GPL-3.0-only
pragma solidity >=0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title UpgradeableAccessControl
 * @dev Allows the default admin to replace the implementation address with a new one and optionally initialize it.
 */
contract UpgradeableAccessControl is AccessControl {

    /// @notice The slot containing the address of the current implementation contract.
    bytes32 public constant IMPLEMENTATION_SLOT = keccak256("IMPLEMENTATION_SLOT");

    /**
     * @notice Constructs the UpgradeableAccessControl contract.
     */
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Replaces the current implementation with a new one and optionally initializes it.
     * @dev Can only be called by an account with the DEFAULT_ADMIN_ROLE. If `initData_` is provided, a delegatecall is made to the new implementation with that data.
     * @param impl_ The address of the new implementation contract.
     * @param initData_ Optional initialization data to delegatecall to the new implementation.
     */
    function replaceImplementation(address impl_, bytes memory initData_) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(impl_ != address(0), "impl_ is zero address");
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, impl_)
        }
        if (initData_.length != 0) {
            (bool success,) = impl_.delegatecall(initData_);
            require(success, "init failed");
        }
    }

    /**
     * @notice Returns the current implementation address
     * @return The current implementation address
     */
    function implementation() public view returns (address) {
        address implementation_;
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            implementation_ := sload(slot)
        }
        return implementation_;
    }
}
