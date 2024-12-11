// SPDX-License-Identifier: GPL-3.0-only
pragma solidity >=0.8.0;

import "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";

/**
 * @title UpgradeableAccessControl
 * @notice This contract extends AccessControlDefaultAdminRules to provide role-based access control with an upgradeable implementation.
 * @dev Allows the default admin to replace the implementation address with a new one and optionally initialize it. The admin role changes are subject to a delay defined in the constructor.
 */
contract UpgradeableAccessControl is AccessControlDefaultAdminRules {

    /// @notice The slot containing the address of the current implementation contract.
    bytes32 public constant IMPLEMENTATION_SLOT = keccak256("IMPLEMENTATION_SLOT");

    /**
     * @notice Constructs the UpgradeableAccessControl contract.
     * @dev Initializes the AccessControlDefaultAdminRules with a delay of 3 days and sets the deployer as the initial default admin.
     */
    constructor() AccessControlDefaultAdminRules(3 days, msg.sender) {}

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
     * @notice Checks if the contract implements an interface.
     * @dev Overrides supportsInterface from AccessControlDefaultAdminRules.
     * @param interfaceId The interface identifier, as specified in ERC-165.
     * @return True if the contract implements `interfaceId`, false otherwise.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlDefaultAdminRules) returns (bool) {
        return super.supportsInterface(interfaceId);
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
