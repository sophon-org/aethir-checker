// SPDX-License-Identifier: GPL-3.0-only
pragma solidity >=0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title Upgradeable
 * @notice This contract provides a base structure for upgradeable contracts, allowing the owner to update the implementation address.
 * @dev Inherits from OpenZeppelin's `Ownable` contract, restricting the `replaceImplementation` function to only the owner.
 */
contract Upgradeable is Ownable {
    
    /// @notice The slot containing the address of the current implementation contract.
    bytes32 public constant IMPLEMENTATION_SLOT = keccak256("IMPLEMENTATION_SLOT");

    /**
     * @notice Initializes the Upgradeable contract and sets the initial owner.
     * @dev Passes the deployer address to the `Ownable` constructor.
     */
    constructor() Ownable(msg.sender) {}

    /**
     * @notice Replaces the current implementation with a new address.
     * @dev Can only be called by the contract owner. Updates the `implementation` state variable.
     * @param impl_ The address of the new implementation contract.
     */
    function replaceImplementation(address impl_) public onlyOwner {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, impl_)
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
