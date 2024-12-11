// SPDX-License-Identifier: GPL-3.0-only
pragma solidity >=0.8.0;

import "@openzeppelin/contracts/access/Ownable2Step.sol";

/**
 * @title Upgradeable2Step
 * @notice This contract implements a two-step process for upgrading the implementation address. It provides security by allowing the owner to propose a new implementation and the implementation to accept itself.
 * @dev Inherits from `Ownable2Step`, allowing the contract owner to initiate the upgrade process, which must then be accepted by the proposed implementation.
 */
contract Upgradeable2Step is Ownable2Step {

    /// @notice The slot containing the address of the pending implementation contract.
    bytes32 public constant PENDING_IMPLEMENTATION_SLOT = keccak256("PENDING_IMPLEMENTATION_SLOT");

    /// @notice The slot containing the address of the current implementation contract.
    bytes32 public constant IMPLEMENTATION_SLOT = keccak256("IMPLEMENTATION_SLOT");

    /**
     * @dev Emitted when a new implementation is proposed.
     * @param previousImplementation The address of the previous implementation.
     * @param newImplementation The address of the new implementation proposed.
     */
    event ReplaceImplementationStarted(address indexed previousImplementation, address indexed newImplementation);

    /**
     * @dev Emitted when a new implementation is accepted and becomes active.
     * @param previousImplementation The address of the previous implementation.
     * @param newImplementation The address of the new active implementation.
     */
    event ReplaceImplementation(address indexed previousImplementation, address indexed newImplementation);

    /**
     * @dev Thrown when an unauthorized account attempts to execute a restricted function.
     */
    error Unauthorized();
      
    /**
     * @notice Initializes the contract and sets the deployer as the initial owner.
     * @dev Passes the deployer address to the `Ownable2Step` constructor.
     */
    constructor() Ownable(msg.sender) {}

    /**
     * @notice Starts the implementation replacement process by setting a new pending implementation address.
     * @dev Can only be called by the owner. Emits the `ReplaceImplementationStarted` event.
     * @param impl_ The address of the new implementation contract to be set as pending.
     */
    function replaceImplementation(address impl_) public onlyOwner {
        bytes32 slot_pending = PENDING_IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot_pending, impl_)
        }
        emit ReplaceImplementationStarted(implementation(), impl_);
    }

    /**
     * @notice Completes the implementation replacement process by accepting the pending implementation.
     * @dev Can only be called by the pending implementation itself. Emits the `ReplaceImplementation` event and updates the `implementation` state.
     *      Deletes the `pendingImplementation` address upon successful acceptance.
     */
    function acceptImplementation() public {
        if (msg.sender != pendingImplementation()) {
            revert OwnableUnauthorizedAccount(msg.sender);
        }
        emit ReplaceImplementation(implementation(), msg.sender);

        bytes32 slot_pending = PENDING_IMPLEMENTATION_SLOT;
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot_pending, 0)
            sstore(slot, caller())
        }
    }

    /**
     * @notice Allows a new implementation to become the active implementation in a proxy contract.
     * @dev Can only be called by the owner of the specified proxy contract. Calls `acceptImplementation` on the proxy contract.
     * @param proxy The proxy contract where the new implementation should be accepted.
     */
    function becomeImplementation(Upgradeable2Step proxy) public {
        if (msg.sender != proxy.owner()) {
            revert Unauthorized();
        }
        proxy.acceptImplementation();
    }

    /**
     * @notice Returns the pending implementation address
     * @return The pending implementation address
     */
    function pendingImplementation() public view returns (address) {
        address pendingImplementation_;
        bytes32 slot_pending = PENDING_IMPLEMENTATION_SLOT;
        assembly {
            pendingImplementation_ := sload(slot_pending)
        }
        return pendingImplementation_;
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
