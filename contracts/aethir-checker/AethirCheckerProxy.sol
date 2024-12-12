// SPDX-License-Identifier: GPL-3.0-only

pragma solidity 0.8.28;

import "../common/proxies/ProxyAccessControl.sol";

/**
 * @title AethirChecker
 * @dev This contract is a proxy for the AethirChecker implementation. It allows for upgradability by pointing to different implementation contracts over time. The contract uses access control inherited from ProxyAccessControl.
 */
contract AethirCheckerProxy is ProxyAccessControl {

    /**
     * @notice Constructor to initialize the proxy with the implementation address and initialization data
     * @param impl_ The address of the initial implementation contract
     * @param initData_ Optional data to initialize the proxy's state via a delegatecall to the implementation contract
     */
    constructor(address impl_, bytes memory initData_) ProxyAccessControl(impl_, initData_) {}
}
