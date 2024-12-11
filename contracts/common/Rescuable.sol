// SPDX-License-Identifier: GPL-3.0-only

pragma solidity >=0.8.0;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

abstract contract Rescuable {
    using SafeERC20 for IERC20;

    /**
     * @notice Override this function in inheriting contracts to set appropriate permissions
     */
    function _requireRescuerRole() internal view virtual;

    /**
     * @notice Allows the rescue of ERC20 tokens held by the contract
     * @param token The ERC20 token to be rescued
     */
    function rescue(IERC20 token) external {
        _requireRescuerRole();
        uint256 balance = token.balanceOf(address(this));
        token.safeTransfer(msg.sender, balance);
    }

    /**
     * @notice Allows the rescue of Ether held by the contract
     */
    function rescueEth() external{
        _requireRescuerRole();
        uint256 balance = address(this).balance;
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }
}
