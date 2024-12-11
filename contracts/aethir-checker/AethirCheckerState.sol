// SPDX-License-Identifier: GPL-3.0-only

pragma solidity 0.8.28;

contract AethirCheckerState {

    mapping (address => string) public clientToId;
    mapping (string => address) public idToClient;

    struct Report {
        string jobId;           // jobId (string)
        string clientId;        // clientId (string)
        string licenseId;       // licenseId (string)
        int64 epoch;            // epoch (int64)
        int256 period;          // period  (int)
        int256 reportTime;      // reportTime (int)
        string containerId;     // containerId (string)
        uint8 jobType;          // jobType (uint8)
        bytes signatureData;    // client's signature
        bytes32 containerHash;  // hash calculated from container.continues (bool), container.loss (uint8),
                                // container.duration (int64) for Liveness OR container.qualified (bool) for Capacity
    }

    /// @notice Mapping to track nonces for each address, used to prevent replay attacks in signed messages
    mapping (address => uint256) public nonces;

    /// @notice Mapping to track counts of container hashes received
    mapping (bytes32 => uint256) public hashCounts;
}
