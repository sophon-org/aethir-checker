// SPDX-License-Identifier: GPL-3.0-only

pragma solidity 0.8.28;

import "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

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
        bytes containerData;    // Liveness: container.continues (bool), container.loss (uint8), container.duration (int64) OR Capacity: container.qualified (bool)
        bytes signatureData;    // client's signature
    }

    struct Batch {
        int64 epoch;            // epoch (int64)
        int256 period;          // period  (int)
        int256 reportTime;      // reportTime (int)
        string containerId;     // containerId (string)
        uint8 jobType;          // jobType (uint8)
        bytes containerData;    // Liveness: container.continues (bool), container.loss (uint8), container.duration (int64) OR Capacity: container.qualified (bool)
    }

    /// @notice EIP-712 Domain Separator
    bytes32 public DOMAIN_SEPARATOR;

    /// @notice Mapping to track nonces for each address, used to prevent replay attacks in signed messages
    mapping (address => uint256) public nonces;

    /// @notice Mapping to temporarily track counts of container hashes received
    /// @dev TODO: make this internal
    mapping (bytes32 => uint256) public _hashCounts;

    uint256 public totalReports;
    Report[][] public storedReports; // array of Report arrays at each timestamp checkpoint
    Checkpoints.Trace208 internal storedReportCheckpoint_; // key: timestamp, value: checkpoint index in storedReports

    uint256 public totalBatches;
    Batch[][] public storedBatches; // array of Batch arrays at each timestamp checkpoint
    Checkpoints.Trace208 internal storedBatchCheckpoint_; // key: timestamp, value: checkpoint index in storedBatches
}
