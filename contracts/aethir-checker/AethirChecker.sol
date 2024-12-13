// SPDX-License-Identifier: GPL-3.0-only

pragma solidity 0.8.28;

import "../common/proxies/UpgradeableAccessControl.sol";
import "./AethirCheckerState.sol";
import "../common/Rescuable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

contract AethirChecker is UpgradeableAccessControl, AethirCheckerState, Rescuable {
    using Checkpoints for Checkpoints.Trace208;

    event BatchFailed(string error);
    event Logger(uint256 uint256val1, uint256 uint256val2, bytes32 bytes32Val1, address addr1, string str1, string str2);

    event ReportReceived(
        string jobId,
        string clientId,
        string licenseId,
        int64 epoch,
        int256 period,
        int256 reportTime,
        string containerId,
        uint8 jobType,
        bytes containerData
    );

    event BatchPassed(
        int64 epoch,
        int256 period,
        int256 reportTime,
        string containerId,
        uint8 jobType,
        bytes containerData
    );

    /// @notice Thrown when the counts of receivers and amounts do not match
    error CountMismatch();

    /// @notice Thrown when the provided signature is invalid or does not match the sender.
    /// @dev This error is thrown if `ecrecover` fails or the recovered address does not match the expected sender.
    error InvalidSignature(address signer);

    /// @notice Thrown when the nonce provided does not match the expected nonce for the sender.
    /// @dev This error prevents replay attacks by ensuring each signature is used only once.
    error InvalidNonce();

    /// @notice Thrown when the signature provided has expired based on the deadline.
    /// @dev The signature is considered expired if the current block timestamp exceeds the deadline set during signature creation.
    error SignatureExpired();

    /// @notice Error thrown when a zero address is provided
    error ZeroAddress();

    /// @notice Error thrown when ether is sent
    error EtherSent();

    /// @notice Error thrown when the action is not authorized
    error Unauthorized(address caller);

    error BatchesNotSent();
    error ClientIdIsZero();
    error ClientExists(address client, string clientId);
    error ClientDoesNotExist();
    error InvalidRange(uint256 startTime, uint256 endTime);

    /// @notice Role constant for report submitter
    bytes32 public constant REPORT_ADMIN_ROLE = keccak256("REPORT_ADMIN_ROLE");

    /// @notice The EIP-712 typehash for the report admin struct used in signature validation
    bytes32 public constant REPORT_ADMIN_TYPEHASH = keccak256("AethirReportAdmin(address signer,uint256 nonce,uint256 deadline)");

    /// @notice The EIP-712 typehash for the report client struct used in signature validation
    bytes32 public constant REPORT_CLIENT_TYPEHASH = keccak256("AethirReportClient(address signer,string clientId,uint256 deadline)");

    function initialize() external onlyRole(DEFAULT_ADMIN_ROLE) {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("AethirChecker")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function registerClient(string memory clientId) external {
        if (bytes(clientId).length == 0) revert ClientIdIsZero();
        if (bytes(clientToId[msg.sender]).length != 0 || idToClient[clientId] != address(0)) revert ClientExists(idToClient[clientId], clientToId[msg.sender]);

        clientToId[msg.sender] = clientId;
        idToClient[clientId] = msg.sender;
    }

    function deregisterClient() external {
        if (bytes(clientToId[msg.sender]).length == 0) revert ClientDoesNotExist();

        string memory clientId = clientToId[msg.sender];
        clientToId[msg.sender] = "";
        idToClient[clientId] = address(0);
    }

    function submitReports(Report[][] memory reports, bytes memory signatureData) external {

        address admin = _authenticateReportAdmin(signatureData);

        if (reports.length == 0) {
            revert BatchesNotSent();
        }

        for (uint256 i; i < reports.length; i++) {
            if (reports[i].length == 0) {
                emit BatchFailed("empty");
                continue;
            }

            uint256 validCount;
            bytes32[] memory containerHashes = new bytes32[](reports[i].length);
            for (uint256 j; j < reports[i].length; j++) {
                Report memory report = reports[i][j];

                if (bytes(report.jobId).length == 0 ||
                    bytes(report.clientId).length == 0 ||
                    bytes(report.licenseId).length == 0 ||
                    report.epoch == 0 ||
                    report.period == 0 ||
                    report.reportTime == 0 ||
                    bytes(report.containerId).length == 0 ||
                    report.jobType == 0 ||
                    report.containerData.length == 0 ||
                    report.signatureData.length == 0) {
                    
                    emit Logger(i, j, 0, address(0), "", "invalid report");

                    continue;
                }

                address client = _authenticateReportClient(report.signatureData);

                if (keccak256(abi.encodePacked(clientToId[client])) != keccak256(abi.encodePacked(report.clientId))) {
                    emit Logger(i, j, 0, client, report.clientId, "clientId mismatch");
                    continue;
                }

                emit Logger(i, j, 0, client, report.clientId, "checks passed");

                // only consider reports that make it this far for additional processing

                _addReport(report);
   
                validCount++;
                containerHashes[j] = keccak256(report.containerData);

                // clear state for hash if remaining from an earlier txn
                _hashCounts[containerHashes[j]] = 0;
            }

            uint256 majorityCount = uint256(validCount) / 2 + 1;
            uint256 majorityIdx;
            uint256 majorityHashCount;

            if (validCount != 0) {
                bytes32 thisHash;
                uint256 hashCount;
                for (uint256 j; j < reports[i].length; j++) {
                    if (containerHashes[j] == 0) continue;
                    thisHash = containerHashes[j];
                    hashCount = _hashCounts[thisHash] + 1;
                    if (hashCount > majorityHashCount) {
                        majorityIdx = j;
                        majorityHashCount = hashCount;
                    }
                    _hashCounts[thisHash] = hashCount;
                }
            }

            if (majorityHashCount >= majorityCount) {
                _addBatch(reports[i][majorityIdx]);
            } else {
                emit BatchFailed("majority rule");
            }
        }
    }

    function _authenticateReportAdmin(bytes memory signatureData) internal returns (address) {
        address signerAddress;

        if (signatureData.length != 0) {
            (address signer, uint256 nonce, uint256 deadline, bytes memory signature) =
                abi.decode(signatureData, (address, uint256, uint256, bytes));

            // Check if the signature has expired
            if (block.timestamp > deadline) {
                revert SignatureExpired();
            }

            // Check for correct nonce to prevent replay attacks
            if (nonce != nonces[signer]) {
                revert InvalidNonce();
            }

            // Construct the struct hash for the signed authentication data
            bytes32 hashVar = keccak256(
                abi.encode(
                    REPORT_ADMIN_TYPEHASH,
                    signer,
                    nonce,
                    deadline
                )
            );

            // Construct the digest as per EIP-712
            hashVar = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashVar));

            // Recover the signer from the signature
            signerAddress = ECDSA.recover(hashVar, signature);
            if (signerAddress == address(0) || signerAddress != signer) {
                revert InvalidSignature(signerAddress);
            }

            // Increment the nonce to prevent replay of this signature
            nonces[signer]++;
        } else {
            signerAddress = msg.sender;
        }

        if (!hasRole(REPORT_ADMIN_ROLE, signerAddress)) {
            revert Unauthorized(signerAddress);
        }

        return signerAddress;
    }

    function _authenticateReportClient(bytes memory signatureData) internal returns (address) {
        address signerAddress;

        if (signatureData.length != 0) {

            (address signer, string memory clientId, uint256 deadline, bytes memory signature) =
                abi.decode(signatureData, (address, string, uint256, bytes));

            // Check if the signature has expired
            if (block.timestamp > deadline) {
                revert SignatureExpired();
            }

            // Construct the struct hash for the signed authentication data
            bytes32 hashVar = keccak256(
                abi.encode(
                    REPORT_CLIENT_TYPEHASH,
                    signer,
                    clientId,
                    deadline
                )
            );

            // Construct the digest as per EIP-712
            hashVar = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashVar));

            // Recover the signer from the signature
            signerAddress = ECDSA.recover(hashVar, signature);
            if (signerAddress == address(0) || signerAddress != signer) {
                revert InvalidSignature(signerAddress);
            }

            // TODO: store hash of client data to prevent duplicates <- is this needed?
        }

        return signerAddress;
    }

    function totalReportsInRange(uint256 startTime, uint256 endTime) external view returns (uint256 total) {
        if (startTime > endTime) {
            revert InvalidRange(startTime, endTime);
        }
        if (startTime > block.timestamp) {
            startTime = block.timestamp;
            endTime = block.timestamp;
        } else if (endTime > block.timestamp) {
            endTime = block.timestamp;
        }

        uint256 lowerBound = storedReportCheckpoint_.lowerLookup(SafeCast.toUint48(startTime));
        if (lowerBound == 0) {
            // none found
            return 0;
        }
        uint256 upperBound = storedReportCheckpoint_.upperLookupRecent(SafeCast.toUint48(endTime));

        for (uint256 repIdx = lowerBound - 1; repIdx < upperBound; repIdx++) {
            total += storedReports[repIdx].length;
        }
    }

    function getReportsInRange(uint256 startTime, uint256 endTime, uint256 limit) external view returns (Report[] memory reports) {
        if (startTime > endTime) {
            revert InvalidRange(startTime, endTime);
        }
        if (startTime > block.timestamp) {
            startTime = block.timestamp;
            endTime = block.timestamp;
        } else if (endTime > block.timestamp) {
            endTime = block.timestamp;
        }

        uint256 lowerBound = storedReportCheckpoint_.lowerLookup(SafeCast.toUint48(startTime));
        if (lowerBound == 0) {
            // none found
            return reports;
        }
        uint256 upperBound = storedReportCheckpoint_.upperLookupRecent(SafeCast.toUint48(endTime));
        if (upperBound < lowerBound) {
            // none found
            return reports;
        }

        reports = new Report[](limit);

        uint256 i;
        uint256 len;
        uint256 idx;
        for (uint256 repIdx = lowerBound - 1; repIdx < upperBound; repIdx++) {
            Report[] memory repArr = storedReports[repIdx];
            len = repArr.length;
            for (i = 0; i < len; i++) {
                reports[idx] = repArr[i];
                idx++;
            }
        }

        assembly {
            mstore(reports, idx)
        }
    }

    function totalBatchesInRange(uint256 startTime, uint256 endTime) external view returns (uint256 total) {
        if (startTime > endTime) {
            revert InvalidRange(startTime, endTime);
        }
        if (startTime > block.timestamp) {
            startTime = block.timestamp;
            endTime = block.timestamp;
        } else if (endTime > block.timestamp) {
            endTime = block.timestamp;
        }

        uint256 lowerBound = storedBatchCheckpoint_.lowerLookup(SafeCast.toUint48(startTime));
        if (lowerBound == 0) {
            // none found
            return 0;
        }
        uint256 upperBound = storedBatchCheckpoint_.upperLookupRecent(SafeCast.toUint48(endTime));

        for (uint256 repIdx = lowerBound - 1; repIdx < upperBound; repIdx++) {
            total += storedBatches[repIdx].length;
        }
    }

    function getBatchesInRange(uint256 startTime, uint256 endTime, uint256 limit) external view returns (Batch[] memory batches) {
        if (startTime > endTime) {
            revert InvalidRange(startTime, endTime);
        }
        if (startTime > block.timestamp) {
            startTime = block.timestamp;
            endTime = block.timestamp;
        } else if (endTime > block.timestamp) {
            endTime = block.timestamp;
        }

        uint256 lowerBound = storedBatchCheckpoint_.lowerLookup(SafeCast.toUint48(startTime));
        if (lowerBound == 0) {
            // none found
            return batches;
        }
        uint256 upperBound = storedBatchCheckpoint_.upperLookupRecent(SafeCast.toUint48(endTime));
        if (upperBound < lowerBound) {
            // none found
            return batches;
        }

        batches = new Batch[](limit);

        uint256 i;
        uint256 len;
        uint256 idx;
        for (uint256 repIdx = lowerBound - 1; repIdx < upperBound; repIdx++) {
            Batch[] memory repArr = storedBatches[repIdx];
            len = repArr.length;
            for (i = 0; i < len; i++) {
                batches[idx] = repArr[i];
                idx++;
            }
        }

        assembly {
            mstore(batches, idx)
        }
    }

    /*function at(uint32 pos) external view returns (Checkpoints.Checkpoint208 memory) {
        return storedReportCheckpoint_.at(pos);
    }*/

    function _addReport(Report memory report) internal {

        (,uint256 timestamp, uint256 pos) = storedReportCheckpoint_.latestCheckpoint();
        Report[] storage _ref;
        if (block.timestamp != timestamp) {
            // create new checkpoint
            storedReports.push().push(report);
            _push(storedReportCheckpoint_, SafeCast.toUint208(storedReports.length));
        } else {
            // checking already exists
            storedReports[pos-1].push(report);
        }

        totalReports++;

        emit ReportReceived(
            report.jobId,
            report.clientId,
            report.licenseId,
            report.epoch,
            report.period,
            report.reportTime,
            report.containerId,
            report.jobType,
            report.containerData
        );
    }

    function _addBatch(Report memory report) internal {

        Batch memory batch = Batch({
            epoch: report.epoch,
            period: report.period,
            reportTime: report.reportTime,
            containerId: report.containerId,
            jobType: report.jobType,
            containerData: report.containerData
        });

        (,uint256 timestamp, uint256 pos) = storedBatchCheckpoint_.latestCheckpoint();
        Batch[] storage _ref;
        if (block.timestamp != timestamp) {
            // create new checkpoint
            storedBatches.push().push(batch);
            _push(storedBatchCheckpoint_, SafeCast.toUint208(storedBatches.length));
        } else {
            // checking already exists
            storedBatches[pos-1].push(batch);
        }

        totalBatches++;

        emit BatchPassed(
            batch.epoch,
            batch.period,
            batch.reportTime,
            batch.containerId,
            batch.jobType,
            batch.containerData
        );
    }

    function _push(Checkpoints.Trace208 storage store, uint208 val) internal {
        store.push(
            SafeCast.toUint48(block.timestamp),
            SafeCast.toUint208(val)
        );
    }

    function _requireRescuerRole() onlyRole(DEFAULT_ADMIN_ROLE) internal view override {
        // Empty function body
    }

    /**
     * @notice Fallback function that receives Ether when no data is sent.
     * @dev Reverts when Ether is sent without data.
     */
    receive() external payable {
        revert EtherSent();
    }
}
