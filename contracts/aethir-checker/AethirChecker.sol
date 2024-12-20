// SPDX-License-Identifier: GPL-3.0-only

pragma solidity 0.8.28;

import "../common/proxies/UpgradeableAccessControl.sol";
import "./AethirCheckerState.sol";
import "../common/Rescuable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

contract AethirChecker is UpgradeableAccessControl, AethirCheckerState, Rescuable {
    using Checkpoints for Checkpoints.Trace208;

    event RegisterClient(address client, string clientId, address admin);
    event DeregisterClient(address client, string clientId, address admin);

    //event Logger(uint256 uint256val1, uint256 uint256val2, bytes32 bytes32Val1, address addr1, string str1, string str2);

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
        string correctJobId,
        string[] correctLicIds,
        string[] incorrectLicIds
    );

    event BatchFailed(
        string[] incorrectLicIds,
        string error
    );

    event BatchPassedM(
        string correctJobId,
        uint256[] correctLicIds,
        uint256[] incorrectLicIds
    );

    event BatchFailedM(
        uint256[] incorrectLicIds,
        string error
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

    function registerClient(address client, string memory clientId, bytes memory signatureData) external {
        address admin = _authenticateReportAdmin(signatureData);

        if (bytes(clientId).length == 0) revert ClientIdIsZero();
        if (bytes(clientToId[client]).length != 0 || idToClient[clientId] != address(0)) revert ClientExists(idToClient[clientId], clientToId[client]);

        clientToId[client] = clientId;
        idToClient[clientId] = client;

        emit RegisterClient(client, clientId, admin);
    }

    function deregisterClient(address client, bytes memory signatureData) external {
        address admin = _authenticateReportAdmin(signatureData);

        if (bytes(clientToId[client]).length == 0) revert ClientDoesNotExist();

        string memory clientId = clientToId[client];
        clientToId[client] = "";
        idToClient[clientId] = address(0);

        emit DeregisterClient(client, clientId, admin);
    }

    function submitReportsMinified(ReportMinified[][] memory reports) external {
        if (!hasRole(REPORT_ADMIN_ROLE, msg.sender)) {
            revert Unauthorized(msg.sender);
        }

        if (reports.length == 0) {
            revert BatchesNotSent();
        }

        for (uint256 i; i < reports.length; i++) {

            uint256 reportsLen = reports[i].length;

            if (reportsLen == 0) {
                emit BatchFailed(
                    new string[](0),
                    "empty batch"
                );
                continue;
            }

            uint256 correctCount;
            bytes32[] memory containerHashes = new bytes32[](reportsLen);
            ReportMinified memory report;
            for (uint256 j; j < reportsLen; j++) {
                report = reports[i][j];

                if (bytes(report.jobId).length == 0 ||
                    report.licenseId == 0 ||
                    report.containerHash == 0) {
                    continue;
                }

                totalReports++;

                correctCount++;
                containerHashes[j] = report.containerHash;

                // clear state for hash if remaining from an earlier txn (just in case)
                _hashCounts[containerHashes[j]] = 0;
            }

            uint256 majorityCount = uint256(correctCount) / 2 + 1;
            uint256 majorityIdx;
            uint256 majorityHashCount;
            bytes32 thisHash;
            if (correctCount != 0) {
                uint256 hashCount;
                for (uint256 j; j < reportsLen; j++) {
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

            correctCount = 0;
            uint256 incorrectCount = 0;

            // correct, incorrect
            uint256[][2] memory licIdGroups;
            if (majorityHashCount >= majorityCount) {
                licIdGroups[0] = new uint256[](majorityHashCount);
                licIdGroups[1] = new uint256[](reportsLen-majorityHashCount);
                bytes32 majorityHash = containerHashes[majorityIdx];
                for (uint256 j; j < reportsLen; j++) {
                    thisHash = containerHashes[j];
                    report = reports[i][j];
                    if (thisHash != majorityHash) {
                        licIdGroups[1][incorrectCount++] = report.licenseId;
                    } else {
                        licIdGroups[0][correctCount++] = report.licenseId;
                    }

                    if (thisHash != 0) {
                        // don't leave temporary state behind
                        _hashCounts[thisHash] = 0;
                    }
                }

                totalBatches++;
                emit BatchPassedM(
                    reports[i][majorityIdx].jobId,
                    licIdGroups[0],
                    licIdGroups[1]
                );

            } else {
                // all are considered incorrect
                licIdGroups[1] = new uint256[](reportsLen);
                for (uint256 j; j < reportsLen; j++) {
                    report = reports[i][j];
                    licIdGroups[1][incorrectCount++] = report.licenseId;
                    thisHash = containerHashes[j];
                    if (thisHash != 0) {
                        // don't leave temporary state behind
                        _hashCounts[thisHash] = 0;
                    }
                }

                emit BatchFailedM(
                    licIdGroups[1],
                    "majority rule"
                );
            }
        }
    }

    function submitReports(Report[][] memory reports, bytes memory signatureData) external {
        address admin = _authenticateReportAdmin(signatureData);

        if (reports.length == 0) {
            revert BatchesNotSent();
        }

        for (uint256 i; i < reports.length; i++) {

            uint256 reportsLen = reports[i].length;

            if (reportsLen == 0) {
                emit BatchFailed(
                    new string[](0),
                    "empty batch"
                );
                continue;
            }

            uint256 correctCount;
            bytes32[] memory containerHashes = new bytes32[](reportsLen);
            Report memory report;
            for (uint256 j; j < reportsLen; j++) {
                report = reports[i][j];

                if (bytes(report.jobId).length == 0 ||
                    bytes(report.clientId).length == 0 ||
                    bytes(report.licenseId).length == 0 ||
                    report.epoch == 0 ||
                    report.period == 0 ||
                    report.reportTime == 0 ||
                    bytes(report.containerId).length == 0 ||
                    report.jobType == 0 ||
                    report.containerData.length == 0) {
                    // TODO: Check for report.signatureData.length == 0 later

                    //emit Logger(i, j, 0, address(0), "", "invalid report");

                    continue;
                }

                address client;
                /*// TODO for later: 
                client = _authenticateReportClient(report.signatureData);

                if (keccak256(abi.encodePacked(clientToId[client])) != keccak256(abi.encodePacked(report.clientId))) {
                    //emit Logger(i, j, 0, client, report.clientId, "clientId mismatch");

                    continue;
                }
                */
                /* TODO for later: MVP doesn't need this yet
                if (idToClient[report.clientId] == address(0)) {
                    //emit Logger(i, j, 0, client, report.clientId, "clientId missing");
                    continue;
                }*/

                // only consider reports that make it this far for additional processing
                //emit Logger(i, j, 0, client, report.clientId, "checks passed");

                _addReport(report);

                correctCount++;
                containerHashes[j] = keccak256(report.containerData);

                // clear state for hash if remaining from an earlier txn (just in case)
                _hashCounts[containerHashes[j]] = 0;
            }

            uint256 majorityCount = uint256(correctCount) / 2 + 1;
            uint256 majorityIdx;
            uint256 majorityHashCount;
            bytes32 thisHash;
            if (correctCount != 0) {
                uint256 hashCount;
                for (uint256 j; j < reportsLen; j++) {
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

            correctCount = 0;
            uint256 incorrectCount = 0;

            // correct, incorrect
            string[][2] memory licIdGroups;
            if (majorityHashCount >= majorityCount) {
                licIdGroups[0] = new string[](majorityHashCount);
                licIdGroups[1] = new string[](reportsLen-majorityHashCount);
                bytes32 majorityHash = containerHashes[majorityIdx];
                for (uint256 j; j < reportsLen; j++) {
                    thisHash = containerHashes[j];
                    report = reports[i][j];
                    if (thisHash != majorityHash) {
                        licIdGroups[1][incorrectCount++] = report.licenseId;
                    } else {
                        licIdGroups[0][correctCount++] = report.licenseId;
                    }

                    if (thisHash != 0) {
                        // don't leave temporary state behind
                        _hashCounts[thisHash] = 0;
                    }
                }

                report = reports[i][majorityIdx];
                _addBatch(Batch({
                    correctJobId: report.jobId,
                    correctLicIds: licIdGroups[0],
                    incorrectLicIds: licIdGroups[1]
                }));

            } else {
                // all are considered incorrect
                licIdGroups[1] = new string[](reportsLen);
                for (uint256 j; j < reportsLen; j++) {
                    report = reports[i][j];
                    licIdGroups[1][incorrectCount++] = report.licenseId;
                    thisHash = containerHashes[j];
                    if (thisHash != 0) {
                        // don't leave temporary state behind
                        _hashCounts[thisHash] = 0;
                    }
                }

                emit BatchFailed(
                    licIdGroups[1],
                    "majority rule"
                );
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

    /*function _authenticateReportClient(bytes memory signatureData) internal returns (address) {
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
    }*/

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

        /*// TODO for later: Store verified reports on chain?
        (,uint256 timestamp, uint256 pos) = storedReportCheckpoint_.latestCheckpoint();
        Report[] storage _ref;
        if (block.timestamp != timestamp) {
            // create new checkpoint
            storedReports.push().push(report);
            _push(storedReportCheckpoint_, SafeCast.toUint208(storedReports.length));
        } else {
            // checking already exists
            storedReports[pos-1].push(report);
        }*/

        totalReports++;

        /*emit ReportReceived(
            report.jobId,
            report.clientId,
            report.licenseId,
            report.epoch,
            report.period,
            report.reportTime,
            report.containerId,
            report.jobType,
            report.containerData
        );*/
    }

    function _addBatch(Batch memory batch) internal {

        /*// TODO for later: Store verified reports on chain?
        (,uint256 timestamp, uint256 pos) = storedBatchCheckpoint_.latestCheckpoint();
        Batch[] storage _ref;
        if (block.timestamp != timestamp) {
            // create new checkpoint
            storedBatches.push().push(batch);
            _push(storedBatchCheckpoint_, SafeCast.toUint208(storedBatches.length));
        } else {
            // checking already exists
            storedBatches[pos-1].push(batch);
        }*/

        totalBatches++;

        emit BatchPassed(
            batch.correctJobId,
            batch.correctLicIds,
            batch.incorrectLicIds
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
