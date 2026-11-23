// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../interfaces/IAttestationVerifier.sol";
import "./Relay.sol";

/**
 * @title RelaySubscriptions Contract
 * @notice This contract manages serverless job subscriptions.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract RelaySubscriptions is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable // public upgrade
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    /// @notice Error for when zero address is provided for Relay contract.
    error RelaySubscriptionsInvalidRelay();

    /**
     * @notice Initializes the logic contract with essential parameters and disables further
     * initializations of the logic contract.
     * @param _relay The Relay contract.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        Relay _relay,
        uint256 _minPeriodicGap,
        uint256 _maxPeriodicGap,
        uint256 _maxTerminationDuration
    ) {
        _disableInitializers();

        if (address(_relay) == address(0)) revert RelaySubscriptionsInvalidRelay();
        RELAY = _relay;
        MIN_PERIODIC_GAP = _minPeriodicGap;
        MAX_PERIODIC_GAP = _maxPeriodicGap;
        MAX_TERMINATION_DURATION = _maxTerminationDuration;
    }

    //-------------------------------- Overrides start --------------------------------//

    /// @inheritdoc ERC165Upgradeable
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    /// @inheritdoc UUPSUpgradeable
    function _authorizeUpgrade(address /*account*/) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    /// @notice Error for when zero address is provided for the admin.
    error RelaySubscriptionsZeroAddressAdmin();

    /**
     * @notice Initializes the Relay contract with the specified admin and enclave images.
     * @param _admin The address to be granted the DEFAULT_ADMIN_ROLE.
     */
    function initialize(address _admin) public initializer {
        if (_admin == address(0)) revert RelaySubscriptionsZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        jobSubsCount = (block.chainid << 192) | (uint256(1) << 191);
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    Relay public immutable RELAY;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable MIN_PERIODIC_GAP;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable MAX_PERIODIC_GAP;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable MAX_TERMINATION_DURATION;

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.RelaySubscriptions"),
                keccak256("1")
            )
        );

    //-------------------------------- Job Subscription Start ----------------------------------//

    struct JobSubscriptionParams {
        uint8 env;
        uint256 startTime;
        uint256 maxGasPrice;
        uint256 usdcDeposit;
        uint256 callbackGasLimit;
        address callbackContract;
        bytes32 codehash;
        bytes codeInputs;
        uint256 periodicGap;
        uint256 terminationTimestamp;
        uint256 userTimeout;
        address refundAccount;
    }

    struct JobSubscription {
        uint256 periodicGap;
        uint256 terminationTimestamp;
        uint256 currentRuns;
        uint256 lastRunTimestamp;
        uint256 userTimeout;
        address refundAccount;
        Relay.Job job;
    }

    // jobSubsId => JobSubscription
    mapping(uint256 => JobSubscription) public jobSubscriptions;

    /**
     * @notice Tracks the job subscriptions count.
     * @dev It follows this scheme -
     *      | Chain ID (64)| 1 (1 bit) | sub_id (64 bits) | instance_count (127) |
     *      First 64 bits represent the chainId.
     *      65th bit is fixed as 1, which represents a job subscription.
     *      Next 64 bits are reserved for subscription id, and increments each time a new job subscrtiption is started.
     *      Last 127 bits are fixed as all zeros.
     *      If sub_id reaches its max value, then we reset the sub_id to zero.
     */
    uint256 public jobSubsCount;

    /**
     * @notice Emitted when a job subscription is started.
     * @param jobSubsId The unique identifier of the job subscription.
     * @param env The execution environment for the periodic jobs.
     * @param jobSubscriber The address of the job subscriber.
     * @param periodicGap The gap between job executions in the subscription.
     * @param usdcDeposit The USDC deposit provided for the subscription.
     * @param terminationTimestamp The timestamp when the subscription should terminate.
     * @param userTimeout The timeout specified by the user for the subscription.
     * @param refundAccount The address where the refund will be sent.
     * @param codehash The transaction hash storing the code to be executed.
     * @param codeInputs The inputs for the code execution.
     * @param startTime The timestamp when the subscription was started.
     */
    event JobSubscriptionStarted(
        uint256 indexed jobSubsId,
        uint8 indexed env,
        address indexed jobSubscriber,
        uint256 periodicGap,
        uint256 usdcDeposit,
        uint256 terminationTimestamp,
        uint256 userTimeout,
        address refundAccount,
        bytes32 codehash,
        bytes codeInputs,
        uint256 startTime
    );

    /**
     * @notice Emitted when a job subscription responds with its output.
     * @param jobSubsId The unique identifier of the job subscription.
     * @param output The output from the job execution.
     * @param totalTime The total time taken for the job execution.
     * @param errorCode The error code if the job failed.
     * @param success A boolean indicating if the job was successful.
     * @param currentRuns The number of times the job has run.
     * @param lastRunTimestamp The timestamp of the last job run.
     */
    event JobSubscriptionResponded(
        uint256 indexed jobSubsId,
        bytes output,
        uint256 totalTime,
        uint256 errorCode,
        bool success,
        uint256 currentRuns,
        uint256 lastRunTimestamp
    );

    /**
     * @notice Emitted when USDC or callback deposit is made for a job subscription.
     * @param jobSubsId The unique identifier of the job subscription.
     * @param depositor The address making the deposit.
     * @param usdcDeposit The amount of USDC deposited.
     * @param callbackDeposit The amount of callback deposit made.
     */
    event JobSubscriptionFundsDeposited(
        uint256 indexed jobSubsId,
        address indexed depositor,
        uint256 usdcDeposit,
        uint256 callbackDeposit
    );

    /**
     * @notice Emitted when job parameters are updated in a job subscription.
     * @param jobSubsId The unique identifier of the job subscription.
     * @param codehash The new code hash for the job.
     * @param codeInputs The new code inputs for the job.
     */
    event JobSubscriptionJobParamsUpdated(uint256 indexed jobSubsId, bytes32 codehash, bytes codeInputs);

    /**
     * @notice Emitted when termination parameters are updated in a job subscription.
     * @param jobSubsId The unique identifier of the job subscription.
     * @param terminationTimestamp The new termination timestamp for the subscription.
     */
    event JobSubscriptionTerminationParamsUpdated(
        uint256 indexed jobSubsId,
        // uint256 maxRuns,
        uint256 terminationTimestamp
    );

    /**
     * @notice Emitted when job subscription remaining funds are withdrawn.
     * @param jobSubsId The unique identifier of the job subscription.
     * @param jobOwner The owner account of the job subscription.
     * @param usdcAmountWithdrawn The amount of USDC withdrawn.
     * @param callbackAmountWithdrawn The amount of callback deposit withdrawn.
     * @param success A boolean indicating if the withdrawal was successful.
     */
    event JobSubscriptionDepositsRefunded(
        uint256 indexed jobSubsId,
        address indexed jobOwner,
        uint256 usdcAmountWithdrawn,
        uint256 callbackAmountWithdrawn,
        bool success
    );

    /**
     * @notice Emitted when job subscription is terminated.
     * param jobSubsId The unique identifier of the job subscription.
     */
    event JobSubscriptionTerminated(uint256 indexed jobSubsId);

    /// @notice Error for when a job subscription is invalid.
    error RelaySubscriptionsInvalidJobSubscription();
    /// @notice Error for when the current runs in job response jobId is invalid.
    error RelaySubscriptionsInvalidCurrentRuns();
    /// @notice Error for when insufficient USDC is being deposited for a job subscription.
    error RelaySubscriptionsInsufficientUsdcDeposit();
    /// @notice Error for when the start timestamp is an invalid value.
    error RelaySubscriptionsInvalidStartTimestamp();
    /// @notice Error for when an invalid user timeout is provided.
    error RelaySubscriptionsInvalidUserTimeout();
    /// @notice Error for when the maximum gas price provided is insufficient.
    error RelaySubscriptionsInsufficientMaxGasPrice();
    /// @notice Error for when there is insufficient callback deposit.
    error RelaySubscriptionsInsufficientCallbackDeposit();
    /// @notice Error for when the overall timeout for a job has been exceeded.
    error RelaySubscriptionsOverallTimeoutOver();
    /// @notice Error for when the signature has expired.
    error RelaySubscriptionsSignatureTooOld();
    /// @notice Error for when the termination timestamp is an invalid value.
    error RelaySubscriptionsInvalidTerminationTimestamp();
    /// @notice Error for when the periodic gap is an invalid value.
    error RelaySubscriptionsInvalidPeriodicGap();
    /// @notice Error for when the msg.sender isn't the job subscription owner
    error RelaySubscriptionsNotJobSubscriptionOwner();
    /// @notice Error for when the job subscription does not exists corresponding to a job subscription id.
    error RelaySubscriptionsNotExists();
    /// @notice Error for when the job subscription is about to be terminated and no updates are allowed 
    ///         i.e. (block.timestamp >= terminationTimestamp  - OVERALL_TIMEOUT)
    error RelaySubscriptionsUpdateDeadlineOver();
    /// @notice Error for when the job subscription owner tries to terminate the subscription
    ///         before the termination condition is reached.
    error RelaySubscriptionsTerminationConditionPending();
    /// @notice Thrown when the provided execution environment is not supported globally.
    error RelaySubscriptionsUnsupportedEnv();

    modifier isValidEnv(uint8 _env) {
        if (!RELAY.isEnvSupported(_env)) revert RelaySubscriptionsUnsupportedEnv();
        _;
    }

    //-------------------------------- internal functions start --------------------------------//

    function _startJobSubscription(
        JobSubscriptionParams memory _jobSubsParams,
        uint256 _callbackDeposit,
        address _jobOwner
    ) internal {
        if (_jobSubsParams.startTime >= _jobSubsParams.terminationTimestamp)
            revert RelaySubscriptionsInvalidStartTimestamp();

        if (_jobSubsParams.terminationTimestamp <= block.timestamp || _jobSubsParams.terminationTimestamp > block.timestamp + MAX_TERMINATION_DURATION)
            revert RelaySubscriptionsInvalidTerminationTimestamp();

        if (_jobSubsParams.periodicGap < MIN_PERIODIC_GAP || _jobSubsParams.periodicGap > MAX_PERIODIC_GAP)
            revert RelaySubscriptionsInvalidPeriodicGap();

        if (
            _jobSubsParams.userTimeout <= RELAY.GLOBAL_MIN_TIMEOUT() ||
            _jobSubsParams.userTimeout >= RELAY.GLOBAL_MAX_TIMEOUT()
        ) revert RelaySubscriptionsInvalidUserTimeout();

        if (_jobSubsParams.maxGasPrice < tx.gasprice) revert RelaySubscriptionsInsufficientMaxGasPrice();

        if (_jobSubsParams.startTime < block.timestamp) _jobSubsParams.startTime = block.timestamp;

        _validateDeposits(
            _jobSubsParams.env,
            _jobSubsParams.userTimeout,
            _jobSubsParams.maxGasPrice,
            _jobSubsParams.callbackGasLimit,
            _jobSubsParams.periodicGap,
            _callbackDeposit,
            _jobSubsParams.usdcDeposit,
            _jobSubsParams.startTime,
            _jobSubsParams.terminationTimestamp
        );

        Relay.Job memory job = Relay.Job({
            env: _jobSubsParams.env,
            startTime: _jobSubsParams.startTime,
            maxGasPrice: _jobSubsParams.maxGasPrice,
            usdcDeposit: _jobSubsParams.usdcDeposit,
            callbackDeposit: _callbackDeposit,
            jobOwner: _jobOwner,
            codehash: _jobSubsParams.codehash,
            codeInputs: _jobSubsParams.codeInputs,
            callbackContract: _jobSubsParams.callbackContract,
            callbackGasLimit: _jobSubsParams.callbackGasLimit
        });

        _createJobSubscription(
            job,
            _jobSubsParams.userTimeout,
            _jobSubsParams.refundAccount,
            _jobSubsParams.periodicGap,
            _jobSubsParams.terminationTimestamp
        );

        // deposit escrow amount(USDC) for the periodic jobs
        RELAY.TOKEN().safeTransferFrom(_jobOwner, address(this), _jobSubsParams.usdcDeposit);
    }

    function _validateDeposits(
        uint8 _env,
        uint256 _userTimeout,
        uint256 _maxGasPrice,
        uint256 _callbackGasLimit,
        uint256 _periodicGap,
        uint256 _callbackDeposit,
        uint256 _usdcDeposit,
        uint256 _startTimestamp,
        uint256 _terminationTimestamp
    ) internal view {
        uint256 totalRuns = ((_terminationTimestamp - _startTimestamp) / _periodicGap) + 1;

        uint256 minCallbackDeposit = _maxGasPrice * (_callbackGasLimit + RELAY.FIXED_GAS() + RELAY.CALLBACK_MEASURE_GAS()) * totalRuns;
        if (_callbackDeposit < minCallbackDeposit) revert RelaySubscriptionsInsufficientCallbackDeposit();

        uint256 minUsdcDeposit = (_userTimeout * RELAY.getJobExecutionFeePerMs(_env) + RELAY.GATEWAY_FEE_PER_JOB()) * totalRuns;
        if (_usdcDeposit < minUsdcDeposit) revert RelaySubscriptionsInsufficientUsdcDeposit();
    }

    function _createJobSubscription(
        Relay.Job memory _job,
        uint256 _userTimeout,
        address _refundAccount,
        uint256 _periodicGap,
        uint256 _terminationTimestamp
    ) internal {
        _updateJobSubsCount();

        jobSubscriptions[jobSubsCount] = JobSubscription({
            periodicGap: _periodicGap,
            terminationTimestamp: _terminationTimestamp,
            currentRuns: 0,
            lastRunTimestamp: 0,
            userTimeout: _userTimeout,
            refundAccount: _refundAccount,
            job: _job
        });

        emit JobSubscriptionStarted(
            jobSubsCount,
            _job.env,
            _job.jobOwner,
            _periodicGap,
            _job.usdcDeposit,
            _terminationTimestamp,
            _userTimeout,
            _refundAccount,
            _job.codehash,
            _job.codeInputs,
            _job.startTime
        );
    }

    function _updateJobSubsCount() internal {
        uint256 subId = (jobSubsCount >> 127) & ((1 << 64) - 1);
        if (subId == 2 ** 64 - 1) jobSubsCount = (block.chainid << 192) | (uint256(1) << 191);
        jobSubsCount += (uint256(1) << 127);
    }

    function _jobSubsResponse(
        bytes calldata _signature,
        uint256 _jobId,
        bytes calldata _output,
        uint256 _totalTime,
        uint8 _errorCode,
        uint256 _signTimestamp
    ) internal {
        // setting the last 127 bits as zero to get the jobSubsId
        uint256 jobSubsId = (_jobId >> 127) << 127;
        JobSubscription memory jobSubs = jobSubscriptions[jobSubsId];
        if (jobSubs.job.jobOwner == address(0)) revert RelaySubscriptionsInvalidJobSubscription();

        uint256 instanceCount = _jobId & ((1 << 127) - 1);
        // note: instance count for the first output should be 0
        if (instanceCount < jobSubs.currentRuns) revert RelaySubscriptionsInvalidCurrentRuns();

        // getting the virtual start time of the job subscription current run
        uint256 jobStartTime = jobSubs.job.startTime + (instanceCount * jobSubs.periodicGap);
        if (block.timestamp > jobStartTime + RELAY.OVERALL_TIMEOUT()) revert RelaySubscriptionsOverallTimeoutOver();

        // signature check
        address enclaveAddress = _verifyJobResponseSign(
            _signature,
            _jobId,
            _output,
            _totalTime,
            _errorCode,
            _signTimestamp
        );

        jobSubscriptions[jobSubsId].currentRuns = instanceCount + 1;
        jobSubscriptions[jobSubsId].lastRunTimestamp = block.timestamp;

        address gatewayOwner = RELAY.gatewayOwners(enclaveAddress);
        _releaseJobSubsEscrowAmount(jobSubsId, jobSubs.job.env, gatewayOwner, _totalTime, jobSubs.job.usdcDeposit);

        (bool success, uint256 callbackGas) = _callBackWithLimit(jobSubsId, jobSubs.job, _output, _errorCode);

        // TODO: FIXED_GAS will be different for this function
        uint256 callbackCost = (callbackGas + RELAY.FIXED_GAS()) * tx.gasprice;

        _releaseJobSubsGasCostOnSuccess(jobSubsId, gatewayOwner, jobSubs.job.callbackDeposit, callbackCost);

        emit JobSubscriptionResponded(
            jobSubsId,
            _output,
            _totalTime,
            _errorCode,
            success,
            instanceCount,
            block.timestamp
        );
    }

    function _verifyJobResponseSign(
        bytes calldata _signature,
        uint256 _jobId,
        bytes calldata _output,
        uint256 _totalTime,
        uint8 _errorCode,
        uint256 _signTimestamp
    ) internal view returns (address) {
        if (block.timestamp > _signTimestamp + RELAY.ATTESTATION_MAX_AGE()) revert RelaySubscriptionsSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                RELAY.JOB_RESPONSE_TYPEHASH(),
                _jobId,
                keccak256(_output),
                _totalTime,
                _errorCode,
                _signTimestamp
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        RELAY.allowOnlyVerified(signer);
        return signer;
    }

    function _releaseJobSubsEscrowAmount(
        uint256 _jobSubsId,
        uint8 _env,
        address _gatewayOwner,
        uint256 _totalTime,
        uint256 _usdcDeposit
    ) internal {
        uint256 gatewayPayoutUsdc;
        uint256 jobOwnerPayoutUsdc;
        unchecked {
            gatewayPayoutUsdc = _totalTime * RELAY.getJobExecutionFeePerMs(_env) + RELAY.GATEWAY_FEE_PER_JOB();
            jobOwnerPayoutUsdc = _usdcDeposit - gatewayPayoutUsdc;
        }

        // release escrow to gateway
        RELAY.TOKEN().safeTransfer(_gatewayOwner, gatewayPayoutUsdc);

        jobSubscriptions[_jobSubsId].job.usdcDeposit = jobOwnerPayoutUsdc;
    }

    function _callBackWithLimit(
        uint256 _jobId,
        Relay.Job memory _job,
        bytes calldata _output,
        uint8 _errorCode
    ) internal returns (bool success, uint callbackGas) {
        if (tx.gasprice <= _job.maxGasPrice) {
            uint startGas = gasleft();
            (success, ) = _job.callbackContract.call{gas: _job.callbackGasLimit}(
                abi.encodeWithSignature(
                    "oysterResultCall(uint256,address,bytes32,bytes,bytes,uint8)",
                    _jobId,
                    _job.jobOwner,
                    _job.codehash,
                    _job.codeInputs,
                    _output,
                    _errorCode
                )
            );
            // calculate callback cost
            callbackGas = startGas - gasleft();
        }
    }

    function _releaseJobSubsGasCostOnSuccess(
        uint256 _jobSubsId,
        address _gatewayOwner,
        uint256 _callbackDeposit,
        uint256 _callbackCost
    ) internal {
        // TODO: If paySuccess is false then deposit will be stucked forever. Find a way out.
        // transfer callback cost to gateway
        _callbackCost = _callbackCost > _callbackDeposit ? _callbackDeposit : _callbackCost;
        (bool paySuccess, ) = _gatewayOwner.call{value: _callbackCost}("");

        // transfer remaining native asset to the jobOwner
        jobSubscriptions[_jobSubsId].job.callbackDeposit -= _callbackCost;
    }

    function _depositJobSubscriptionFunds(uint256 _jobSubsId, uint256 _usdcDeposit, uint256 _callbackDeposit) internal {
        if (jobSubscriptions[_jobSubsId].job.jobOwner == address(0)) revert RelaySubscriptionsInvalidJobSubscription();

        _depositTokens(_jobSubsId, _usdcDeposit, _callbackDeposit);
    }

    function _depositTokens(uint256 _jobSubsId, uint256 _usdcDeposit, uint256 _callbackDeposit) internal {
        RELAY.TOKEN().safeTransferFrom(_msgSender(), address(this), _usdcDeposit);

        jobSubscriptions[_jobSubsId].job.usdcDeposit += _usdcDeposit;
        jobSubscriptions[_jobSubsId].job.callbackDeposit += _callbackDeposit;
        emit JobSubscriptionFundsDeposited(_jobSubsId, _msgSender(), _usdcDeposit, _callbackDeposit);
    }

    function _updateJobSubsJobParams(uint256 _jobSubsId, bytes32 _codehash, bytes calldata _codeInputs) internal {
        if (jobSubscriptions[_jobSubsId].job.jobOwner != _msgSender())
            revert RelaySubscriptionsNotJobSubscriptionOwner();

        if(jobSubscriptions[_jobSubsId].terminationTimestamp <= block.timestamp + RELAY.OVERALL_TIMEOUT())
            revert RelaySubscriptionsUpdateDeadlineOver();

        jobSubscriptions[_jobSubsId].job.codehash = _codehash;
        jobSubscriptions[_jobSubsId].job.codeInputs = _codeInputs;

        emit JobSubscriptionJobParamsUpdated(_jobSubsId, _codehash, _codeInputs);
    }

    function _updateJobSubsTerminationParams(
        uint256 _jobSubsId,
        uint256 _terminationTimestamp,
        uint256 _usdcDeposit,
        uint256 _callbackDeposit
    ) internal {
        if (jobSubscriptions[_jobSubsId].job.jobOwner != _msgSender())
            revert RelaySubscriptionsNotJobSubscriptionOwner();

        if (_terminationTimestamp < block.timestamp + RELAY.OVERALL_TIMEOUT() || _terminationTimestamp > block.timestamp + MAX_TERMINATION_DURATION)
            revert RelaySubscriptionsInvalidTerminationTimestamp();

        uint256 currentTerminationTimestamp = jobSubscriptions[_jobSubsId].terminationTimestamp;

        if(currentTerminationTimestamp <= block.timestamp + RELAY.OVERALL_TIMEOUT())
            revert RelaySubscriptionsUpdateDeadlineOver();

        // won't be executed if called from terminateJobSubscription()
        if (_terminationTimestamp > currentTerminationTimestamp) {
            _depositTokens(_jobSubsId, _usdcDeposit, _callbackDeposit);

            JobSubscription memory jobSubs = jobSubscriptions[_jobSubsId];
            uint256 remainingRuns = ((_terminationTimestamp - jobSubs.job.startTime) / jobSubs.periodicGap) + 1 - jobSubs.currentRuns;

            if (
                jobSubs.job.maxGasPrice *
                    (jobSubs.job.callbackGasLimit + RELAY.FIXED_GAS() + RELAY.CALLBACK_MEASURE_GAS()) *
                    remainingRuns >
                jobSubs.job.callbackDeposit
            ) revert RelaySubscriptionsInsufficientCallbackDeposit();

            uint256 executionFeePerMs = RELAY.getJobExecutionFeePerMs(jobSubs.job.env);
            uint256 minUsdcDeposit = (jobSubs.userTimeout * executionFeePerMs + RELAY.GATEWAY_FEE_PER_JOB()) *
                remainingRuns;
            if (jobSubs.job.usdcDeposit < minUsdcDeposit) revert RelaySubscriptionsInsufficientUsdcDeposit();
        }

        jobSubscriptions[_jobSubsId].terminationTimestamp = _terminationTimestamp;

        emit JobSubscriptionTerminationParamsUpdated(_jobSubsId, _terminationTimestamp);
    }

    function _refundJobSubsDeposits(uint256 _jobSubsId) internal {
        if (jobSubscriptions[_jobSubsId].job.jobOwner == address(0)) revert RelaySubscriptionsNotExists();

        if (block.timestamp <= jobSubscriptions[_jobSubsId].terminationTimestamp + RELAY.OVERALL_TIMEOUT())
            revert RelaySubscriptionsTerminationConditionPending();

        uint256 usdcAmount = jobSubscriptions[_jobSubsId].job.usdcDeposit;
        uint256 callbackAmount = jobSubscriptions[_jobSubsId].job.callbackDeposit;

        address _jobOwner = jobSubscriptions[_jobSubsId].job.jobOwner;
        delete jobSubscriptions[_jobSubsId];

        RELAY.TOKEN().safeTransfer(_jobOwner, usdcAmount);
        // TODO: do we need to check this bool success
        (bool success, ) = _jobOwner.call{value: callbackAmount}("");

        emit JobSubscriptionDepositsRefunded(_jobSubsId, _jobOwner, usdcAmount, callbackAmount, success);
    }

    function _terminateJobSubscription(uint256 _jobSubsId) internal {
        _updateJobSubsTerminationParams(_jobSubsId, block.timestamp + RELAY.OVERALL_TIMEOUT(), 0, 0);

        emit JobSubscriptionTerminated(_jobSubsId);
    }

    //-------------------------------- internal functions end --------------------------------//

    //-------------------------------- external functions start --------------------------------//

    /**
     * @notice Starts a subscription for periodic job execution.
     * @dev The subscription parameters are validated, and the necessary deposits(USDC+ETH) are made.
     * @param _jobSubsParams All the job subscription params required.
     */
    function startJobSubscription(
        JobSubscriptionParams memory _jobSubsParams
    ) external payable isValidEnv(_jobSubsParams.env) returns (uint256) {
        _startJobSubscription(_jobSubsParams, msg.value, _msgSender());
        return jobSubsCount;
    }

    /**
     * @notice Function for the gateway to respond to a periodic job within a subscription.
     * @dev The response includes output data, execution time, and error code.
     * @param _signature The signature of the gateway enclave verifying the job response.
     * @param _jobId The unique identifier of the job of a specific job subscription. Last 127 bits
     *               store the current runs count for which the response is being submitted.
     * @param _output The output data from the job execution.
     * @param _totalTime The total time taken for job execution in milliseconds.
     * @param _errorCode The error code returned from the job execution.
     * @param _signTimestamp The timestamp at which the response was signed by the enclave.
     */
    function jobSubsResponse(
        bytes calldata _signature,
        uint256 _jobId,
        bytes calldata _output,
        uint256 _totalTime,
        uint8 _errorCode,
        uint256 _signTimestamp
    ) external {
        _jobSubsResponse(_signature, _jobId, _output, _totalTime, _errorCode, _signTimestamp);
    }

    /**
     * @notice Deposits additional USDC and native assets(ETH) for a job subscription.
     * @dev This function allows the subscriber to top up their subscription balance.
     * @param _jobSubsId The unique identifier of the job subscription.
     * @param _usdcDeposit The amount of USDC to be deposited.
     */
    function depositJobSubscriptionFunds(uint256 _jobSubsId, uint256 _usdcDeposit) external payable {
        _depositJobSubscriptionFunds(_jobSubsId, _usdcDeposit, msg.value);
    }

    /**
     * @notice Updates the job parameters for a specific job subscription.
     * @dev This function allows the subscriber to modify the job execution code and input parameters
     *      for an existing subscription. The new parameters will be used in subsequent
     *      job executions within the subscription.
     * @param _jobSubsId The unique identifier of the job subscription to be updated.
     * @param _codehash The new transaction hash storing the code that will be executed by the enclave.
     * @param _codeInputs The new input parameters for the code to be executed.
     */
    function updateJobSubsJobParams(uint256 _jobSubsId, bytes32 _codehash, bytes calldata _codeInputs) external {
        _updateJobSubsJobParams(_jobSubsId, _codehash, _codeInputs);
    }

    /**
     * @notice Updates the termination parameters for a specific job subscription.
     * @dev This function allows the subscriber to modify the termination time associated with an
     *      existing job subscription. It means user might have to deposit additional USDC+ETH if
     *      termination time is increased, and enought funds weren't deposited initially.
     * @param _jobSubsId The unique identifier of the job subscription to be updated.
     * @param _terminationTimestamp The new timestamp (in seconds) when the job subscription will terminate.
     * @param _usdcDeposit The additional amount of USDC to be deposited.
     */
    function updateJobSubsTerminationParams(
        uint256 _jobSubsId,
        uint256 _terminationTimestamp,
        uint256 _usdcDeposit
    ) external payable {
        _updateJobSubsTerminationParams(_jobSubsId, _terminationTimestamp, _usdcDeposit, msg.value);
    }

    /**
     * @notice Allows job subscription remaining fund withdrawal once the termination condition is reached.
     * @dev This function deletes the job subscription data and refunds the deposited USDC and ETH, if any.
     * param _jobSubsId The unique identifier of the job subscription.
     */
    function refundJobSubsDeposits(uint256 _jobSubsId) external {
        _refundJobSubsDeposits(_jobSubsId);
    }

    /**
     * @notice For advance termination of job subscription.
     * param _jobSubsId The unique identifier of the job subscription.
     */
    function terminateJobSubscription(uint256 _jobSubsId) external {
        _terminateJobSubscription(_jobSubsId);
    }

    //-------------------------------- external functions end --------------------------------//

    //-------------------------------- Job Subscription End --------------------------------//
}
