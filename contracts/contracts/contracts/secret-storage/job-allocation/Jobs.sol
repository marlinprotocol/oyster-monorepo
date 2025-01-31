// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../SecretStore.sol";
import "../SecretManager.sol";
import "../TeeManager.sol";
import "../Executors.sol";

/**
 * @title Jobs Contract
 * @dev This contract manages job creation, execution, and reward distribution.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract Jobs is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable // public upgrade
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    /// @notice Thrown when the staking token address is zero.
    error JobsZeroAddressStakingToken();
    /// @notice Thrown when the USDC token address is zero.
    error JobsZeroAddressUsdcToken();

    /**
     * @dev Initializes the logic contract without any admins and safeguards against a potential takeover.
     * @param _stakingToken The address of the staking token contract(POND).
     * @param _usdcToken The address of the USDC token contract.
     * @param _signMaxAge The maximum age of a valid signature in seconds.
     * @param _executionBufferTime The buffer time allowed for job execution in milliseconds.
     * @param _noOfNodesToSelect The number of executor nodes to select for a job.
     * @param _stakingPaymentPoolAddress The address of the staking payment pool.
     * @param _usdcPaymentPoolAddress The address of the USDC payment pool.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        IERC20 _stakingToken,
        IERC20 _usdcToken,
        uint256 _signMaxAge,
        uint256 _executionBufferTime,
        uint256 _noOfNodesToSelect,
        address _stakingPaymentPoolAddress,
        address _usdcPaymentPoolAddress
    ) {
        _disableInitializers();

        if (address(_stakingToken) == address(0)) revert JobsZeroAddressStakingToken();
        STAKING_TOKEN = _stakingToken;

        if (address(_usdcToken) == address(0)) revert JobsZeroAddressUsdcToken();
        USDC_TOKEN = _usdcToken;

        SIGN_MAX_AGE = _signMaxAge;
        EXECUTION_BUFFER_TIME = _executionBufferTime;
        NO_OF_NODES_TO_SELECT = _noOfNodesToSelect;

        STAKING_PAYMENT_POOL = _stakingPaymentPoolAddress;
        USDC_PAYMENT_POOL = _usdcPaymentPoolAddress;
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

    /// @notice Thrown when the admin address is zero.
    error JobsZeroAddressAdmin();

    /**
     * @dev Initializes the contract with the specified admin address.
     * @param _admin The address of the admin.
     */
    function initialize(address _admin) public initializer {
        if (_admin == address(0)) revert JobsZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable STAKING_TOKEN;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable USDC_TOKEN;

    /// @notice Maximum age of a valid signature, in seconds.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SIGN_MAX_AGE;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable EXECUTION_BUFFER_TIME;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable NO_OF_NODES_TO_SELECT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address public immutable STAKING_PAYMENT_POOL;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address public immutable USDC_PAYMENT_POOL;

    TeeManager public TEE_MANAGER;

    Executors public EXECUTORS;

    SecretStore public SECRET_STORE;

    SecretManager public SECRET_MANAGER;

    //-------------------------------- Execution Env start --------------------------------//

    struct ExecutionEnv {
        // The fee paid to executors per millisecond.
        uint256 executionFeePerMs;
        // The staking reward per millisecond, paid to the payment pool.
        uint256 stakingRewardPerMs;
    }

    mapping(uint8 => ExecutionEnv) public executionEnv;

    /**
     * @notice Emitted when a new execution environment support is added globally.
     * @param env The execution environment added.
     * @param executionFeePerMs The fee paid to executors per millisecond.
     * @param stakingRewardPerMs The staking reward per millisecond, paid to the payment pool.
     */
    event GlobalEnvAdded(uint8 indexed env, uint256 executionFeePerMs, uint256 stakingRewardPerMs);

    /**
     * @notice Emitted when an existing execution environment support is removed globally.
     * @param env The execution environment removed.
     */
    event GlobalEnvRemoved(uint8 indexed env);

    /// @notice Thrown when the execution environment is already supported globally.
    error JobsGlobalEnvAlreadySupported();
    /// @notice Thrown when the execution environment is already unsupported globally.
    error JobsGlobalEnvAlreadyUnsupported();

    //------------------------------ internal functions start ------------------------------//

    function _addGlobalEnv(uint8 _env, uint256 _executionFeePerMs, uint256 _stakingRewardPerMs) internal {
        executionEnv[_env] = ExecutionEnv({
            executionFeePerMs: _executionFeePerMs,
            stakingRewardPerMs: _stakingRewardPerMs
        });
        EXECUTORS.initTree(_env);
        SECRET_STORE.initTree(_env);

        emit GlobalEnvAdded(_env, _executionFeePerMs, _stakingRewardPerMs);
    }

    function _removeGlobalEnv(uint8 _env) internal {
        delete executionEnv[_env];
        EXECUTORS.removeTree(_env);
        SECRET_STORE.removeTree(_env);

        emit GlobalEnvRemoved(_env);
    }

    //------------------------------ internal functions end --------------------------------//

    //------------------------------ external functions start ------------------------------//

    function setTeeManager(address _teeManagerAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        TEE_MANAGER = TeeManager(_teeManagerAddress);
    }

    function setExecutors(address _executorsAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        EXECUTORS = Executors(_executorsAddress);
    }

    function setSecretStore(address _secretStoreAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        SECRET_STORE = SecretStore(_secretStoreAddress);
    }

    function setSecretManager(address _secretManagerAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        SECRET_MANAGER = SecretManager(_secretManagerAddress);
    }

    /**
     * @notice Adds global support for a new execution environment.
     * @dev Can only be called by an account with the `DEFAULT_ADMIN_ROLE`.
            It also initializes a new executor nodes tree for the environment.
     * @param _env The execution environment to be added.
     * @param _executionFeePerMs The fee paid to executors per millisecond.
     * @param _stakingRewardPerMs The staking reward per millisecond, paid to the payment pool.
     */
    function addGlobalEnv(
        uint8 _env,
        uint256 _executionFeePerMs,
        uint256 _stakingRewardPerMs
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _addGlobalEnv(_env, _executionFeePerMs, _stakingRewardPerMs);
    }

    /**
     * @notice Removes global support for an existing execution environment.
     * @dev Can only be called by an account with the `DEFAULT_ADMIN_ROLE`.
     * @param _env The execution environment to be removed.
     */
    function removeGlobalEnv(uint8 _env) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _removeGlobalEnv(_env);
    }

    function getJobExecutionFeePerMs(uint8 _env) public view returns (uint256) {
        return executionEnv[_env].executionFeePerMs + executionEnv[_env].stakingRewardPerMs;
    }

    //------------------------------ external functions end -------------------------------//

    //--------------------------------- Execution Env end ---------------------------------//

    //-------------------------------- Job start --------------------------------//

    struct Job {
        uint256 deadline; // in milliseconds
        uint256 execStartTime;
        uint256 executionTime; // it stores the execution time for first output submitted only (in milliseconds)
        address jobOwner;
        uint8 env;
        uint8 outputCount;
        address[] selectedExecutors;
        mapping(address => bool) hasExecutedJob; // selectedExecutor => hasExecuted
    }

    // jobKey => Job
    Job[] public jobs;

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.Jobs"),
                keccak256("1")
            )
        );
    bytes32 private constant SUBMIT_OUTPUT_TYPEHASH =
        keccak256("SubmitOutput(uint256 jobId,bytes output,uint256 totalTime,uint8 errorCode,uint256 signTimestamp)");

    /**
     * @dev Emitted when a new job is created.
     * @param jobId The ID of the job created.
     * @param env The execution environment for the job.
     * @param jobOwner The address of the job owner.
     * @param codehash The transaction hash storing the job code.
     * @param codeInputs The inputs to the job code.
     * @param deadline The deadline for the job in milliseconds.
     * @param selectedExecutors The selected executors for the job.
     */
    event JobCreated(
        uint256 indexed jobId,
        uint8 indexed env,
        address indexed jobOwner,
        uint256 secretId,
        bytes32 codehash,
        bytes codeInputs,
        uint256 deadline, // in milliseconds
        address[] selectedExecutors
    );

    /**
     * @dev Emitted when an output is submitted for a job.
     * @param jobId The ID of the job.
     * @param output The output data.
     * @param totalTime The total time taken to execute the job in milliseconds.
     * @param errorCode The error code associated with the job execution.
     * @param outputCount The number of outputs submitted for the job.
     */
    event JobResponded(
        uint256 indexed jobId,
        address indexed executor,
        bytes output,
        uint256 totalTime,
        uint8 errorCode,
        uint8 outputCount
    );

    /**
     * @dev Emitted when the job result callback is called.
     * @param jobId The ID of the job.
     * @param callback_success Boolean indicating if the callback was successful.
     */
    event JobResultCallbackCalled(uint256 indexed jobId, bool callback_success);

    /**
     * @dev Emitted when the job failure callback is called.
     * @param jobId The ID of the job.
     * @param callback_success Boolean indicating if the callback was successful.
     */
    event JobFailureCallbackCalled(uint256 indexed jobId, bool callback_success);

    /// @notice Thrown when the signature is too old.
    error JobsSignatureTooOld();
    /// @notice Thrown when the job execution time has passed.
    error JobsExecutionTimeOver();
    /// @notice Thrown when the executor is not selected for the job.
    error JobsNotSelectedExecutor();
    /// @notice Thrown when the executor has already submitted output for the job.
    error JobsExecutorAlreadySubmittedOutput();
    /// @notice Thrown when there are unavailable resources to execute the job.
    error JobsUnavailableResources();

    //-------------------------------- internal functions start --------------------------------//

    function _createJob(
        uint8 _env,
        uint256 _secretId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline, // in milliseconds
        // TODO: need to add real job owner(when the gatewayJobs calls this function, then need to delegate to it)
        address _jobOwner
    ) internal returns (uint256 jobId) {
        // 1. Validate secretId (secretId should exist and owner should be msg sender)
        // 2. Check if the secret is acknowledged by all the selected stores
        // 3. Get the no. of selected stores(=L)
        address[] memory selectedStores;
        if(_secretId != 0)
            selectedStores = SECRET_MANAGER.verifyUserAndGetSelectedStores(_secretId, _jobOwner);

        // 4. if L >= N, then select N stores as executors(stake based selection)
        // 5. if 1 < L < N, then select all the L stores and other (N-L) via selection algo
        // 6. if L = 0, then select via selection algo
        // 7. While selecting among the stores, update their activeJobs count
        address[] memory selectedNodes = EXECUTORS.selectExecutionNodes(_env, selectedStores, NO_OF_NODES_TO_SELECT);

        // deposit escrow amount(USDC)
        USDC_TOKEN.safeTransferFrom(_jobOwner, address(this), _deadline * getJobExecutionFeePerMs(_env));

        jobId = _create(_codehash, _codeInputs, _deadline, _jobOwner, _env, _secretId, selectedNodes);
    }


    function _create(
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline, // in milliseconds
        address _jobOwner,
        uint8 _env,
        uint256 _secretId,
        address[] memory _selectedNodes
    ) internal returns (uint256 jobId) {
        // create a struct
        jobId = jobs.length;
        jobs.push();
        jobs[jobId].deadline = _deadline;
        jobs[jobId].execStartTime = block.timestamp;
        jobs[jobId].jobOwner = _jobOwner;
        jobs[jobId].env = _env;
        jobs[jobId].selectedExecutors = _selectedNodes;

        emit JobCreated(jobId, _env, _jobOwner, _secretId, _codehash, _codeInputs, _deadline, _selectedNodes);
    }

    function _submitOutput(
        bytes memory _signature,
        uint256 _jobId,
        bytes memory _output,
        uint256 _totalTime,
        uint8 _errorCode,
        uint256 _signTimestamp
    ) internal {
        if (
            (block.timestamp * 1000) >
            (jobs[_jobId].execStartTime * 1000) + jobs[_jobId].deadline + (EXECUTION_BUFFER_TIME * 1000)
        ) revert JobsExecutionTimeOver();

        // signature check
        address enclaveAddress = _verifyOutputSign(_signature, _jobId, _output, _totalTime, _errorCode, _signTimestamp);

        if (!_isJobExecutor(_jobId, enclaveAddress)) revert JobsNotSelectedExecutor();
        if (jobs[_jobId].hasExecutedJob[enclaveAddress]) revert JobsExecutorAlreadySubmittedOutput();

        EXECUTORS.releaseExecutor(enclaveAddress);
        jobs[_jobId].hasExecutedJob[enclaveAddress] = true;

        uint8 outputCount = ++jobs[_jobId].outputCount;
        _totalTime = _totalTime > jobs[_jobId].deadline ? jobs[_jobId].deadline : _totalTime;
        if (outputCount == 1) jobs[_jobId].executionTime = _totalTime;

        // on reward distribution, 1st output executor node gets max reward
        // reward ratio - 4:3:2
        _transferRewardPayout(_jobId, outputCount, enclaveAddress);

        // TODO: add callback gas
        if (outputCount == 1) {
            address jobOwner = jobs[_jobId].jobOwner;
            (bool success, ) = jobOwner.call(
                abi.encodeWithSignature(
                    "oysterResultCall(uint256,bytes,uint8,uint256)",
                    _jobId,
                    _output,
                    _errorCode,
                    _totalTime
                )
            );
            emit JobResultCallbackCalled(_jobId, success);
        }
        emit JobResponded(_jobId, enclaveAddress, _output, _totalTime, _errorCode, outputCount);
    }

    function _verifyOutputSign(
        bytes memory _signature,
        uint256 _jobId,
        bytes memory _output,
        uint256 _totalTime,
        uint8 _errorCode,
        uint256 _signTimestamp
    ) internal view returns (address) {
        if (block.timestamp > _signTimestamp + SIGN_MAX_AGE) revert JobsSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(SUBMIT_OUTPUT_TYPEHASH, _jobId, keccak256(_output), _totalTime, _errorCode, _signTimestamp)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        TEE_MANAGER.allowOnlyVerified(signer);
        return signer;
    }

    function _transferRewardPayout(uint256 _jobId, uint256 _outputCount, address _enclaveAddress) internal {
        address owner = TEE_MANAGER.getTeeNodeOwner(_enclaveAddress);
        uint256 executionTime = jobs[_jobId].executionTime;
        address jobOwner = jobs[_jobId].jobOwner;
        uint256 deadline = jobs[_jobId].deadline;
        uint256 executionFeePerMs = executionEnv[jobs[_jobId].env].executionFeePerMs;
        uint256 stakingRewardPerMs = executionEnv[jobs[_jobId].env].stakingRewardPerMs;
        // TODO: how's the execution fee dependent on reputation
        uint256 executorsFee = executionTime * executionFeePerMs;
        // for first output
        if (_outputCount == 1) {
            // transfer payout to executor
            USDC_TOKEN.safeTransfer(owner, (executorsFee * 4) / 9);
            // transfer payout to payment pool
            USDC_TOKEN.safeTransfer(USDC_PAYMENT_POOL, executionTime * stakingRewardPerMs);
            // transfer to job owner
            USDC_TOKEN.safeTransfer(jobOwner, (deadline - executionTime) * (executionFeePerMs + stakingRewardPerMs));

            // TODO: increase reputation logic
            EXECUTORS.increaseReputation(_enclaveAddress, 10);
        }
        // for second output
        else if (_outputCount == 2) {
            // transfer payout to executor
            USDC_TOKEN.safeTransfer(owner, executorsFee / 3);
            // TODO: decrease reputation logic
            EXECUTORS.decreaseReputation(_enclaveAddress, 5);
        }
        // for 3rd output
        else {
            // transfer payout to executor
            USDC_TOKEN.safeTransfer(owner, executorsFee - ((executorsFee * 4) / 9) - (executorsFee / 3));
            // TODO: decrease reputation logic
            EXECUTORS.decreaseReputation(_enclaveAddress, 5);
            // cleanup job data after 3rd output submitted
            _cleanJobData(_jobId);
        }
    }

    function _cleanJobData(uint256 _jobId) internal {
        uint256 len = jobs[_jobId].selectedExecutors.length;
        for (uint256 index = 0; index < len; index++) {
            address enclaveAddress = jobs[_jobId].selectedExecutors[index];
            delete jobs[_jobId].hasExecutedJob[enclaveAddress];
        }
        delete jobs[_jobId].selectedExecutors;
        delete jobs[_jobId];
    }

    function _isJobExecutor(uint256 _jobId, address _enclaveAddress) internal view returns (bool) {
        address[] memory selectedNodes = jobs[_jobId].selectedExecutors;
        uint256 len = selectedNodes.length;
        for (uint256 index = 0; index < len; index++) {
            if (selectedNodes[index] == _enclaveAddress) return true;
        }
        return false;
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start --------------------------------//

    /**
     * @notice Creates a new job with the specified parameters.
     * @param _env The execution environment supported by the enclave.
     * @param _secretId The unique id assigned to the stored secret.
     * @param _codehash The transaction hash storing the code in calldata, that needs to be executed.
     * @param _codeInputs The inputs to the job code.
     * @param _deadline The deadline for the job in milliseconds.
     * @return jobId The ID of the job created.
     */
    function createJob(
        uint8 _env,
        uint256 _secretId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline // in milliseconds
    ) external returns (uint256) {
        return _createJob(_env, _secretId, _codehash, _codeInputs, _deadline, _msgSender());
    }

    /**
     * @notice Submits the output for a job.
     * @param _signature The signature of the executor.
     * @param _jobId The ID of the job.
     * @param _output The output data.
     * @param _totalTime The total time taken to execute the job in milliseconds.
     * @param _errorCode The error code associated with the job execution.
     * @param _signTimestamp The timestamp of the signature.
     */
    function submitOutput(
        bytes memory _signature,
        uint256 _jobId,
        bytes memory _output,
        uint256 _totalTime,
        uint8 _errorCode,
        uint256 _signTimestamp
    ) external {
        _submitOutput(_signature, _jobId, _output, _totalTime, _errorCode, _signTimestamp);
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- Job end --------------------------------//

    //-------------------------------- Timeout start --------------------------------//

    /**
     * @notice Emitted when an executor is slashed due to execution timeout.
     * @param jobId The ID of the job.
     * @param enclaveAddress The address of the slashed executor.
     */
    event SlashedOnExecutionTimeout(uint256 indexed jobId, address indexed enclaveAddress);

    /// @notice Thrown when the job ID is invalid.
    error JobsInvalidJob();
    /// @notice Thrown when the job deadline has not yet passed.
    error JobsDeadlineNotOver();

    //-------------------------------- internal functions start ----------------------------------//

    function _slashOnExecutionTimeout(uint256 _jobId) internal {
        if (jobs[_jobId].execStartTime == 0) revert JobsInvalidJob();

        // check for time
        if (
            (block.timestamp * 1000) <=
            (jobs[_jobId].execStartTime * 1000) + jobs[_jobId].deadline + (EXECUTION_BUFFER_TIME * 1000)
        ) revert JobsDeadlineNotOver();

        address jobOwner = jobs[_jobId].jobOwner;
        uint8 outputCount = jobs[_jobId].outputCount;
        bool isNoOutputSubmitted = (outputCount == 0);
        uint256 deadline = jobs[_jobId].deadline;
        uint256 executionTime = jobs[_jobId].executionTime;

        _releaseEscrowAmount(jobs[_jobId].env, jobOwner, outputCount, deadline, executionTime);

        // slash Execution node
        uint256 len = jobs[_jobId].selectedExecutors.length;
        uint256 slashAmount = 0;
        for (uint256 index = 0; index < len; index++) {
            address enclaveAddress = jobs[_jobId].selectedExecutors[index];

            if (!jobs[_jobId].hasExecutedJob[enclaveAddress]) {
                slashAmount += EXECUTORS.slashExecutor(enclaveAddress);
                emit SlashedOnExecutionTimeout(_jobId, enclaveAddress);
            }
            delete jobs[_jobId].hasExecutedJob[enclaveAddress];
        }

        delete jobs[_jobId].selectedExecutors;
        delete jobs[_jobId];

        if (isNoOutputSubmitted) {
            // transfer the slashed amount to job owner
            STAKING_TOKEN.safeTransfer(jobOwner, slashAmount);
            // TODO: add gas limit
            (bool success, ) = jobOwner.call(
                abi.encodeWithSignature("oysterFailureCall(uint256,uint256)", _jobId, slashAmount)
            );
            emit JobFailureCallbackCalled(_jobId, success);
        } else {
            // transfer the slashed amount to payment pool
            STAKING_TOKEN.safeTransfer(STAKING_PAYMENT_POOL, slashAmount);
        }
    }

    function _releaseEscrowAmount(
        uint8 _env,
        address _jobOwner,
        uint8 _outputCount,
        uint256 _deadline,
        uint256 _executionTime
    ) internal {
        uint256 executionFeePerMs = executionEnv[_env].executionFeePerMs;
        uint256 stakingRewardPerMs = executionEnv[_env].stakingRewardPerMs;
        uint256 jobOwnerDeposit = _deadline * (executionFeePerMs + stakingRewardPerMs);
        uint256 executorsFee = _executionTime * executionFeePerMs;
        if (_outputCount == 0) {
            // transfer back the whole escrow amount to gateway if no output submitted
            USDC_TOKEN.safeTransfer(_jobOwner, jobOwnerDeposit);
        } else if (_outputCount == 1) {
            // Note: No need to pay job owner the remaining, it has already been paid when first output is submitted
            // transfer the expected reward of second and third submitter to payment pool
            USDC_TOKEN.safeTransfer(USDC_PAYMENT_POOL, executorsFee - (executorsFee * 4) / 9);
        }
        // if _outputCount = 2
        else {
            // Note: No need to pay job owner the remaining, it has already been paid when first output is submitted
            // transfer the expected reward of third submitter to payment pool
            USDC_TOKEN.safeTransfer(USDC_PAYMENT_POOL, executorsFee - ((executorsFee * 4) / 9) - (executorsFee / 3));
        }
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    /**
     * @notice Slashes executors for a job if the execution has timed out.
     * @dev This function is called externally to trigger the slashing mechanism for a
     *      job when the execution time has exceeded the allowed deadline plus buffer time.
     * @param _jobId The ID of the job for which executors are to be slashed.
     */
    function slashOnExecutionTimeout(uint256 _jobId) external {
        _slashOnExecutionTimeout(_jobId);
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- Timeout end --------------------------------//

    /**
     * @notice Retrieves the list of executors selected for a specific job.
     * @param _jobId The ID of the job for which to retrieve the selected executors.
     * @return An array of addresses representing the executors selected for the job.
     */
    function getSelectedExecutors(uint256 _jobId) external view returns (address[] memory) {
        return jobs[_jobId].selectedExecutors;
    }
}
