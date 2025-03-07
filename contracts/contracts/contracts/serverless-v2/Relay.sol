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
import "../AttestationAutherUpgradeable.sol";
import "../interfaces/IAttestationVerifier.sol";

/**
 * @title Relay Contract
 * @notice This contract manages serverless job relay and gateway registration functionalities.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract Relay is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable, // public upgrade
    AttestationAutherUpgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    /// @notice Error for when zero address token is provided.
    error RelayInvalidToken();
    /// @notice Error for when global timeout values are invalid (minimum timeout is not less than maximum timeout).
    error RelayInvalidGlobalTimeouts();

    /**
     * @notice Initializes the logic contract with essential parameters and disables further
     * initializations of the logic contract.
     * @param attestationVerifier The contract responsible for verifying attestations.
     * @param maxAge The maximum age for attestations and signature, in seconds.
     * @param _token The ERC20 token used for payments and deposits.
     * @param _globalMinTimeout The minimum timeout value for jobs.
     * @param _globalMaxTimeout The maximum timeout value for jobs. This refers to the max time for the executor to execute the job.
     * @param _overallTimeout The overall timeout value for job execution. This refers to the max time for the complete lifecycle of the job request on-chain.
     * @param _gatewayFeePerJob The fixed fee per job for the gateway(in USDC).
     * @param _fixedGas The fixed gas amount for job responses without callback.
     * @param _callbackMeasureGas The gas amount used for measuring callback gas.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        IERC20 _token,
        uint256 _globalMinTimeout, // in milliseconds
        uint256 _globalMaxTimeout, // in milliseconds
        uint256 _overallTimeout,
        uint256 _gatewayFeePerJob,
        uint256 _fixedGas,
        uint256 _callbackMeasureGas
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if (address(_token) == address(0)) revert RelayInvalidToken();
        TOKEN = _token;

        if (_globalMinTimeout >= _globalMaxTimeout) revert RelayInvalidGlobalTimeouts();
        GLOBAL_MIN_TIMEOUT = _globalMinTimeout;
        GLOBAL_MAX_TIMEOUT = _globalMaxTimeout;
        OVERALL_TIMEOUT = _overallTimeout;

        GATEWAY_FEE_PER_JOB = _gatewayFeePerJob;

        FIXED_GAS = _fixedGas;
        CALLBACK_MEASURE_GAS = _callbackMeasureGas;
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
    error RelayZeroAddressAdmin();

    /**
     * @notice Initializes the Relay contract with the specified admin and enclave images.
     * @param _admin The address to be granted the DEFAULT_ADMIN_ROLE.
     * @param _images The initial enclave images to be whitelisted.
     */
    function initialize(address _admin, EnclaveImage[] memory _images) public initializer {
        if (_admin == address(0)) revert RelayZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(_images);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        jobCount = block.chainid << 192;
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GLOBAL_MIN_TIMEOUT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GLOBAL_MAX_TIMEOUT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable OVERALL_TIMEOUT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GATEWAY_FEE_PER_JOB;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable FIXED_GAS; // Should equal to gas of jobResponse without callback - gas refunds

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable CALLBACK_MEASURE_GAS; // gas consumed for measurement of callback gas

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.Relay"),
                keccak256("1")
            )
        );

    //-------------------------------- Admin methods start --------------------------------//

    /**
     * @notice Whitelist an enclave image for use by gateways.
     * @param PCR0 The first PCR value of the enclave image.
     * @param PCR1 The second PCR value of the enclave image.
     * @param PCR2 The third PCR value of the enclave image.
     * @return Computed image id and true if the image was freshly whitelisted, false otherwise.
     */
    function whitelistEnclaveImage(
        bytes calldata PCR0,
        bytes calldata PCR1,
        bytes calldata PCR2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bytes32, bool) {
        return _whitelistEnclaveImage(EnclaveImage(PCR0, PCR1, PCR2));
    }

    /**
     * @notice Revoke an enclave image.
     * @param imageId Image to be revoked.
     * @return true if the image was freshly revoked, false otherwise.
     */
    function revokeEnclaveImage(bytes32 imageId) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _revokeEnclaveImage(imageId);
    }

    //-------------------------------- Admin methods end ----------------------------------//

    //-------------------------------- Execution Env start --------------------------------//

    struct ExecutionEnv {
        // The fee per millisecond for job execution(in USDC).
        uint256 executionFeePerMs;
        bool status;
    }

    mapping(uint8 => ExecutionEnv) public executionEnv;

    /**
     * @notice Emitted when a new execution environment support is added globally.
     * @param env The execution environment added.
     * @param executionFeePerMs The fee per millisecond for job execution(in USDC).
     */
    event GlobalEnvAdded(uint8 indexed env, uint256 executionFeePerMs);

    /**
     * @notice Emitted when an existing execution environment support is removed globally.
     * @param env The execution environment removed.
     */
    event GlobalEnvRemoved(uint8 indexed env);

    /// @notice Thrown when the provided execution environment is not supported globally.
    error RelayEnvUnsupported();
    /// @notice Thrown when the execution environment is already supported globally.
    error RelayGlobalEnvAlreadySupported();
    /// @notice Thrown when the execution environment is already unsupported globally.
    error RelayGlobalEnvAlreadyUnsupported();

    modifier isValidEnv(uint8 _env) {
        if (!executionEnv[_env].status) revert RelayEnvUnsupported();
        _;
    }

    //-------------------------------- internal functions start --------------------------------//

    function _addGlobalEnv(uint8 _env, uint256 _executionFeePerMs) internal {
        if (executionEnv[_env].status) revert RelayGlobalEnvAlreadySupported();

        executionEnv[_env] = ExecutionEnv({executionFeePerMs: _executionFeePerMs, status: true});

        emit GlobalEnvAdded(_env, _executionFeePerMs);
    }

    function _removeGlobalEnv(uint8 _env) internal {
        if (!executionEnv[_env].status) revert RelayGlobalEnvAlreadyUnsupported();

        delete executionEnv[_env];

        emit GlobalEnvRemoved(_env);
    }

    //-------------------------------- internal functions end --------------------------------//

    //-------------------------------- external functions start --------------------------------//

    /**
     * @notice Adds global support for a new execution environment.
     * @dev Can only be called by an account with the `DEFAULT_ADMIN_ROLE`.
            It also initializes a new executor nodes tree for the environment.
     * @param _env The execution environment to be added.
     * @param _executionFeePerMs The fee per millisecond for job execution(in USDC).
     */
    function addGlobalEnv(uint8 _env, uint256 _executionFeePerMs) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _addGlobalEnv(_env, _executionFeePerMs);
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
        return executionEnv[_env].executionFeePerMs;
    }

    function isEnvSupported(uint8 _env) public view returns (bool) {
        return executionEnv[_env].status;
    }

    //-------------------------------- external functions end --------------------------------//

    //--------------------------------- Execution Env end ---------------------------------//

    //-------------------------------- Gateway start --------------------------------//

    // enclaveAddress => owner
    mapping(address => address) public gatewayOwners;

    bytes32 private constant REGISTER_TYPEHASH = keccak256("Register(address owner,uint256 signTimestamp)");

    /**
     * @notice Emitted when a gateway is successfully registered.
     * @param owner The address of the owner of the enclave.
     * @param enclaveAddress The address of the enclave being registered.
     */
    event GatewayRegistered(address indexed owner, address indexed enclaveAddress);

    /**
     * @notice Emitted when a gateway is successfully deregistered.
     * @param enclaveAddress The address of the enclave being deregistered.
     */
    event GatewayDeregistered(address indexed enclaveAddress);

    /// @notice Error for when the gateway with a given enclave address is already registered.
    error RelayGatewayAlreadyExists();
    /// @notice Error for when the msg.sender isn't the gateway owner.
    error RelayInvalidGatewayOwner();
    /// @notice Error for when the signature has expired.
    error RelaySignatureTooOld();
    /// @notice Error for when a given signature hasn't been signed by the gateway enclave.
    error RelayInvalidSigner();

    //-------------------------------- internal functions start --------------------------------//

    function _registerGateway(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        bytes calldata _signature,
        uint256 _signTimestamp,
        address _owner
    ) internal {
        // attestation verification
        _verifyEnclaveKey(_attestationSignature, _attestation);

        address enclaveAddress = _pubKeyToAddress(_attestation.enclavePubKey);

        // signature verification
        _verifyRegisterSign(_owner, _signTimestamp, _signature, enclaveAddress);

        if (gatewayOwners[enclaveAddress] != address(0)) revert RelayGatewayAlreadyExists();
        gatewayOwners[enclaveAddress] = _owner;

        emit GatewayRegistered(_owner, enclaveAddress);
    }

    function _verifyRegisterSign(
        address _owner,
        uint256 _signTimestamp,
        bytes calldata _signature,
        address _enclaveAddress
    ) internal view {
        if (block.timestamp > _signTimestamp + ATTESTATION_MAX_AGE) revert RelaySignatureTooOld();

        bytes32 hashStruct = keccak256(abi.encode(REGISTER_TYPEHASH, _owner, _signTimestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if (signer != _enclaveAddress) revert RelayInvalidSigner();
    }

    function _deregisterGateway(address _enclaveAddress, address _owner) internal {
        if (gatewayOwners[_enclaveAddress] != _owner) revert RelayInvalidGatewayOwner();

        _revokeEnclaveKey(gatewayOwners[_enclaveAddress]);
        delete gatewayOwners[_enclaveAddress];

        emit GatewayDeregistered(_enclaveAddress);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start --------------------------------//

    /**
     * @notice Registers a gateway by providing attestation and signature details.
     * @dev This function verifies the enclave key and signature before registering the gateway.
     * @param _attestationSignature The attestation signature from the enclave.
     * @param _attestation The attestation details including the enclave public key.
     * @param _signature The signature from the enclave for registering the gateway.
     * @param _signTimestamp The timestamp at which the enclave signed the registration.
     */
    function registerGateway(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        bytes calldata _signature,
        uint256 _signTimestamp
    ) external {
        _registerGateway(_attestationSignature, _attestation, _signature, _signTimestamp, _msgSender());
    }

    /**
     * @notice Deregisters a gateway by its enclave address.
     * @dev This function checks the caller's ownership of the gateway before deregistration.
     * @param _enclaveAddress The address of the enclave to be deregistered.
     */
    function deregisterGateway(address _enclaveAddress) external {
        _deregisterGateway(_enclaveAddress, _msgSender());
    }

    /**
     * @notice Ensures that the specified enclave address is verified.
     * @param _enclaveAddress The address of the enclave to verify.
     */
    function allowOnlyVerified(address _enclaveAddress) external view {
        _allowOnlyVerified(_enclaveAddress);
    }

    //-------------------------------- external functions end ---------------------------//

    //-------------------------------- Gateway End --------------------------------//

    //-------------------------------- Job start --------------------------------//

    struct Job {
        uint256 startTime;
        uint256 maxGasPrice;
        uint256 usdcDeposit;
        uint256 callbackDeposit;
        uint256 callbackGasLimit;
        address jobOwner;
        address callbackContract;
        uint8 env;
        bytes32 codehash;
        bytes codeInputs;
    }

    mapping(uint256 => Job) public jobs;

    /**
     * @notice Tracks the jobs count.
     * @dev It follows this scheme -
     *      | Chain ID (64 bit) | 0 (1 bit) | job_id (191 bits) |
     *      First 64 bits represent the chainId.
     *      65th bit is fixed as 0, which represents an individual job.
     *      Last 191 bits refers to the job id, and increments each time a new job is relayed.
     *      If job_id reaches its max value, then we reset the job_id to zero.
     */
    uint256 public jobCount;

    bytes32 public constant JOB_RESPONSE_TYPEHASH =
        keccak256("JobResponse(uint256 jobId,bytes output,uint256 totalTime,uint8 errorCode,uint256 signTimestamp)");

    /**
     * @notice Emitted when a job is successfully relayed.
     * @param jobId The unique identifier of the job.
     * @param env The execution environment for the job.
     * @param codehash The transaction hash storing the code to be executed.
     * @param codeInputs The inputs for the code execution.
     * @param userTimeout The timeout specified by the user for the job.
     * @param maxGasPrice The maximum gas price allowed for the job response and callback method.
     * @param usdcDeposit The USDC deposit provided for the job.
     * @param callbackDeposit The callback deposit provided for the job.
     * @param refundAccount The address where the slashed token will be sent on common chain.
     * @param callbackContract The address of the callback contract.
     * @param startTime The timestamp when the job was started.
     * @param callbackGasLimit The gas limit for the callback execution.
     * @param jobOwner The address of the job owner.
     */
    event JobRelayed(
        uint256 indexed jobId,
        uint8 indexed env,
        bytes32 codehash,
        bytes codeInputs,
        uint256 userTimeout, // in milliseconds
        uint256 maxGasPrice,
        uint256 usdcDeposit,
        uint256 callbackDeposit,
        address refundAccount,
        address callbackContract,
        uint256 startTime,
        uint256 callbackGasLimit,
        address jobOwner
    );

    /**
     * @notice Emitted when a job responds with its output.
     * @param jobId The unique identifier of the job.
     * @param output The output from the job execution.
     * @param totalTime The total time taken for the job execution.
     * @param errorCode The error code if the job failed.
     * @param success A boolean indicating if the callback was successful.
     */
    event JobResponded(uint256 indexed jobId, bytes output, uint256 totalTime, uint256 errorCode, bool success);

    /**
     * @notice Emitted when a job is cancelled.
     * @param jobId The unique identifier of the job being cancelled.
     */
    event JobCancelled(uint256 indexed jobId);

    /// @notice Error for when an invalid user timeout is provided.
    error RelayInvalidUserTimeout();
    /// @notice Error for when a job does not exist.
    error RelayJobNotExists();
    /// @notice Error for when the overall timeout for a job has been exceeded.
    error RelayOverallTimeoutOver();
    /// @notice Error for when the overall timeout for a job has not yet been exceeded.
    error RelayOverallTimeoutNotOver();
    /// @notice Error for when the callback deposit transfer fails.
    error RelayCallbackDepositTransferFailed();
    /// @notice Error for when there is insufficient callback deposit.
    error RelayInsufficientCallbackDeposit();
    /// @notice Error for when the maximum gas price provided is insufficient.
    error RelayInsufficientMaxGasPrice();

    //-------------------------------- internal functions start -------------------------------//

    function _relayJob(
        uint8 _env,
        bytes32 _codehash,
        bytes calldata _codeInputs,
        uint256 _userTimeout, // in milliseconds
        uint256 _maxGasPrice,
        uint256 _callbackDeposit,
        address _refundAccount,
        address _callbackContract,
        uint256 _callbackGasLimit,
        address _jobOwner
    ) internal {
        if (_userTimeout <= GLOBAL_MIN_TIMEOUT || _userTimeout >= GLOBAL_MAX_TIMEOUT) revert RelayInvalidUserTimeout();

        if (jobCount + 1 == (block.chainid << 192) | (uint256(1) << 191)) jobCount = block.chainid << 192;

        if (_maxGasPrice < tx.gasprice) revert RelayInsufficientMaxGasPrice();

        if (_maxGasPrice * (_callbackGasLimit + FIXED_GAS + CALLBACK_MEASURE_GAS) > _callbackDeposit)
            revert RelayInsufficientCallbackDeposit();

        uint256 usdcDeposit = _userTimeout * executionEnv[_env].executionFeePerMs + GATEWAY_FEE_PER_JOB;
        jobs[++jobCount] = Job({
            startTime: block.timestamp,
            maxGasPrice: _maxGasPrice,
            usdcDeposit: usdcDeposit,
            callbackDeposit: _callbackDeposit,
            jobOwner: _jobOwner,
            codehash: _codehash,
            codeInputs: _codeInputs,
            callbackContract: _callbackContract,
            callbackGasLimit: _callbackGasLimit,
            env: _env
        });

        // deposit escrow amount(USDC)
        TOKEN.safeTransferFrom(_jobOwner, address(this), usdcDeposit);

        emit JobRelayed(
            jobCount,
            _env,
            _codehash,
            _codeInputs,
            _userTimeout,
            _maxGasPrice,
            usdcDeposit,
            _callbackDeposit,
            _refundAccount,
            _callbackContract,
            block.timestamp,
            _callbackGasLimit,
            _jobOwner
        );
    }

    function _jobResponse(
        bytes calldata _signature,
        uint256 _jobId,
        bytes calldata _output,
        uint256 _totalTime,
        uint8 _errorCode,
        uint256 _signTimestamp
    ) internal {
        Job memory job = jobs[_jobId];
        if (job.jobOwner == address(0)) revert RelayJobNotExists();

        // check time case
        if (block.timestamp > job.startTime + OVERALL_TIMEOUT) revert RelayOverallTimeoutOver();

        // signature check
        address enclaveAddress = _verifyJobResponseSign(
            _signature,
            _jobId,
            _output,
            _totalTime,
            _errorCode,
            _signTimestamp
        );

        delete jobs[_jobId];
        _releaseEscrowAmount(job.env, enclaveAddress, job.jobOwner, _totalTime, job.usdcDeposit);

        (bool success, uint256 callbackGas) = _callBackWithLimit(_jobId, job, _output, _errorCode);

        uint256 callbackCost = (callbackGas + FIXED_GAS) * tx.gasprice;

        _releaseGasCostOnSuccess(gatewayOwners[enclaveAddress], job.jobOwner, job.callbackDeposit, callbackCost);
        emit JobResponded(_jobId, _output, _totalTime, _errorCode, success);
    }

    function _verifyJobResponseSign(
        bytes calldata _signature,
        uint256 _jobId,
        bytes calldata _output,
        uint256 _totalTime,
        uint8 _errorCode,
        uint256 _signTimestamp
    ) internal view returns (address) {
        if (block.timestamp > _signTimestamp + ATTESTATION_MAX_AGE) revert RelaySignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(JOB_RESPONSE_TYPEHASH, _jobId, keccak256(_output), _totalTime, _errorCode, _signTimestamp)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        _allowOnlyVerified(signer);
        return signer;
    }

    function _releaseEscrowAmount(
        uint8 _env,
        address _enclaveAddress,
        address _jobOwner,
        uint256 _totalTime,
        uint256 _usdcDeposit
    ) internal {
        uint256 gatewayPayoutUsdc;
        uint256 jobOwnerPayoutUsdc;
        unchecked {
            gatewayPayoutUsdc = _totalTime * executionEnv[_env].executionFeePerMs + GATEWAY_FEE_PER_JOB;
            jobOwnerPayoutUsdc = _usdcDeposit - gatewayPayoutUsdc;
        }

        // release escrow to gateway
        TOKEN.safeTransfer(gatewayOwners[_enclaveAddress], gatewayPayoutUsdc);
        // release escrow to jobOwner
        TOKEN.safeTransfer(_jobOwner, jobOwnerPayoutUsdc);
    }

    function _jobCancel(uint256 _jobId) internal {
        Job memory job = jobs[_jobId];
        if (job.jobOwner == address(0)) revert RelayJobNotExists();

        // check time case
        if (block.timestamp <= job.startTime + OVERALL_TIMEOUT) revert RelayOverallTimeoutNotOver();

        uint256 callbackDeposit = job.callbackDeposit;
        uint256 usdcDeposit = job.usdcDeposit;
        delete jobs[_jobId];

        // return back escrow amount to the user
        TOKEN.safeTransfer(job.jobOwner, usdcDeposit);

        // return back callback deposit to the user
        (bool success, ) = job.jobOwner.call{value: callbackDeposit}("");
        if (!success) revert RelayCallbackDepositTransferFailed();

        emit JobCancelled(_jobId);
    }

    function _callBackWithLimit(
        uint256 _jobId,
        Job memory _job,
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

    function _releaseGasCostOnSuccess(
        address _gatewayOwner,
        address _jobOwner,
        uint256 _callbackDeposit,
        uint256 _callbackCost
    ) internal {
        // TODO: If paySuccess is false then deposit will be stucked forever. Find a way out.
        // transfer callback cost to gateway
        _callbackCost = _callbackCost > _callbackDeposit ? _callbackDeposit : _callbackCost;
        (bool paySuccess, ) = _gatewayOwner.call{value: _callbackCost}("");
        // transfer remaining native asset to the jobOwner
        (paySuccess, ) = _jobOwner.call{value: _callbackDeposit - _callbackCost}("");
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start --------------------------------//

    /**
     * @notice Function for users to relay a job to the enclave for execution.
     * @dev The job parameters are validated before relaying to the enclave.
     *      The job escrow amount (USDC+ETH) is transferred to the contract.
     * @param _env The execution environment for the job.
     * @param _codehash The transaction hash storing the code to be executed by the enclave.
     * @param _codeInputs The inputs to the code to be executed.
     * @param _userTimeout The maximum execution time allowed for the job in milliseconds.
     * @param _maxGasPrice The maximum gas price the job owner is willing to pay, to get back the job response.
     * @param _refundAccount The account to receive any slashed tokens.
     * @param _callbackContract The contract address to be called upon submitting job response.
     * @param _callbackGasLimit The gas limit for the callback function.
     */
    function relayJob(
        uint8 _env,
        bytes32 _codehash,
        bytes calldata _codeInputs,
        uint256 _userTimeout,
        uint256 _maxGasPrice,
        address _refundAccount, // Common chain slashed token will be sent to this address
        address _callbackContract,
        uint256 _callbackGasLimit
    ) external payable isValidEnv(_env) returns (uint256) {
        _relayJob(
            _env,
            _codehash,
            _codeInputs,
            _userTimeout,
            _maxGasPrice,
            msg.value,
            _refundAccount,
            _callbackContract,
            _callbackGasLimit,
            _msgSender()
        );
        return jobCount;
    }

    /**
     * @notice Function for gateways to respond to a job that has been executed by the enclave.
     * @dev The response includes output data, execution time, and error code.
     * @param _signature The signature of the gateway enclave.
     * @param _jobId The unique identifier of the job.
     * @param _output The output data from the job execution.
     * @param _totalTime The total time taken for job execution in milliseconds.
     * @param _errorCode The error code returned from the job execution.
     * @param _signTimestamp The timestamp at which the response was signed by the enclave.
     */
    function jobResponse(
        bytes calldata _signature,
        uint256 _jobId,
        bytes calldata _output,
        uint256 _totalTime,
        uint8 _errorCode,
        uint256 _signTimestamp
    ) external {
        _jobResponse(_signature, _jobId, _output, _totalTime, _errorCode, _signTimestamp);
    }

    /**
     * @notice Cancels a job whose response hasn't been submitted and the deadline is over.
     * @dev The function can be called by any user but ensures that the overall timeout has been reached before cancellation.
     * @param _jobId The unique identifier of the job to be cancelled.
     */
    function jobCancel(uint256 _jobId) external {
        _jobCancel(_jobId);
    }

    //-------------------------------- external functions end --------------------------------//

    //-------------------------------- Job End --------------------------------//
}
