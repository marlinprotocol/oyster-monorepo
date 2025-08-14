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
import "./Gateways.sol";
import "./Jobs.sol";

/**
 * @title GatewayJobs Contract
 * @dev This contract interacts with Jobs contract for job relay and response, and also slashes and 
        reassigns gateway in case they fail to relay the job request. 
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract GatewayJobs is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable // public upgrade
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    /// @notice Error for when zero address is provided for staking token.
    error GatewayJobsZeroAddressStakingToken();
    /// @notice Error for when zero address is provided for USDC token.
    error GatewayJobsZeroAddressUsdcToken();

    /**
     * @notice Initializes the logic contract without any admins to safeguard against takeover of the logic contract.
     * @param _stakingToken The staking token used in the system.
     * @param _usdcToken The USDC token used for payments.
     * @param _signMaxAge The maximum age of a valid signature in seconds.
     * @param _relayBufferTime The buffer time allowed for relaying jobs.
     * @param _slashCompForGateway The slashed amount component given to the gateway when all the selected executors fails to submit the job response.
     * @param _reassignCompForReporterGateway The compensation for the gateway that reports the reassignment.
     * @param _jobMgr The job manager contract.
     * @param _gateways The gateways contract.
     * @param _stakingPaymentPoolAddress The address of the staking payment pool.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        IERC20 _stakingToken,
        IERC20 _usdcToken,
        uint256 _signMaxAge,
        uint256 _relayBufferTime,
        uint256 _slashCompForGateway,
        uint256 _reassignCompForReporterGateway,
        Jobs _jobMgr,
        Gateways _gateways,
        address _stakingPaymentPoolAddress
    ) {
        _disableInitializers();

        if (address(_stakingToken) == address(0)) revert GatewayJobsZeroAddressStakingToken();
        STAKING_TOKEN = _stakingToken;

        if (address(_usdcToken) == address(0)) revert GatewayJobsZeroAddressUsdcToken();
        USDC_TOKEN = _usdcToken;

        SIGN_MAX_AGE = _signMaxAge;
        RELAY_BUFFER_TIME = _relayBufferTime;
        SLASH_COMP_FOR_GATEWAY = _slashCompForGateway;
        REASSIGN_COMP_FOR_REPORTER_GATEWAY = _reassignCompForReporterGateway;
        JOB_MANAGER = _jobMgr;
        GATEWAYS = _gateways;
        STAKING_PAYMENT_POOL = _stakingPaymentPoolAddress;
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

    /// @notice Error for when zero address is provided for the admin address.
    error GatewayJobsZeroAddressAdmin();

    /**
     * @notice Initializes the contract, setting the admin and configuring roles.
     * @param _admin The address to be granted the admin role.
     */
    function initialize(address _admin) public initializer {
        if (_admin == address(0)) revert GatewayJobsZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(JOBS_ROLE, address(JOB_MANAGER));

        // increasing allowance to be used while relaying jobs
        USDC_TOKEN.safeIncreaseAllowance(address(JOB_MANAGER), type(uint256).max);
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
    uint256 public immutable RELAY_BUFFER_TIME;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_COMP_FOR_GATEWAY;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable REASSIGN_COMP_FOR_REPORTER_GATEWAY;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    Jobs public immutable JOB_MANAGER;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    Gateways public immutable GATEWAYS;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address public immutable STAKING_PAYMENT_POOL;

    bytes32 public constant JOBS_ROLE = keccak256("JOBS_ROLE");

    struct Job {
        uint256 execStartTime;
        uint256 usdcDeposit;
        address jobOwner;
        bool isResourceUnavailable;
        uint8 sequenceId;
        uint8 env;
        address gateway;
    }

    // job_id => job
    mapping(uint256 => Job) public relayJobs;

    // execution_job_id => job_id
    mapping(uint256 => uint256) public execJobs;

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.GatewayJobs"),
                keccak256("1")
            )
        );

    bytes32 private constant RELAY_JOB_TYPEHASH =
        keccak256(
            "RelayJob(uint256 jobId,bytes32 codeHash,bytes codeInputs,uint256 deadline,uint256 jobRequestTimestamp,uint8 sequenceId,address jobOwner,uint8 env,uint256 signTimestamp)"
        );
    bytes32 private constant REASSIGN_GATEWAY_TYPEHASH =
        keccak256(
            "ReassignGateway(uint256 jobId,address gatewayOld,address jobOwner,uint8 sequenceId,uint256 jobRequestTimestamp,uint256 signTimestamp)"
        );

    /**
     * @notice Emitted when a job is relayed by a gateway.
     * @param jobId The ID of the job from request chain.
     * @param execJobId The ID of the job by Jobs contract.
     * @param env The execution environment for the job.
     * @param jobOwner The address of the job owner.
     * @param gateway The address of the gateway.
     */
    event JobRelayed(uint256 indexed jobId, uint256 execJobId, uint8 env, address jobOwner, address gateway);

    /**
     * @notice Emitted when a job's resource is unavailable.
     * @param jobId The ID of the job from request chain.
     * @param gateway The address of the gateway that relayed the job.
     */
    event JobResourceUnavailable(uint256 indexed jobId, address indexed gateway);

    /**
     * @notice Emitted when a gateway is reassigned to a job.
     * @param jobId The ID of the job.
     * @param prevGateway The address of the previous gateway.
     * @param reporterGateway The address of the gateway that reported the reassignment.
     * @param sequenceId The sequence ID of the reassignment.
     */
    event GatewayReassigned(uint256 indexed jobId, address prevGateway, address reporterGateway, uint8 sequenceId);

    /**
     * @notice Emitted when a job has been responded to after execution.
     * @param jobId The ID of the job.
     * @param output The output data from the job execution.
     * @param totalTime The total time taken for the job execution, in milliseconds.
     * @param errorCode The error code returned from the job execution.
     */
    event JobResponded(uint256 indexed jobId, bytes output, uint256 totalTime, uint8 errorCode);

    /**
     * @notice Emitted when a job has failed.
     * @param jobId The ID of the job.
     */
    event JobFailed(uint256 indexed jobId);

    // @notice Error for when USDC token approval fails.
    error GatewaysJobsUsdcApprovalFailed(address spender, uint256 value);
    // @notice Error for when the relay time for a job has passed.
    error GatewayJobsRelayTimeOver();
    // @notice Error for when the job resource is unavailable.
    error GatewayJobsResourceUnavailable();
    // @notice Error for when a job has already been relayed.
    error GatewayJobsAlreadyRelayed();
    // @notice Error for when the relay sequence ID is invalid.
    error GatewayJobsInvalidRelaySequenceId();
    // @notice Error for when the chain is unsupported.
    error GatewayJobsUnsupportedChain();
    // @notice Error for when the job signature is too old.
    error GatewayJobsSignatureTooOld();
    /// @notice Error for when job creation fails with a reason.
    /// @param reason The reason for the job creation failure.
    error GatewayJobsCreateFailed(bytes reason);

    //-------------------------------- admin functions start ----------------------------------//

    /**
     * @notice Sets the job allowance for the USDC token, allowing the JOB_MANAGER to spend it.
     * @dev Only callable by an account with the DEFAULT_ADMIN_ROLE.
     */
    function setJobAllowance() external onlyRole(DEFAULT_ADMIN_ROLE) {
        // increasing allowance to be used while relaying jobs
        bool success = USDC_TOKEN.approve(address(JOB_MANAGER), type(uint256).max);
        if (!success) revert GatewaysJobsUsdcApprovalFailed(address(JOB_MANAGER), type(uint256).max);
    }

    //-------------------------------- admin functions end ----------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _relayJob(
        bytes memory _signature,
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline, // in milliseconds
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner,
        uint8 _env,
        uint256 _signTimestamp,
        address _gateway
    ) internal {
        if (block.timestamp > _jobRequestTimestamp + RELAY_BUFFER_TIME) revert GatewayJobsRelayTimeOver();
        if (relayJobs[_jobId].isResourceUnavailable) revert GatewayJobsResourceUnavailable();
        if (relayJobs[_jobId].execStartTime != 0) revert GatewayJobsAlreadyRelayed();
        if (_sequenceId != relayJobs[_jobId].sequenceId + 1) revert GatewayJobsInvalidRelaySequenceId();

        uint256 reqChainId = _jobId >> 192;
        if (!GATEWAYS.isChainSupported(reqChainId)) revert GatewayJobsUnsupportedChain();

        // signature check
        address enclaveAddress = _verifyRelaySign(
            _signature,
            _jobId,
            _codehash,
            _codeInputs,
            _deadline,
            _jobRequestTimestamp,
            _sequenceId,
            _jobOwner,
            _env,
            _signTimestamp
        );

        // reserve execution fee from gateway
        uint256 usdcDeposit = _deadline * JOB_MANAGER.getJobExecutionFeePerMs(_env);
        USDC_TOKEN.safeTransferFrom(_gateway, address(this), usdcDeposit);

        _createJob(
            _jobId,
            _codehash,
            _codeInputs,
            _deadline,
            _jobOwner,
            enclaveAddress,
            usdcDeposit,
            _sequenceId,
            _env
        );
    }

    function _createJob(
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline,
        address _jobOwner,
        address _gateway,
        uint256 _usdcDeposit,
        uint8 _sequenceId,
        uint8 _env
    ) internal {
        try JOB_MANAGER.createJob(_env, _codehash, _codeInputs, _deadline) returns (uint256 execJobId) {
            relayJobs[_jobId].execStartTime = block.timestamp;
            relayJobs[_jobId].jobOwner = _jobOwner;
            relayJobs[_jobId].usdcDeposit = _usdcDeposit;
            relayJobs[_jobId].sequenceId = _sequenceId;
            relayJobs[_jobId].gateway = _gateway;
            relayJobs[_jobId].env = _env;

            execJobs[execJobId] = _jobId;

            emit JobRelayed(_jobId, execJobId, _env, _jobOwner, _gateway);
        } catch (bytes memory reason) {
            if (bytes4(reason) == Jobs.JobsUnavailableResources.selector) {
                // Resource unavailable
                relayJobs[_jobId].isResourceUnavailable = true;
                // Refund the USDC deposit
                USDC_TOKEN.safeTransfer(_gateway, _usdcDeposit);

                emit JobResourceUnavailable(_jobId, _gateway);
                return;
            } else {
                revert GatewayJobsCreateFailed(reason);
            }
        }
    }

    function _verifyRelaySign(
        bytes memory _signature,
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline, // in milliseconds
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner,
        uint8 _env,
        uint256 _signTimestamp
    ) internal view returns (address) {
        if (block.timestamp > _signTimestamp + SIGN_MAX_AGE) revert GatewayJobsSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                RELAY_JOB_TYPEHASH,
                _jobId,
                _codehash,
                keccak256(_codeInputs),
                _deadline,
                _jobRequestTimestamp,
                _sequenceId,
                _jobOwner,
                _env,
                _signTimestamp
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        GATEWAYS.allowOnlyVerified(signer);
        return signer;
    }

    function _reassignGatewayRelay(
        address _gatewayOld,
        uint256 _jobId,
        bytes memory _signature,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp,
        address _jobOwner,
        uint256 _signTimestamp,
        address _gateway
    ) internal {
        // time check will be done in the gateway enclaves and based on the algo, a new gateway will be selected
        if (block.timestamp > _jobRequestTimestamp + RELAY_BUFFER_TIME) revert GatewayJobsRelayTimeOver();

        if (relayJobs[_jobId].execStartTime != 0) revert GatewayJobsAlreadyRelayed();
        if (relayJobs[_jobId].isResourceUnavailable) revert GatewayJobsResourceUnavailable();
        if (_sequenceId != relayJobs[_jobId].sequenceId + 1 || _sequenceId > 2)
            revert GatewayJobsInvalidRelaySequenceId();
        relayJobs[_jobId].sequenceId = _sequenceId;

        // signature check
        address enclaveAddress = _verifyReassignGatewaySign(
            _signature,
            _jobId,
            _gatewayOld,
            _jobOwner,
            _sequenceId,
            _jobRequestTimestamp,
            _signTimestamp
        );

        // slash old gateway
        uint256 slashedAmount = GATEWAYS.slashOnReassignGateway(_gatewayOld);
        address _reporterGateway = GATEWAYS.getOwner(enclaveAddress);
        STAKING_TOKEN.safeTransfer(_reporterGateway, REASSIGN_COMP_FOR_REPORTER_GATEWAY);
        if (_sequenceId == 1) {
            // if sequenceId = 1, keep the comp in payment pool
            STAKING_TOKEN.safeTransfer(STAKING_PAYMENT_POOL, slashedAmount - REASSIGN_COMP_FOR_REPORTER_GATEWAY);
        } else {
            // if sequenceId = 2, transfer comp to jobOwner
            STAKING_TOKEN.safeTransfer(_jobOwner, slashedAmount - REASSIGN_COMP_FOR_REPORTER_GATEWAY);
        }

        emit GatewayReassigned(_jobId, _gatewayOld, _gateway, _sequenceId);
    }

    function _verifyReassignGatewaySign(
        bytes memory _signature,
        uint256 _jobId,
        address _gatewayOld,
        address _jobOwner,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp,
        uint256 _signTimestamp
    ) internal view returns (address) {
        if (block.timestamp > _signTimestamp + SIGN_MAX_AGE) revert GatewayJobsSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                REASSIGN_GATEWAY_TYPEHASH,
                _jobId,
                _gatewayOld,
                _jobOwner,
                _sequenceId,
                _jobRequestTimestamp,
                _signTimestamp
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        GATEWAYS.allowOnlyVerified(signer);
        return signer;
    }
    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start --------------------------------//

    /**
     * @notice Function to relay a job from a gateway.
     * @dev Can only be called by a gateway registered in the Gateways contract.
     * @param _signature The signature verifying the job details.
     * @param _jobId The ID of the job to be relayed.
     * @param _codehash The transaction hash storing the code in calldata, that needs to be executed.
     * @param _codeInputs The inputs to the job's code.
     * @param _deadline The deadline for job execution in milliseconds.
     * @param _jobRequestTimestamp The timestamp when the job was requested.
     * @param _sequenceId The sequence ID of the job relay.
     * @param _jobOwner The address of the job owner.
     * @param _signTimestamp The timestamp when the signature was created.
     */
    function relayJob(
        bytes memory _signature,
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline, // in milliseconds
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner,
        uint8 _env,
        uint256 _signTimestamp
    ) external {
        _relayJob(
            _signature,
            _jobId,
            _codehash,
            _codeInputs,
            _deadline,
            _jobRequestTimestamp,
            _sequenceId,
            _jobOwner,
            _env,
            _signTimestamp,
            _msgSender()
        );
    }

    /**
     * @notice Reassigns a gateway for a job relay. This function facilitates the reassignment by verifying the provided signature and updating the job's gateway.
     * @dev Can only be called by a registered gateway.
     * @param _gatewayOld The address of the previous gateway that was assigned to the job.
     * @param _jobId The ID of the job that needs a gateway reassignment.
     * @param _signature The signature provided to verify the job reassignment details.
     * @param _sequenceId The sequence ID associated with the job relay, used for tracking the order of operations.
     * @param _jobRequestTimestamp The timestamp when the job was initially requested.
     * @param _jobOwner The address of the owner of the job.
     * @param _signTimestamp The timestamp when the signature was created.
     */
    function reassignGatewayRelay(
        address _gatewayOld,
        uint256 _jobId,
        bytes memory _signature,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp,
        address _jobOwner,
        uint256 _signTimestamp
    ) external {
        _reassignGatewayRelay(
            _gatewayOld,
            _jobId,
            _signature,
            _sequenceId,
            _jobRequestTimestamp,
            _jobOwner,
            _signTimestamp,
            _msgSender()
        );
    }
    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- JobsContract functions start --------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _oysterResultCall(
        uint256 _execJobId,
        bytes memory _output,
        uint8 _errorCode,
        uint256 _totalTime
    ) internal {
        uint256 jobId = execJobs[_execJobId];
        address gateway = relayJobs[jobId].gateway;
        uint256 usdcDeposit = relayJobs[jobId].usdcDeposit;
        uint8 env = relayJobs[jobId].env;

        delete execJobs[_execJobId];
        delete relayJobs[jobId];

        address owner = GATEWAYS.getOwner(gateway);

        USDC_TOKEN.safeTransfer(owner, usdcDeposit - _totalTime * JOB_MANAGER.getJobExecutionFeePerMs(env));
        emit JobResponded(jobId, _output, _totalTime, _errorCode);
    }

    function _oysterFailureCall(
        uint256 _execJobId,
        // uint256 _slashAmount,
        address[] memory _tokens,
        uint256[] memory _amounts
    ) internal {
        uint jobId = execJobs[_execJobId];
        address gateway = relayJobs[jobId].gateway;
        uint256 usdcDeposit = relayJobs[jobId].usdcDeposit;
        address jobOwner = relayJobs[jobId].jobOwner;
        delete execJobs[_execJobId];
        delete relayJobs[jobId];

        address gatewayOwner = GATEWAYS.getOwner(gateway);

        USDC_TOKEN.safeTransfer(gatewayOwner, usdcDeposit);
        // STAKING_TOKEN.safeTransfer(jobOwner, _slashAmount - SLASH_COMP_FOR_GATEWAY);
        // STAKING_TOKEN.safeTransfer(gatewayOwner, SLASH_COMP_FOR_GATEWAY);
        for (uint256 index = 0; index < _tokens.length; index++) {
            uint256 slashAmount = _amounts[index];
            // TODO: need to fix this scenario
            if(slashAmount <= SLASH_COMP_FOR_GATEWAY) {
                IERC20(_tokens[index]).safeTransfer(jobOwner, slashAmount);
            } else {
                IERC20(_tokens[index]).safeTransfer(jobOwner, slashAmount - SLASH_COMP_FOR_GATEWAY);
                IERC20(_tokens[index]).safeTransfer(gatewayOwner, SLASH_COMP_FOR_GATEWAY);
            }
        }
        emit JobFailed(jobId);
    }
    //-------------------------------- internal functions end ----------------------------------//

    //------------------------------- external functions start ---------------------------------//

    /**
     * @notice External function to call the internal _oysterResultCall function after a job has been executed.
     * @dev Can only be called by an address with the JOBS_ROLE.
     * @param _jobId The ID of the job that was executed.
     * @param _output The output data from the job execution.
     * @param _errorCode The error code returned from the job execution. 0 indicates success, while non-zero values indicate specific errors.
     * @param _totalTime The total time taken for the job execution, in milliseconds.
     */
    function oysterResultCall(
        uint256 _jobId,
        bytes memory _output,
        uint8 _errorCode,
        uint256 _totalTime
    ) external onlyRole(JOBS_ROLE) {
        _oysterResultCall(_jobId, _output, _errorCode, _totalTime);
    }

    /**
     * @notice External function to call the internal _oysterFailureCall function after a job has failed.
     * @dev Can only be called by an address with the JOBS_ROLE.
     * @param _jobId The ID of the job that failed.
     */
    function oysterFailureCall(
        uint256 _jobId,
        // uint256 _slashAmount,
        address[] memory _tokens,
        uint256[] memory _amounts
    ) external onlyRole(JOBS_ROLE) {
        _oysterFailureCall(_jobId, _tokens, _amounts);
    }
    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- JobsContract functions end --------------------------------//
}
