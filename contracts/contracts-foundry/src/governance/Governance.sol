// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

/* Contracts */
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/* Interfaces */
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IGovernance} from "./interfaces/IGovernance.sol";

/* Libraries */
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract Governance is
    Initializable, // initializer
    ContextUpgradeable,
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC enumeration
    PausableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    IGovernance
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    // ========== Constants ==========
    bytes32 public constant CONFIG_SETTER_ROLE = keccak256("CONFIG_SETTER_ROLE");

    // ========== Storage Gaps ==========
    uint256[500] private __gap0;

    // ========== State Variables ==========

    // Core Contracts
    address public treasury;

    // Proposal Management
    mapping(address token => uint256 amount) public proposalDepositAmounts;
    mapping(bytes32 id => Proposal) proposals;
    mapping(bytes32 id => bool) public executionQueue;
    mapping(address proposer => uint256 nonce) public proposerNonce;

    // Proposal Configuration
    ProposalTimingConfig public proposalTimingConfig;
    uint256 public minQuorumThreshold;
    uint256 public proposalPassVetoThreshold;
    uint256 public vetoSlashRate;

    // KMS Configuration
    PCRConfig public pcrConfig;
    bytes public kmsRootServerPubKey;
    string public kmsPath;

    // Network Configuration
    bytes32 private networkHash;
    uint256[] public supportedChainIds;
    uint256 public maxRPCUrlsPerChain;
    mapping(uint256 chainId => TokenNetworkConfig config) public tokenNetworkConfigs;

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), NotDefaultAdmin());
        _;
    }

    modifier onlyConfigSetter() {
        require(hasRole(CONFIG_SETTER_ROLE, _msgSender()), NotConfigSetterRole());
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor() initializer {}

    //-------------------------------- Overrides start --------------------------------//

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165Upgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address /*account*/ ) internal view override onlyAdmin {}

    //-------------------------------- Overrides ends --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap1;

    /// @notice Initializes the governance contract with all required configuration parameters
    /// @dev This function sets up the initial state of the governance system including roles, thresholds, and configurations
    /// @dev setTokenLockAmount, setNetworkConfig should be seperately called after initialization
    ///      Otherwise, propose() will revert
    /// @param _admin The address that will have admin privileges
    /// @param _configSetter The address that can modify configuration parameters
    /// @param _treasury The address where slashed funds will be sent
    /// @param _minQuorumThreshold The minimum percentage of total voting power required for a proposal to be valid
    /// @param _proposalPassVetoThreshold The percentage of votes required for a proposal to pass or be vetoed
    /// @param _vetoSlashRate The percentage of deposit that will be slashed when a proposal is vetoed (in basis points)
    /// @param _voteActivationDelay The delay before voting can start after proposal creation
    /// @param _voteDuration The duration of the voting period
    /// @param _proposalDuration The total duration of a proposal from creation to deadline
    /// @param _maxRPCUrlsPerChain The maximum number of RPC URLs allowed per chain
    /// @param _pcr The PCR configuration containing pcr0, pcr1, and pcr2 values
    /// @param _kmsRootServerPubKey The public key of the KMS root server
    /// @param _kmsPath The path configuration for KMS operations
    function initialize(
        address _admin,
        address _configSetter,
        address _treasury,
        uint256 _minQuorumThreshold,
        uint256 _proposalPassVetoThreshold,
        uint256 _vetoSlashRate,
        uint256 _voteActivationDelay,
        uint256 _voteDuration,
        uint256 _proposalDuration,
        uint256 _maxRPCUrlsPerChain,
        PCR calldata _pcr,
        bytes calldata _kmsRootServerPubKey,
        string calldata _kmsPath
    ) public initializer {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __Pausable_init_unchained();

        // Set Roles
        require(_admin != address(0), InvalidAddress());
        require(_configSetter != address(0), InvalidAddress());
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(CONFIG_SETTER_ROLE, _configSetter);

        // Set Treasury Address
        _setTreasury(_treasury);

        // Set Proposal Pass Threshold
        _setProposalPassVetoThreshold(_proposalPassVetoThreshold);

        // Set Min Quorum Threshold
        _setMinQuorumThreshold(_minQuorumThreshold);

        // Set Veto Slash Rate
        _setVetoSlashRate(_vetoSlashRate);

        // Set Proposal Time Config
        _setProposalTimingConfig(_voteActivationDelay, _voteDuration, _proposalDuration);

        // Set Max RPC URLs per Chain
        _setMaxRPCUrlsPerChain(_maxRPCUrlsPerChain);

        // Set PCR0, PCR1, PCR2
        _setPCRConfig(_pcr.pcr0, _pcr.pcr1, _pcr.pcr2);

        // Set KMS Config
        _setKMSRootServerKey(_kmsRootServerPubKey);
        _setKMSPath(_kmsPath);

        // Note: setTokenLockAmount, setNetworkConfig should be seperately called after initialization
    }

    //-------------------------------- Initializer end --------------------------------//

    //-------------------------------- Admin start --------------------------------//

    /// @notice Sets the required deposit amount for a specific token when creating proposals
    /// @dev This function allows config setters to specify how much of a particular token must be deposited to create a proposal
    /// @param _token The address of the token for which to set the deposit amount
    /// @param _amount The amount of tokens required as deposit for proposal creation
    function setTokenLockAmount(address _token, uint256 _amount) external onlyConfigSetter {
        require(_amount > 0, InvalidAddress());
        proposalDepositAmounts[_token] = _amount;
        emit TokenLockAmountSet(_token, _amount);
    }

    /// @notice Sets the proposal pass threshold, which is the minimum percentage of votes required for a proposal to pass or be vetoed
    /// @dev This threshold determines the minimum percentage of total voting power needed for a proposal to be considered passed or vetoed
    /// @param _proposalPassVetoThreshold The percentage threshold for proposal pass/veto (in basis points)
    function setProposalPassVetoThreshold(uint256 _proposalPassVetoThreshold) external onlyConfigSetter {
        _setProposalPassVetoThreshold(_proposalPassVetoThreshold);
    }

    function _setProposalPassVetoThreshold(uint256 _proposalPassVetoThreshold) internal {
        require(_proposalPassVetoThreshold > 0, ZeroProposalPassThreshold());
        proposalPassVetoThreshold = _proposalPassVetoThreshold;
        emit ProposalPassVetoThresholdSet(_proposalPassVetoThreshold);
    }

    /// @notice Sets the minimum quorum threshold required for a proposal to be valid
    /// @dev This threshold ensures that a minimum percentage of total voting power participates in the proposal
    /// @param _minQuorumThreshold The minimum percentage of total voting power required for quorum (in basis points)
    function setMinQuorumThreshold(uint256 _minQuorumThreshold) external onlyConfigSetter {
        _setMinQuorumThreshold(_minQuorumThreshold);
    }

    function _setMinQuorumThreshold(uint256 _minQuorumThreshold) internal {
        require(_minQuorumThreshold > 0, InvalidMinQuorumThreshold());
        minQuorumThreshold = _minQuorumThreshold;
        emit MinQuorumThresholdSet(_minQuorumThreshold);
    }

    /// @notice Sets the percentage of deposit that will be slashed when a proposal is vetoed
    /// @dev This rate determines how much of the proposer's deposit is taken as penalty when their proposal is vetoed
    /// @param _vetoSlashRate The percentage of deposit to slash on veto (in basis points, max 100%)
    function setVetoSlashRate(uint256 _vetoSlashRate) external onlyConfigSetter {
        _setVetoSlashRate(_vetoSlashRate);
    }

    function _setVetoSlashRate(uint256 _vetoSlashRate) internal {
        require(_vetoSlashRate <= 1e18, InvalidVetoSlashRate());
        vetoSlashRate = _vetoSlashRate;
        emit VetoSlashRateSet(_vetoSlashRate);
    }

    /// @notice Sets the treasury address where slashed funds will be sent
    /// @dev This address receives the slashed portion of deposits when proposals are vetoed
    /// @param _treasury The address to set as the treasury
    function setTreasury(address _treasury) external onlyConfigSetter {
        _setTreasury(_treasury);
    }

    function _setTreasury(address _treasury) internal {
        require(_treasury != address(0), InvalidAddress());
        treasury = _treasury;
        emit TreasurySet(_treasury);
    }

    /// @notice Sets the timing configuration for proposals including activation delay, voting duration, and total proposal duration
    /// @dev This function configures the time-based parameters that control the proposal lifecycle
    /// @param _voteActivationDelay The delay before voting can start after proposal creation
    /// @param _voteDuration The duration of the voting period
    /// @param _proposalDuration The total duration of a proposal from creation to deadline
    function setProposalTimingConfig(uint256 _voteActivationDelay, uint256 _voteDuration, uint256 _proposalDuration)
        external
        onlyConfigSetter
    {
        _setProposalTimingConfig(_voteActivationDelay, _voteDuration, _proposalDuration);
    }

    function _setProposalTimingConfig(uint256 _voteActivationDelay, uint256 _voteDuration, uint256 _proposalDuration) internal {
        require(_voteActivationDelay + _voteDuration + _proposalDuration > 0, ZeroProposalTimeConfig());

        if(_voteActivationDelay > 0) {
            _setVoteActivationDelay(_voteActivationDelay);
        }
        if(_voteDuration > 0) {
            _setVoteDuration(_voteDuration);
        }
        if(_proposalDuration > 0) {
            _setProposalDuration(_proposalDuration);
        }

        require(
            proposalTimingConfig.voteActivationDelay + proposalTimingConfig.voteDuration
                < proposalTimingConfig.proposalDuration,
            InvalidProposalTimeConfig()
        );
    }

    function _setVoteActivationDelay(uint256 _voteActivationDelay) internal {
        proposalTimingConfig.voteActivationDelay = _voteActivationDelay;
        emit VoteActivationDelaySet(_voteActivationDelay);
    }

    function _setVoteDuration(uint256 _voteDuration) internal {
        proposalTimingConfig.voteDuration = _voteDuration;
        emit VoteDurationSet(_voteDuration);
    }

    function _setProposalDuration(uint256 _proposalDuration) internal {
        proposalTimingConfig.proposalDuration = _proposalDuration;
        emit ProposalDurationSet(_proposalDuration);
    }

    /// @dev Condition `voteActivationDelay + voteDuration < proposalDuration` is not checked here

    /// @notice Sets the maximum number of RPC URLs allowed per chain
    /// @dev This limit prevents excessive RPC URL storage and ensures efficient network configuration management
    /// @param _maxRPCUrlsPerChain The maximum number of RPC URLs allowed per chain
    function setMaxRPCUrlsPerChain(uint256 _maxRPCUrlsPerChain) external onlyConfigSetter {
        _setMaxRPCUrlsPerChain(_maxRPCUrlsPerChain);
    }

    function _setMaxRPCUrlsPerChain(uint256 _maxRPCUrlsPerChain) internal {
        require(_maxRPCUrlsPerChain > 0, InvalidMaxRpcUrlsPerChain());
        maxRPCUrlsPerChain = _maxRPCUrlsPerChain;
        emit MaxRpcUrlsPerChainSet(_maxRPCUrlsPerChain);
    }

    /// @notice Add or update NetworkConfig for the specified chainId
    /// @dev If the chainId is not in supportedChainIds, it will be added.
    /// @param _chainId The chain ID for which the network config is being set
    /// @param _tokenAddress The address of the token contract on the specified chain
    ///          If the token address is set to address(0), the chainId will be removed from supportedChainIds
    /// @param _rpcUrls An array of RPC URLs for the specified chain
    function setNetworkConfig(uint256 _chainId, address _tokenAddress, string[] calldata _rpcUrls)
        public
        onlyConfigSetter
    {
        require(_chainId > 0, InvalidChainId());
        require(_rpcUrls.length > 0, InvalidRpcUrl());
        require(_rpcUrls.length <= maxRPCUrlsPerChain, MaxRpcUrlsPerChainReached());

        // If _tokenAddress is address(0), remove the chainId from supportedChainIds
        if (_tokenAddress == address(0)) {
            _removeChainIdFromSupported(_chainId);
            // Clear the token network config for this chainId
            delete tokenNetworkConfigs[_chainId];
            networkHash = _calcNetworkHash();
            emit NetworkConfigSet(_chainId, _tokenAddress, _rpcUrls, networkHash);
            return;
        }

        // Check if the chainId is already set for the chainId
        bool chainIdExists = false;
        for (uint256 i = 0; i < supportedChainIds.length; ++i) {
            if (supportedChainIds[i] == _chainId) {
                chainIdExists = true;
                break;
            }
        }

        // If the chainId is not supported, add it to the supportedChainIds
        if (!chainIdExists) {
            supportedChainIds.push(_chainId);
        }

        // Update the token network config
        bytes32 chainHash = sha256(abi.encode(_chainId, _rpcUrls));
        tokenNetworkConfigs[_chainId] =
            TokenNetworkConfig({chainHash: chainHash, tokenAddress: _tokenAddress, rpcUrls: _rpcUrls});

        networkHash = _calcNetworkHash();

        emit NetworkConfigSet(_chainId, _tokenAddress, _rpcUrls, networkHash);
    }

    function _calcNetworkHash() internal view returns (bytes32) {
        bytes memory chainHashEncoded;
        for (uint256 i = 0; i < supportedChainIds.length; ++i) {
            uint256 chainId = supportedChainIds[i];
            bytes32 chainHash = tokenNetworkConfigs[chainId].chainHash;
            chainHashEncoded = abi.encode(chainHashEncoded, chainHash);
        }
        return sha256(chainHashEncoded);
    }

    /// @notice Remove a chainId from the supportedChainIds array
    /// @dev This function removes the specified chainId from the supportedChainIds array
    /// @param _chainId The chain ID to remove from supported chain IDs
    function _removeChainIdFromSupported(uint256 _chainId) internal {
        for (uint256 i = 0; i < supportedChainIds.length; ++i) {
            if (supportedChainIds[i] == _chainId) {
                // Move the last element to the position of the element to delete
                supportedChainIds[i] = supportedChainIds[supportedChainIds.length - 1];
                // Remove the last element
                supportedChainIds.pop();
                break;
            }
        }
    }

    /// @notice Updates an existing RPC URL for the specified chainId at the given index
    /// @notice This will overwrite the existing rpc urls for the chainId
    function setRpcUrls(uint256 _chainId, string[] calldata _rpcUrls) external onlyConfigSetter {
        require(_chainId > 0, InvalidChainId());
        require(_rpcUrls.length > 0, InvalidRpcUrl());
        require(_rpcUrls.length <= maxRPCUrlsPerChain, MaxRpcUrlsPerChainReached());

        // Check if the chainId exists in supportedChainIds
        bool chainIdExists = false;
        for (uint256 i = 0; i < supportedChainIds.length; ++i) {
            if (supportedChainIds[i] == _chainId) {
                chainIdExists = true;
                break;
            }
        }
        require(chainIdExists, InvalidChainId());

        // Update the rpcUrls and recalculate chainHash
        bytes32 chainHash = sha256(abi.encode(_chainId, _rpcUrls));
        tokenNetworkConfigs[_chainId].rpcUrls = _rpcUrls;
        tokenNetworkConfigs[_chainId].chainHash = chainHash;
        networkHash = _calcNetworkHash();

        emit RpcUrlUpdated(_chainId, _rpcUrls);
    }

    /// @notice Sets the KMS Root Server public key for signature verification
    /// @dev This public key is used to verify KMS signatures during proposal result submission
    /// @param _kmsRootServerPubKey The public key of the KMS root server
    function setKMSRootServerKey(bytes calldata _kmsRootServerPubKey) external onlyConfigSetter {
        _setKMSRootServerKey(_kmsRootServerPubKey);
    }

    function _setKMSRootServerKey(bytes calldata _kmsRootServerPubKey) internal {
        require(_kmsRootServerPubKey.length > 0, InvalidKMSRootServerPubKey());
        kmsRootServerPubKey = _kmsRootServerPubKey;
        emit KMSRootServerPubKeySet(_kmsRootServerPubKey);
    }

    /// @notice Set KMS Path to be used for KMS signature verification
    /// @dev The path should be in the format used by the KMS, e.g., "/derive/secp256k1/public?image_id={imageId}&path={path}"
    /// @param _kmsPath The KMS path to be set
    function setKMSPath(string calldata _kmsPath) external onlyConfigSetter {
        _setKMSPath(_kmsPath);
    }

    function _setKMSPath(string calldata _kmsPath) internal {
        require(bytes(_kmsPath).length > 0, InvalidKMSPath());
        kmsPath = _kmsPath;
        emit KMSPathSet(_kmsPath);
    }

    /// @notice Sets the PCR configuration (PCR0, PCR1, PCR2) and generates the corresponding image ID
    /// @dev This configuration is used for enclave verification and must be unique from the current configuration
    /// @param _pcr0 The PCR0 value for enclave verification
    /// @param _pcr1 The PCR1 value for enclave verification
    /// @param _pcr2 The PCR2 value for enclave verification
    function setPCRConfig(bytes calldata _pcr0, bytes calldata _pcr1, bytes calldata _pcr2) external onlyConfigSetter {
        _setPCRConfig(_pcr0, _pcr1, _pcr2);
    }

    function _setPCRConfig(bytes calldata _pcr0, bytes calldata _pcr1, bytes calldata _pcr2) internal {
        require(_pcr0.length > 0 && _pcr1.length > 0 && _pcr2.length > 0, InvalidPCRLength());
        bytes32 imageIdGenerated = _generateImageId(_pcr0, _pcr1, _pcr2);
        require(imageIdGenerated != pcrConfig.imageId, SameImageId());

        pcrConfig.pcr = PCR({pcr0: _pcr0, pcr1: _pcr1, pcr2: _pcr2});
        pcrConfig.imageId = imageIdGenerated;
        emit PCRConfigSet(_pcr0, _pcr1, _pcr2, imageIdGenerated);
    }

    /// @notice Pauses the governance contract, preventing all state-changing operations
    /// @dev Only admin can pause the contract, and it can only be called when not already paused
    function pause() external whenNotPaused onlyAdmin {
        _pause();
    }

    /// @notice Unpauses the governance contract, allowing state-changing operations to resume
    /// @dev Only admin can unpause the contract, and it can only be called when currently paused
    function unpause() external whenPaused onlyAdmin {
        _unpause();
    }

    //-------------------------------- Admin end --------------------------------//

    //-------------------------------- Propose start --------------------------------//

    /// @notice Creates a new governance proposal with the specified parameters
    /// @dev This function validates inputs, locks deposit tokens, and stores the proposal data
    /// @dev The caller must send the exact amount of ETH specified in the proposal values
    /// @param _params The proposal parameters including targets, values, calldatas, title, description, and deposit token
    /// @return proposalId The unique identifier of the created proposal
    function propose(ProposeInputParams calldata _params) external payable whenNotPaused returns (bytes32) {
        // Validate input
        require(
            _params.targets.length == _params.values.length && _params.targets.length == _params.calldatas.length,
            InvalidInputLength()
        );
        require(bytes(_params.title).length > 0 && bytes(_params.description).length > 0, InvalidTitleLength());
        for (uint256 i = 0; i < _params.targets.length; ++i) {
            require(_params.targets[i] != address(this), InvalidAddress());
        }
        uint256 valueSum;
        for (uint256 i = 0; i < _params.values.length; ++i) {
            if (_params.values[i] > 0) valueSum += _params.values[i];
        }
        require(valueSum == msg.value, InvalidMsgValue());
        require(proposalDepositAmounts[_params.depositToken] > 0, TokenNotSupported());
        require(supportedChainIds.length > 0, NoSupportedChainConfigured());

        // Calculate proposalId
        bytes32 descriptionHash = sha256(abi.encode(_params.title, _params.description));
        bytes32 proposalId = _generateProposalId(
            _params.targets, _params.values, _params.calldatas, descriptionHash, msg.sender, proposerNonce[msg.sender]
        );
        require(proposals[proposalId].proposalInfo.proposer == address(0), ProposalAlreadyExists());

        // Deposit and store
        _depositTokenAndLock(proposalId, _params.depositToken, proposalDepositAmounts[_params.depositToken]);
        _storeProposal(
            proposalId, _params.targets, _params.values, _params.calldatas, _params.title, _params.description
        );

        emit ProposalCreated(
            proposalId,
            proposerNonce[msg.sender],
            _params.targets,
            _params.values,
            _params.calldatas,
            _params.title,
            _params.description,
            proposals[proposalId].proposalTimeInfo
        );

        proposerNonce[msg.sender] += 1;
        return proposalId;
    }

    function _storeProposal(
        bytes32 _proposalId,
        address[] calldata _targets,
        uint256[] calldata _values,
        bytes[] calldata _calldatas,
        string calldata _title,
        string calldata _description
    ) internal {
        // Store the proposal information
        proposals[_proposalId].proposalInfo = ProposalInfo({
            proposer: msg.sender,
            targets: _targets,
            values: _values,
            calldatas: _calldatas,
            title: _title,
            description: _description
        });

        // Set the proposal time information
        proposals[_proposalId].proposalTimeInfo = ProposalTimeInfo({
            proposedTimestamp: block.timestamp,
            voteActivationTimestamp: block.timestamp + proposalTimingConfig.voteActivationDelay,
            voteDeadlineTimestamp: block.timestamp + proposalTimingConfig.voteActivationDelay
                + proposalTimingConfig.voteDuration,
            proposalDeadlineTimestamp: block.timestamp + proposalTimingConfig.proposalDuration
        });

        proposals[_proposalId].networkHash = networkHash;
        proposals[_proposalId].imageId = pcrConfig.imageId;
    }

    //-------------------------------- Propose end --------------------------------//

    //-------------------------------- Vote start --------------------------------//

    /// @notice Submits an encrypted vote for a specific proposal
    /// @dev This function can only be called during the active voting period of a proposal
    /// @dev The vote is encrypted and stored along with the voter's address
    /// @param _proposalId The unique identifier of the proposal to vote on
    /// @param _voteEncrypted The encrypted vote data
    function vote(bytes32 _proposalId, bytes calldata _voteEncrypted) external {
        require(proposals[_proposalId].proposalInfo.proposer != address(0), ProposalDoesNotExist());
        ProposalTimeInfo storage proposalTimeInfo = proposals[_proposalId].proposalTimeInfo;
        require(
            block.timestamp >= proposalTimeInfo.voteActivationTimestamp
                && block.timestamp < proposalTimeInfo.voteDeadlineTimestamp,
            VotingNotActive()
        );

        ProposalVoteInfo storage proposalVoteInfo = proposals[_proposalId].proposalVoteInfo;
        uint256 voteIdx = proposalVoteInfo.voteCount;
        proposalVoteInfo.votes[voteIdx] = Vote({voter: msg.sender, voteEncrypted: _voteEncrypted});
        proposalVoteInfo.voteCount++;

        bytes32 voteEncryptedHash = sha256(_voteEncrypted);
        bytes32 voteHashOld = proposalVoteInfo.voteHash;
        bytes32 voteHashUpdated = sha256(abi.encode(voteHashOld, voteEncryptedHash));
        proposalVoteInfo.voteHash = voteHashUpdated;

        emit VoteSubmitted(_proposalId, voteIdx, msg.sender, _voteEncrypted);
    }

    //-------------------------------- Vote end --------------------------------//

    //-------------------------------- Result start --------------------------------//

    /// @notice Submits the final voting result for a proposal after the voting period has ended
    /// @dev This function verifies KMS and enclave signatures before processing the result
    /// @dev The result determines whether the proposal passes, fails, or is vetoed
    /// @param _params The result submission parameters including result data, enclave public key, and signatures
    function submitResult(SubmitResultInputParams calldata _params) external nonReentrant {
        // Decode `_resultData`
        (bytes32 proposalId, VoteDecisionResult memory voteDecisionResult) =
            abi.decode(_params.resultData, (bytes32, VoteDecisionResult));

        require(proposals[proposalId].proposalInfo.proposer != address(0), ProposalDoesNotExist());

        // Check if the proposal in Result Submission Phase
        ProposalTimeInfo storage proposalTimeInfo = proposals[proposalId].proposalTimeInfo;
        require(
            block.timestamp >= proposalTimeInfo.voteDeadlineTimestamp
                && block.timestamp < proposalTimeInfo.proposalDeadlineTimestamp,
            NotResultSubmissionPhase()
        );

        // Check if the result of the proposal is not already submitted
        require(proposals[proposalId].voteOutcome == VoteOutcome.Pending, ResultAlreadySubmitted());

        // Verify KMS sig
        require(
            verifyKMSSig(proposals[proposalId].imageId, _params.enclavePubKey, _params.kmsSig), InvadidKMSSignature()
        );

        // Verify Enclave Sig
        bytes32 contractDataHash = sha256(
            abi.encode(
                address(this),
                proposalTimeInfo.proposedTimestamp,
                proposals[proposalId].networkHash,
                proposals[proposalId].proposalVoteInfo.voteHash
            )
        );
        bytes memory message = abi.encode(contractDataHash, proposalId, voteDecisionResult);
        require(_verifyEnclaveSig(_params.enclavePubKey, _params.enclaveSig, message), InvalidEnclaveSignature());

        // Handle the result
        VoteOutcome voteOutcome = _calcVoteResult(voteDecisionResult);
        _handleVoteOutcome(proposalId, voteOutcome);

        emit ResultSubmitted(proposalId, voteDecisionResult, voteOutcome);
    }

    /// @notice Refund the value sent for the proposal when result is not submitted and deadline has passed
    /// @dev Note: Deposited tokens cannot be fully refunded only when result is submitted with Passed or Failed
    function refund(bytes32 _proposalId) external nonReentrant {
        // If voteOutcome is still Pending, and the proposal deadline has passed, refund the deposit
        require(proposals[_proposalId].proposalInfo.proposer != address(0), ProposalDoesNotExist());
        ProposalTimeInfo storage proposalTimeInfo = proposals[_proposalId].proposalTimeInfo;
        VoteOutcome proposalVoteOutcome = proposals[_proposalId].voteOutcome;

        require(
            block.timestamp >= proposalTimeInfo.proposalDeadlineTimestamp && proposalVoteOutcome == VoteOutcome.Pending,
            NotRefundableProposal()
        );

        uint256 valueSum = _getValueSum(_proposalId);
        require(valueSum > 0, NoValueToRefund());
        _refundValue(_proposalId, valueSum);

        emit ExpiredProposalRefunded(_proposalId);
    }

    /// @dev Handles the outcome of a vote by updating the proposal state and processing deposits
    function _handleVoteOutcome(bytes32 _proposalId, VoteOutcome _voteOutcome) internal {
        proposals[_proposalId].voteOutcome = _voteOutcome;

        if (_voteOutcome == VoteOutcome.Passed) {
            if (proposals[_proposalId].proposalInfo.targets.length > 0) {
                _queueExecution(_proposalId);
            }
            _unlockDepositAndRefund(_proposalId);
        } else if (_voteOutcome == VoteOutcome.Failed) {
            _unlockDepositAndRefund(_proposalId);
            _refundValue(_proposalId, _getValueSum(_proposalId));
        } else if (_voteOutcome == VoteOutcome.Vetoed) {
            _slashDeposit(_proposalId);
            _refundValue(_proposalId, _getValueSum(_proposalId));
        }
    }

    function _getValueSum(bytes32 _proposalId) internal view returns (uint256) {
        uint256 valueSum;
        for (uint256 i = 0; i < proposals[_proposalId].proposalInfo.values.length; ++i) {
            valueSum += proposals[_proposalId].proposalInfo.values[i];
        }
        return valueSum;
    }

    /// @dev Refunds the ETH value sent with the proposal to the proposer
    function _refundValue(bytes32 _proposalId, uint256 _amount) internal {
        // Note: This will not revert even if the proposer is a contract without a payable fallback or receive function
        (bool ok,) = payable(proposals[_proposalId].proposalInfo.proposer).call{value: _amount}("");
        ok;

        emit ValueRefunded(_proposalId, proposals[_proposalId].proposalInfo.proposer, _amount);
    }

    /// @dev Queues a passed proposal for execution
    function _queueExecution(bytes32 _proposalId) internal {
        // This should never revert
        require(executionQueue[_proposalId] == false, ProposalAlreadyInQueue());
        require(proposals[_proposalId].executed == false, ProposalAlreadySubmitted());

        // Mark the proposal as queued for execution
        executionQueue[_proposalId] = true;
    }

    //-------------------------------- Result end --------------------------------//

    //-------------------------------- Execution start --------------------------------//

    /// @notice Executes a proposal that has been queued for execution
    /// @dev This function can only be called for proposals that have passed and been queued
    /// @dev The function executes all target contract calls with their specified values and calldata
    /// @param _proposalId The unique identifier of the proposal to execute
    function execute(bytes32 _proposalId) external whenNotPaused nonReentrant {
        require(executionQueue[_proposalId] == true, ProposalNotInQueue());
        require(proposals[_proposalId].executed == false, ProposalAlreadySubmitted());

        ProposalInfo storage proposalInfo = proposals[_proposalId].proposalInfo;
        address[] memory targets = proposalInfo.targets;
        uint256[] memory values = proposalInfo.values;
        bytes[] memory calldatas = proposalInfo.calldatas;

        proposals[_proposalId].executed = true;

        for (uint256 i = 0; i < targets.length; ++i) {
            (bool success, bytes memory returndata) = targets[i].call{value: values[i]}(calldatas[i]);
            Address.verifyCallResult(success, returndata);
        }

        emit ProposalExecuted(_proposalId);
        delete executionQueue[_proposalId];
    }

    //-------------------------------- Execution end --------------------------------//

    //-------------------------------- Helpers start --------------------------------//

    /// @dev Transfers tokens from proposer and locks them as deposit
    function _depositTokenAndLock(bytes32 _proposalId, address _token, uint256 _amount) internal {
        IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        _lockDeposit(_proposalId, _token, _amount);
    }

    /// @dev Stores the locked deposit information for a proposal
    function _lockDeposit(bytes32 _proposalId, address _token, uint256 _amount) internal {
        proposals[_proposalId].tokenLockInfo = TokenLockInfo({token: _token, amount: _amount});
        emit DepositLocked(_proposalId, _token, _amount);
    }

    /// @dev Unlocks and refunds the deposit tokens to the proposer
    function _unlockDepositAndRefund(bytes32 _proposalId) internal {
        TokenLockInfo memory tokenLockInfo = proposals[_proposalId].tokenLockInfo;
        _deleteDepositLock(_proposalId);
        IERC20(tokenLockInfo.token).safeTransfer(proposals[_proposalId].proposalInfo.proposer, tokenLockInfo.amount);
    }

    /// @dev Slashes a portion of the deposit based on vetoSlashRate and refunds the remainder
    function _slashDeposit(bytes32 _proposalId) internal {
        TokenLockInfo memory tokenLockInfo = proposals[_proposalId].tokenLockInfo;
        address proposer = proposals[_proposalId].proposalInfo.proposer;

        // Calculate slash amount based on vetoSlashRate
        uint256 slashAmount = (tokenLockInfo.amount * vetoSlashRate) / 1e18;
        uint256 refundAmount = tokenLockInfo.amount - slashAmount;

        // Transfer slashed amount to treasury
        if (slashAmount > 0) {
            IERC20(tokenLockInfo.token).safeTransfer(treasury, slashAmount);
        }

        // Refund remaining amount to proposer
        if (refundAmount > 0) {
            IERC20(tokenLockInfo.token).safeTransfer(proposer, refundAmount);
        }

        _deleteDepositLock(_proposalId);
        emit DepositSlashed(_proposalId, tokenLockInfo.token, slashAmount);
    }

    /// @dev Deletes the deposit lock information for a proposal
    function _deleteDepositLock(bytes32 _proposalId) internal {
        delete proposals[_proposalId].tokenLockInfo;
    }

    /// @dev Converts a public key to an Ethereum address
    /// @return address The Ethereum address derived from the public key
    function _pubKeyToAddress(bytes memory _pubKey) internal pure returns (address) {
        require(_pubKey.length == 64, InvalidPubKeyLength());

        bytes32 pubKeyHash = keccak256(_pubKey);
        return address(uint160(uint256(pubKeyHash)));
    }

    /// @dev Calculates the final outcome of a proposal based on vote counts and thresholds
    /// @return voteOutcome The final outcome of the proposal (Passed, Failed, or Vetoed)
    function _calcVoteResult(VoteDecisionResult memory _voteDecisionCount) internal view returns (VoteOutcome) {
        uint256 yes = _voteDecisionCount.yes;
        uint256 no = _voteDecisionCount.no;
        uint256 abstain = _voteDecisionCount.abstain;
        uint256 noWithVeto = _voteDecisionCount.noWithVeto;
        uint256 totalVotingPower = _voteDecisionCount.totalVotingPower;

        // Check Quorum
        if ((yes + no + abstain + noWithVeto) < (minQuorumThreshold * totalVotingPower) / 1e18) {
            return VoteOutcome.Failed;
        }

        // Check Pass
        if (yes > (no + noWithVeto) && yes > (proposalPassVetoThreshold * totalVotingPower) / 1e18) {
            return VoteOutcome.Passed;
        }

        // Check Veto
        if (
            yes < (no + noWithVeto) && no < noWithVeto
                && noWithVeto > (proposalPassVetoThreshold * totalVotingPower) / 1e18
        ) {
            return VoteOutcome.Vetoed;
        }

        // Otherwise, return Failed
        return VoteOutcome.Failed;
    }

    /// @dev Generates an image ID from PCR values for enclave verification
    /// @return imageId The generated image ID for enclave verification
    function _generateImageId(bytes memory _pcr0, bytes memory _pcr1, bytes memory _pcr2)
        internal
        pure
        returns (bytes32)
    {
        uint32 bitflags = uint32((1 << 0) | (1 << 1) | (1 << 2) | (1 << 16));
        bytes memory pcr16 = new bytes(48);
        return sha256(abi.encodePacked(bitflags, _pcr0, _pcr1, _pcr2, pcr16));
    }

    /// @dev Verifies the signature from an enclave using the provided public key
    /// @return isValid True if the signature is valid, false otherwise
    function _verifyEnclaveSig(bytes memory _enclavePubKey, bytes memory _enclaveSig, bytes memory message)
        internal
        pure
        returns (bool)
    {
        // Reconstruct the message to verify
        bytes32 digest = sha256(message);

        // Recover the address from the signature
        address recoveredAddress = digest.recover(_enclaveSig);

        // Convert the public key to address
        address enclaveAddress = _pubKeyToAddress(_enclavePubKey);

        // Compare the recovered address with the enclave address
        return recoveredAddress == enclaveAddress;
    }

    /// @dev Converts bytes32 to a hex string without the '0x' prefix
    /// @return hexString The hex string representation without '0x' prefix
    function _toHexStringWithNoPrefix(bytes32 data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            str[i * 2] = alphabet[uint8(data[i] >> 4)];
            str[i * 2 + 1] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    /// @notice Verifies a KMS signature for enclave public key derivation
    /// @dev This function reconstructs the URI and verifies the signature against the KMS root server public key
    /// @param _imageId The image ID used in the KMS path
    /// @param _enclavePubKey The enclave public key to verify
    /// @param _kmsSig The KMS signature to verify
    /// @return isValid True if the signature is valid, false otherwise
    function verifyKMSSig(bytes32 _imageId, bytes calldata _enclavePubKey, bytes calldata _kmsSig)
        public
        view
        returns (bool)
    {
        // Reconstruct URI (must match the format signed by the KMS)
        // Check: https://github.com/marlinprotocol/oyster-monorepo/tree/master/kms/root-server#public-endpoints
        string memory uri = string(
            abi.encodePacked(
                "/derive/secp256k1/public?image_id=", _toHexStringWithNoPrefix(_imageId), "&path=", kmsPath
            )
        );

        // Combine URI and binary public key
        bytes memory message = abi.encodePacked(bytes(uri), _enclavePubKey);

        // Hash the message
        bytes32 messageHash = sha256(message);

        // Recover signer address
        return messageHash.recover(_kmsSig) == _pubKeyToAddress(kmsRootServerPubKey);
    }

    //-------------------------------- Helpers end --------------------------------//

    //-------------------------------- Getters start --------------------------------//

    /// @dev Generates a unique proposal ID based on proposal parameters and proposer nonce
    /// @return proposalId The unique proposal identifier
    function _generateProposalId(
        address[] calldata _targets,
        uint256[] calldata _values,
        bytes[] calldata _calldatas,
        bytes32 _descriptionHash,
        address _proposer,
        uint256 _nonce
    ) internal pure returns (bytes32) {
        return sha256(abi.encode(_targets, _values, _calldatas, _descriptionHash, _proposer, _nonce));
    }

    /// @notice Retrieves the timing information for a specific proposal
    /// @dev Returns the complete timing structure including proposed, activation, voting deadline, and proposal deadline timestamps
    /// @param _proposalId The unique identifier of the proposal
    /// @return proposalTimeInfo The timing information structure for the proposal
    function getProposalTimeInfo(bytes32 _proposalId) public view returns (ProposalTimeInfo memory) {
        return proposals[_proposalId].proposalTimeInfo;
    }

    /// @notice Retrieves the complete proposal information for a specific proposal
    /// @dev Returns all proposal details including proposer, targets, values, calldatas, title, and description
    /// @param _proposalId The unique identifier of the proposal
    /// @return proposer The address of the proposal creator
    /// @return targets Array of target contract addresses for the proposal
    /// @return values Array of ETH values to send with each call
    /// @return calldatas Array of calldata for each target contract call
    /// @return title The title of the proposal
    /// @return description The description of the proposal
    function getProposalInfo(bytes32 _proposalId)
        public
        view
        returns (
            address proposer,
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory title,
            string memory description
        )
    {
        ProposalInfo storage proposalInfo = proposals[_proposalId].proposalInfo;
        return (
            proposalInfo.proposer,
            proposalInfo.targets,
            proposalInfo.values,
            proposalInfo.calldatas,
            proposalInfo.title,
            proposalInfo.description
        );
    }

    /// @notice Returns the current network hash that represents the state of all supported chains
    /// @dev This hash is used to verify that proposal execution happens with the same network configuration
    /// @return networkHash The current network hash
    function getNetworkHash() public view returns (bytes32) {
        return networkHash;
    }

    /// @notice Returns the vote hash for a given proposal ID
    /// @dev This hash represents the cumulative hash of all votes cast for the proposal
    /// @dev This does not check if the vote is done, so the hash could not be the final hash
    /// @param _proposalId The unique identifier of the proposal
    /// @return voteHash The vote hash for the proposal
    function getVoteHash(bytes32 _proposalId) public view returns (bytes32) {
        // reverts if proposal does not exist
        require(proposals[_proposalId].proposalInfo.proposer != address(0), ProposalDoesNotExist());

        ProposalVoteInfo storage proposalVoteInfo = proposals[_proposalId].proposalVoteInfo;
        return proposalVoteInfo.voteHash;
    }

    /// @notice Returns the total vote count for a given proposal
    /// @dev This function does not check if the vote is done, so the count could not be the final count
    /// @param _proposalId The unique identifier of the proposal
    /// @return voteCount The total number of votes cast for the proposal
    function getVoteCount(bytes32 _proposalId) external view returns (uint256) {
        // reverts if proposal does not exist
        require(proposals[_proposalId].proposalInfo.proposer != address(0), ProposalDoesNotExist());

        return proposals[_proposalId].proposalVoteInfo.voteCount;
    }

    /// @notice Returns the vote information for a specific vote index in a proposal
    /// @dev Returns the voter address and encrypted vote data for the specified vote index
    /// @param _proposalId The unique identifier of the proposal
    /// @param _idx The index of the vote to retrieve
    /// @return voter The address of the voter
    /// @return voteEncrypted The encrypted vote data
    function getVoteInfo(bytes32 _proposalId, uint256 _idx) external view returns (address, bytes memory) {
        require(_idx < proposals[_proposalId].proposalVoteInfo.voteCount, InvalidVoteIndex());
        return (
            proposals[_proposalId].proposalVoteInfo.votes[_idx].voter,
            proposals[_proposalId].proposalVoteInfo.votes[_idx].voteEncrypted
        );
    }

    /// @notice Returns all vote information for a specific proposal
    /// @dev Returns an array of all votes, the total vote count, and the cumulative vote hash
    /// @param _proposalId The unique identifier of the proposal
    /// @return votes Array of all votes cast for the proposal
    /// @return voteCount The total number of votes cast
    /// @return voteHash The cumulative hash of all votes
    function getAllVoteInfo(bytes32 _proposalId)
        external
        view
        returns (Vote[] memory votes, uint256 voteCount, bytes32 voteHash)
    {
        ProposalVoteInfo storage proposalVoteInfo = proposals[_proposalId].proposalVoteInfo;
        voteCount = proposalVoteInfo.voteCount;
        votes = new Vote[](voteCount);
        for (uint256 i = 0; i < voteCount; ++i) {
            votes[i] = proposalVoteInfo.votes[i];
        }
        voteHash = proposalVoteInfo.voteHash;
    }

    /// @notice Returns all network configurations for all supported chains
    /// @dev Returns arrays of chain IDs and their corresponding network configurations
    /// @return supportedChainIds Array of supported chain IDs
    /// @return tokenNetworkConfigs Array of token network configurations for each chain
    function getAllNetworkConfigs() external view returns (uint256[] memory, TokenNetworkConfig[] memory) {
        uint256 chainCount = supportedChainIds.length;
        TokenNetworkConfig[] memory tokenNetworkConfigList = new TokenNetworkConfig[](chainCount);
        for (uint256 i = 0; i < chainCount; ++i) {
            uint256 chainId = supportedChainIds[i];
            tokenNetworkConfigList[i] = tokenNetworkConfigs[chainId];
        }
        return (supportedChainIds, tokenNetworkConfigList);
    }

    //-------------------------------- Getters end --------------------------------//

    uint256[500] private __gap2;
}
