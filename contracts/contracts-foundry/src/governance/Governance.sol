// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

/* Contracts */
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {AccessControlEnumerableUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/* Interfaces */
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IGovernance} from "./interfaces/IGovernance.sol";

/* Libraries */
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract Governance is
    Initializable, // initializer
    ContextUpgradeable,
    ERC165Upgradeable, // supportsInterface
    AccessControlEnumerableUpgradeable, // RBAC enumeration
    PausableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    IGovernance
{
    using SafeERC20 for IERC20;
    using Strings for uint256;
    using ECDSA for bytes32;

    bytes32 public constant CONFIG_SETTER_ROLE = keccak256("CONFIG_SETTER_ROLE"); // 0x17df964a140c45e2553048f59e406d5adf9a078929e0ad3964333b8139768702

    uint256[500] private __gap0;

    IERC20 public usdc;

    /// @notice Token amount required to submit a proposal which will be locked until result is submitted
    mapping(address token => uint256 amount) proposalDepositAmounts;
    /// @notice Mapping of proposal IDs to their respective Proposal structs
    mapping(bytes32 id => Proposal) proposals;
    /// @notice Mapping of proposal IDs that are queued for execution when the result for the proposal is passed
    mapping(bytes32 id => bool) executionQueue;
    /// @notice Used to calculate proposalId
    /// @notice Each time proposal is submitted, the nonce is incremented to ensure uniqueness of proposalId
    /// @dev Starts from 0
    mapping(address proposer => uint256 nonce) proposerNonce;

    /* Proposal Config */
    ProposalTimingConfig public proposalTimingConfig;
    /// @notice Address where tokens are sent when proposal's vote outcome is Vetoed
    address treasury;

    /* KMS */
    PCR public pcrConfig;
    bytes public kmsRootServerPubKey;
    string public kmsPath;

    /* Token Network Config */
    bytes32 public networkHash;
    /// @notice An array of chain IDs where the token used to measure voting power in Governance has been deployed
    uint256[] public supportedChainIds;
    /// @notice Maximum number of RPC URLs allowed to be added per chain
    uint256 public maxRPCUrlsPerChain;
    /// @notice Mapping of chain IDs to their respective token network configurations
    mapping(uint256 chainId => TokenNetworkConfig config) tokenNetworkConfigs;

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
        override(ERC165Upgradeable, AccessControlEnumerableUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address /*account*/ ) internal view override onlyAdmin {}

    //-------------------------------- Overrides ends --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap1;

    function initialize(
        address _admin,
        address _configSetter,
        address _treasury,
        uint256 _voteActivationDelay,
        uint256 _voteDuration,
        uint256 _proposalDuration,
        uint256 _maxRPCUrlsPerChain,
        PCR calldata _pcrConfig,
        bytes calldata _kmsRootServerPubKey,
        string calldata _kmsPath
    ) public initializer {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __Pausable_init_unchained();

        // Set Roles
        require(_admin != address(0), ZeroAdminAddress());
        require(_configSetter != address(0), ZeroConfigSetterAddress());
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(CONFIG_SETTER_ROLE, _configSetter);

        // Set Treasury Address
        _setTreasury(_treasury);

        // Set Proposal Time Config
        require(_voteActivationDelay * _voteDuration * _proposalDuration > 0, ZeroProposalTimeConfig());
        _setVoteActivationDelay(_voteActivationDelay);
        _setVoteDuration(_voteDuration);
        _setProposalDuration(_proposalDuration);
        _checkProposalTimeConfig();

        // Set Max RPC URLs per Chain
        _setMaxRPCUrlsPerChain(_maxRPCUrlsPerChain);

        // Set PCR0, PCR1, PCR2
        _setPCRConfig(_pcrConfig.pcr0, _pcrConfig.pcr1, _pcrConfig.pcr2);

        // Set KMS Config
        _setKMSRootServerKey(_kmsRootServerPubKey);
        _setKMSPath(_kmsPath);

        // Note: setTokenLockAmount, setNetworkConfig should be seperately called after initialization
    }

    //-------------------------------- Initializer end --------------------------------//

    //-------------------------------- Admin start --------------------------------//

    function setTokenLockAmount(address _token, uint256 _amount) external onlyConfigSetter {
        proposalDepositAmounts[_token] = _amount;
        emit TokenLockAmountSet(_token, _amount);
    }

    function setTreasury(address _treasury) external onlyConfigSetter {
        _setTreasury(_treasury);
    }

    function _setTreasury(address _treasury) internal {
        require(_treasury != address(0), ZeroTreasuryAddress());
        treasury = _treasury;
        emit TreasurySet(_treasury);
    }

    function setProposalTimingConfig(uint256 _voteActivationDelay, uint256 _voteDuration, uint256 _proposalDuration)
        external
        onlyConfigSetter
    {
        require(_voteActivationDelay * _voteDuration * _proposalDuration > 0, ZeroProposalTimeConfig());

        if (_voteActivationDelay > 0) {
            _setVoteActivationDelay(_voteActivationDelay);
        }

        if (_voteDuration > 0) {
            _setVoteDuration(_voteDuration);
        }

        if (_proposalDuration > 0) {
            _setProposalDuration(_proposalDuration);
        }

        _checkProposalTimeConfig();
    }

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
    /// @param _rpcUrls An array of RPC URLs for the specified chain
    function setNetworkConfig(uint256 _chainId, address _tokenAddress, string[] calldata _rpcUrls)
        public
        onlyConfigSetter
    {
        require(_chainId > 0, InvalidChainId());
        require(_tokenAddress != address(0), InvalidTokenAddress());
        require(_rpcUrls.length > 0, InvalidRpcUrl());
        require(_rpcUrls.length <= maxRPCUrlsPerChain, MaxRpcUrlsPerChainReached());
        for( uint256 i = 0; i < _rpcUrls.length; ++i) {
            require(bytes(_rpcUrls[i]).length > 0, InvalidRpcUrl());
        }

        // Check if the token address is already set for the chainId
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
        bytes32 chainHash = keccak256(abi.encode(_chainId, _rpcUrls));
        tokenNetworkConfigs[_chainId] =
            TokenNetworkConfig({chainHash: chainHash, tokenAddress: _tokenAddress, rpcUrls: _rpcUrls});

        emit NetworkConfigSet(_chainId, _tokenAddress, _rpcUrls);
    }

    /// @notice Adds a new RPC URL for the specified chainId into rpcUrls array
    function addRpcUrl(uint256 _chainId, string[] calldata _rpcUrl) external onlyConfigSetter {
        require(_chainId > 0, InvalidChainId());

        if (tokenNetworkConfigs[_chainId].rpcUrls.length == maxRPCUrlsPerChain) {
            revert MaxRpcUrlsPerChainReached();
        }

        // Check RPC url length
        for (uint256 i = 0; i < _rpcUrl.length; ++i) {
            require(bytes(_rpcUrl[i]).length > 0, InvalidRpcUrl());
        }

        // Check if the chainId is supported
        bool chainIdExists = false;
        for (uint256 i = 0; i < supportedChainIds.length; ++i) {
            if (supportedChainIds[i] == _chainId) {
                chainIdExists = true;
                break;
            }
        }
        require(chainIdExists, InvalidChainId());

        // Add the new RPC URL to the rpcUrls array for the specified chainId
        TokenNetworkConfig storage config = tokenNetworkConfigs[_chainId];
        for (uint256 i = 0; i < _rpcUrl.length; ++i) {
            require(bytes(_rpcUrl[i]).length > 0, InvalidRpcUrl());
            config.rpcUrls.push(_rpcUrl[i]);
        }

        // Emit an event for the added RPC URL
        for (uint256 i = 0; i < _rpcUrl.length; ++i) {
            emit RpcUrlAdded(_chainId, _rpcUrl[i]);
        }
    }

    /// @notice Updates an existing RPC URL for the specified chainId at the given index
    function updateRpcUrl(uint256 _chainId, uint256 _index, string calldata _rpcUrl) external onlyConfigSetter {
        require(_chainId > 0, InvalidChainId());
        require(_index < tokenNetworkConfigs[_chainId].rpcUrls.length, InvalidRpcUrl());
        require(bytes(_rpcUrl).length > 0, InvalidRpcUrl());

        tokenNetworkConfigs[_chainId].rpcUrls[_index] = _rpcUrl;
        emit RpcUrlUpdated(_chainId, _index, _rpcUrl);
    }

    /// @notice Sets KMS Root Server Key
    function setKMSRootServerKey(bytes calldata _kmsRootServerPubKey) external onlyConfigSetter {
        _setKMSRootServerKey(_kmsRootServerPubKey);
    }

    function _setKMSRootServerKey(bytes calldata _kmsRootServerPubKey) internal {
        require(_kmsRootServerPubKey.length > 0, "KMS Root Server Public Key cannot be empty");
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
        require(bytes(_kmsPath).length > 0, "KMS Path cannot be empty");
        kmsPath = _kmsPath;
        emit KMSPathSet(_kmsPath);
    }

    function setPCRConfig(bytes calldata _pcr0, bytes calldata _pcr1, bytes calldata _pcr2) external onlyConfigSetter {
        _setPCRConfig(_pcr0, _pcr1, _pcr2);
    }

    function _setPCRConfig(bytes calldata _pcr0, bytes calldata _pcr1, bytes calldata _pcr2) internal {
        require(_pcr0.length > 0 && _pcr1.length > 0 && _pcr2.length > 0, InvalidPCRLength());
        pcrConfig = PCR({pcr0: _pcr0, pcr1: _pcr1, pcr2: _pcr2});
        emit PCRConfigSet(_pcr0, _pcr1, _pcr2);
    }

    /// @dev Condition `voteActivationDelay + voteDuration < proposalDuration` is not checked here
    function _setVoteActivationDelay(uint256 _voteActivationDelay) internal {
        proposalTimingConfig.voteActivationDelay = _voteActivationDelay;
        emit VoteActivationDelaySet(_voteActivationDelay);
    }

    /// @dev Condition `voteActivationDelay + voteDuration < proposalDuration` is not checked here
    function _setVoteDuration(uint256 _voteDuration) internal {
        proposalTimingConfig.voteDuration = _voteDuration;
        emit VoteDurationSet(_voteDuration);
    }

    /// @dev Condition `voteActivationDelay + voteDuration < proposalDuration` is not checked here
    function _setProposalDuration(uint256 _proposalDuration) internal {
        proposalTimingConfig.proposalDuration = _proposalDuration;
        emit ProposalDurationSet(_proposalDuration);
    }

    /// @dev Checks if the proposal timing configuration is valid
    /// @dev Condition `voteActivationDelay + voteDuration < proposalDuration` must hold true
    function _checkProposalTimeConfig() internal view {
        ProposalTimingConfig memory config = proposalTimingConfig;

        // Note: ResultSubmissionDuration = proposalDuration - (voteActivationDelay + voteDuration)
        require(config.voteActivationDelay + config.voteDuration < config.proposalDuration, InvalidProposalTimeConfig());
    }

    function _calcNetworkHash() internal view returns (bytes32) {
        bytes memory chainHashEncoded;
        for (uint256 i = 0; i < supportedChainIds.length; ++i) {
            uint256 chainId = supportedChainIds[i];
            bytes32 chainHash = tokenNetworkConfigs[chainId].chainHash;
            abi.encode(networkHash, chainHash);
        }

        return keccak256(chainHashEncoded);
    }

    function pause() external whenNotPaused onlyAdmin {
        _pause();
    }

    function unpause() external whenPaused onlyAdmin {
        _unpause();
    }

    //-------------------------------- Admin end --------------------------------//

    //-------------------------------- Propose start --------------------------------//

    function propose(
        address _depositToken,
        address[] calldata _targets,
        uint256[] calldata _values,
        bytes[] calldata _calldatas,
        string calldata _title,
        string calldata _description
    ) external payable whenNotPaused returns (bytes32 proposalId) {
        require(supportedChainIds.length > 0, NoSupportedChainConfigured());
        // Input Validation
        require(_targets.length == _values.length, InvalidInputLength());
        require(_targets.length == _calldatas.length, InvalidInputLength());
        require(bytes(_title).length > 0, InvalidTitleLength());
        require(bytes(_description).length > 0, InvalidDescriptionLength());

        for (uint256 i = 0; i < _targets.length; ++i) {
            require(_targets[i] != address(this), InvalidTargetAddress());
        }

        uint256 valueSum;
        for (uint256 i = 0; i < _values.length; ++i) {
            if (_values[i] > 0) {
                valueSum += _values[i];
            }
        }
        require(valueSum == msg.value, InvalidMsgValue());

        // Calculate proposalId
        bytes32 descriptionHash = getDescriptionHash(_title, _description);
        proposalId =
            getProposalId(_targets, _values, _calldatas, descriptionHash, msg.sender, proposerNonce[msg.sender]);
        proposerNonce[msg.sender] += 1;

        // Ensure that the proposal does not already exist
        require(proposals[proposalId].proposalInfo.proposer == address(0), ProposalAlreadyExists());

        // Deposit token and lock
        uint256 depositAmount = proposalDepositAmounts[_depositToken];
        // Only Accept tokens with non-zero threshold
        require(depositAmount > 0, TokenNotSupported());
        if (proposalDepositAmounts[_depositToken] == 0) {
            revert TokenNotSupported();
        }
        _depositTokenAndLock(proposalId, _depositToken, depositAmount);

        // Store the proposal information
        proposals[proposalId].proposalInfo = ProposalInfo({
            proposer: msg.sender,
            targets: _targets,
            values: _values,
            calldatas: _calldatas,
            title: _title,
            description: _description
        });

        // Set the proposal time information
        proposals[proposalId].proposalTimeInfo = ProposalTimeInfo({
            proposedTimestamp: block.timestamp,
            voteActivationTimestamp: block.timestamp + proposalTimingConfig.voteActivationDelay,
            voteDeadlineTimestamp: block.timestamp + proposalTimingConfig.voteActivationDelay
                + proposalTimingConfig.voteDuration,
            proposalDeadlineTimestamp: block.timestamp + proposalTimingConfig.proposalDuration
        });

        proposals[proposalId].networkHash = getNetworkHash();

        emit ProposalCreated(
            proposalId,
            msg.sender,
            proposerNonce[msg.sender],
            _targets,
            _values,
            _calldatas,
            _title,
            _description,
            proposals[proposalId].proposalTimeInfo
        );
    }

    function _updateVoteHash(bytes32 _proposalId, bytes32 _voteEncryptedHash) internal {
        bytes32 voteHasOld = proposals[_proposalId].proposalVoteInfo.voteHash;
        bytes32 voteHashUpdated = keccak256(abi.encode(voteHasOld, _voteEncryptedHash));
        proposals[_proposalId].proposalVoteInfo.voteHash = voteHashUpdated;
    }

    function _incrementVoteCount(bytes32 _proposalId) internal {
        proposals[_proposalId].proposalVoteInfo.voteCount++;
    }

    function vote(bytes32 _proposalId, bytes calldata _voteEncrypted) external {
        // Check if the proposal exists
        require(proposals[_proposalId].proposalInfo.proposer != address(0), ProposalDoesNotExist());

        // Chech if the proposal is active
        ProposalTimeInfo storage proposalTimeInfo = proposals[_proposalId].proposalTimeInfo;
        uint256 voteActivationTimestamp = proposalTimeInfo.voteActivationTimestamp;
        uint256 voteDeadlineTimestamp = proposalTimeInfo.voteDeadlineTimestamp;
        require(
            block.timestamp >= voteActivationTimestamp && block.timestamp < voteDeadlineTimestamp, VotingNotActive()
        );

        // Increment the vote count
        _incrementVoteCount(_proposalId);

        // Store the vote
        Proposal storage proposal = proposals[_proposalId];
        ProposalVoteInfo storage proposalVoteInfo = proposal.proposalVoteInfo;
        uint256 voteIdx = proposalVoteInfo.voteCount;
        proposalVoteInfo.votes[voteIdx] = Vote({voter: msg.sender, voteEncrypted: _voteEncrypted});

        // Update Vote Hash of the proposal
        bytes32 voteEncryptedHash = keccak256(_voteEncrypted);
        _updateVoteHash(_proposalId, voteEncryptedHash);

        emit VoteSubmitted(_proposalId, voteIdx, msg.sender, _voteEncrypted);
    }

    //-------------------------------- Propose end --------------------------------//

    //-------------------------------- Result start --------------------------------//

    /// @param _resultData ABI-encoded bytes data of four values: contractDataHash, pcr16Sha256, pcr16Sha384, and voteResult
    function submitResult(
        bytes32 _proposalId,
        bytes calldata _kmsSig,
        bytes calldata _enclavePubKey,
        bytes calldata _enclaveSig,
        bytes calldata _resultData
    ) external nonReentrant {
        require(proposals[_proposalId].proposalInfo.proposer != address(0), ProposalDoesNotExist());

        // Check if the proposal in Result Submission Phase
        ProposalTimeInfo storage proposalTimeInfo = proposals[_proposalId].proposalTimeInfo;
        require(
            block.timestamp >= proposalTimeInfo.voteDeadlineTimestamp
                && block.timestamp < proposalTimeInfo.proposalDeadlineTimestamp,
            NotResultSubmissionPhase()
        );

        // Check if the result of the proposal is not already submitted
        require(proposals[_proposalId].voteOutcome == VoteOutcome.Pending, ResultAlreadySubmitted());

        // Decode `_resultData`
        (bytes32 pcr16Sha256, bytes memory pcr16Sha384, VoteDecisionCount memory voteDecisionCount) =
            _decodeResultData(_resultData);

        // Compare pcr16Sha256 with calculated value
        require(pcr16Sha256 == _getPCR16Sha256(_proposalId), InvalidPCR16Sha256());

        // Verify Enclave Sig
        require(_verifyEnclaveSig(_enclavePubKey, _enclaveSig, _resultData), InvalidEnclaveSignature());

        // Generate Image ID from pcr16Sha384 and verify KMS signature
        require(verifyKMSSig(_generateImageId(pcr16Sha384), _enclavePubKey, _kmsSig), InvadidKMSSignature());

        // Handle the result
        VoteOutcome voteCoutome = _calcResult(voteDecisionCount);
        proposals[_proposalId].voteOutcome = voteCoutome;
        if (voteCoutome == VoteOutcome.Passed) {
            _handleProposalPassed(_proposalId);
        } else if (voteCoutome == VoteOutcome.Failed) {
            _handleProposalFailed(_proposalId);
        } else if (voteCoutome == VoteOutcome.Vetoed) {
            _handleProposalVetoed(_proposalId);
        }
        // Write the result to the proposal
        proposals[_proposalId].voteOutcome = voteCoutome;

        emit ResultSubmitted(_proposalId, voteDecisionCount, voteCoutome);
    }

    function _handleProposalPassed(bytes32 _proposalId) internal {
        // Executed only if the proposal has on-chain execution targets
        if (proposals[_proposalId].proposalInfo.targets.length > 0) {
            _queueExecution(_proposalId);
        }

        _unlockDepositAndRefund(_proposalId);
    }

    function _handleProposalFailed(bytes32 _proposalId) internal {
        // Refund the deposit to the proposer
        _unlockDepositAndRefund(_proposalId);

        // Refund Value
        _refundValue(_proposalId);
    }

    function _refundValue(bytes32 _proposalId) internal {
        // Refund eth sent
        uint256 valueSum;
        for (uint256 i = 0; i < proposals[_proposalId].proposalInfo.values.length; ++i) {
            valueSum += proposals[_proposalId].proposalInfo.values[i];
        }

        address proposer = proposals[_proposalId].proposalInfo.proposer;
        if (valueSum > 0) {
            // Note: This will not revert if the transfer fails, and it will not refund to proposer
            (bool ok,) = payable(proposer).call{value: valueSum}("");
            ok;
        }

        emit ValueRefunded(_proposalId, proposer, valueSum);
    }

    function _handleProposalVetoed(bytes32 _proposalId) internal {
        _refundValue(_proposalId);
        _slashDeposit(_proposalId);
    }

    function _queueExecution(bytes32 _proposalId) internal {
        // This should never revert
        require(executionQueue[_proposalId] == false, ProposalAlreadyInQueue());
        require(proposals[_proposalId].executed == false, ProposalAlreadySubmitted());

        // Mark the proposal as queued for execution
        executionQueue[_proposalId] = true;
    }

    function execute(bytes32 _proposalId) external whenNotPaused {
        // Check if the proposal is queued for execution
        require(executionQueue[_proposalId] == true, ProposalNotInQueue());

        // Check if the proposal is not executed yet
        require(proposals[_proposalId].executed == false, ProposalAlreadySubmitted());

        // Execute the proposal
        _execute(_proposalId);

        // Mark the proposal as executed
        proposals[_proposalId].executed = true;

        emit ProposalExecuted(_proposalId);

        // Remove the proposal from the execution queue
        delete executionQueue[_proposalId];
    }

    function _execute(bytes32 _proposalId) internal {
        ProposalInfo storage proposalInfo = proposals[_proposalId].proposalInfo;
        address[] memory targets = proposalInfo.targets;
        uint256[] memory values = proposalInfo.values;
        bytes[] memory calldatas = proposalInfo.calldatas;

        proposals[_proposalId].executed = true;

        for (uint256 i = 0; i < targets.length; ++i) {
            (bool success, bytes memory returndata) = targets[i].call{value: values[i]}(calldatas[i]);
            Address.verifyCallResult(success, returndata);
        }
    }

    //-------------------------------- Result end --------------------------------//

    //-------------------------------- Helpers start --------------------------------//

    function _depositTokenAndLock(bytes32 _proposalId, address _token, uint256 _amount) internal {
        IERC20(_token).transferFrom(msg.sender, address(this), _amount);
        _lockDeposit(_proposalId, _token, _amount);
    }

    function _unlockDepositAndRefund(bytes32 _proposalId) internal {
        TokenLockInfo memory tokenLockInfo = proposals[_proposalId].tokenLockInfo;
        _deleteDepositLock(_proposalId);
        IERC20(tokenLockInfo.token).safeTransfer(proposals[_proposalId].proposalInfo.proposer, tokenLockInfo.amount);
    }

    function _slashDeposit(bytes32 _proposalId) internal {
        // Transfer the deposit to treasury
        TokenLockInfo memory tokenLockInfo = proposals[_proposalId].tokenLockInfo;
        IERC20(tokenLockInfo.token).safeTransfer(treasury, tokenLockInfo.amount);
        _deleteDepositLock(_proposalId);
        emit DepositSlashed(
            _proposalId, proposals[_proposalId].tokenLockInfo.token, proposals[_proposalId].tokenLockInfo.amount
        );
    }

    function _lockDeposit(bytes32 _proposalId, address _token, uint256 _amount) internal {
        proposals[_proposalId].tokenLockInfo = TokenLockInfo({token: _token, amount: _amount});
        emit DepositLocked(_proposalId, _token, _amount);
    }

    function _deleteDepositLock(bytes32 _proposalId) internal {
        delete proposals[_proposalId].tokenLockInfo;
    }

    function _boolToString(bool v) internal pure returns (string memory) {
        return v ? "true" : "false";
    }

    function _pubKeyToAddress(bytes memory _pubKey) internal pure returns (address) {
        require(_pubKey.length == 64, InvalidPubKeyLength());

        bytes32 hash = keccak256(_pubKey);
        return address(uint160(uint256(hash)));
    }

    function _getPCR16Sha256(bytes32 _proposalId) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                address(this),
                _proposalId,
                proposals[_proposalId].proposalTimeInfo.proposedTimestamp,
                getContractDataHash(_proposalId)
            )
        );
    }

    /// @notice Calculates the result of the proposal based on the vote result
    function _calcResult(VoteDecisionCount memory _voteDecisionCount) internal pure returns (VoteOutcome) {
        if (_voteDecisionCount.yesCount > (_voteDecisionCount.noCount + _voteDecisionCount.noWithVetoCount)) {
            // Proposal passed
            return VoteOutcome.Passed;
        } else {
            return _voteDecisionCount.noCount > _voteDecisionCount.noWithVetoCount
                ? VoteOutcome.Failed
                : VoteOutcome.Vetoed;
        }
    }

    function _generateImageId(bytes memory _pcr16Sha384) internal view returns (bytes32) {
        uint32 flags = uint32((1 << 0) | (1 << 1) | (1 << 2) | (1 << 16));
        bytes memory data = abi.encode(bytes4(flags), pcrConfig.pcr0, pcrConfig.pcr1, pcrConfig.pcr2, _pcr16Sha384);
        return keccak256(data);
    }

    function _decodeResultData(bytes memory _resultData)
        internal
        pure
        returns (bytes32 pcr16Sha256, bytes memory pcr16Sha384, VoteDecisionCount memory voteResult)
    {
        // Decode the result data
        (pcr16Sha256, pcr16Sha384, voteResult) = abi.decode(_resultData, (bytes32, bytes, VoteDecisionCount));
    }

    function _verifyEnclaveSig(bytes memory _enclavePubKey, bytes memory _enclaveSig, bytes memory _resultData)
        internal
        pure
        returns (bool)
    {
        // Reconstruct the message to verify
        bytes32 messageHash = keccak256(_resultData);

        // Recover the address from the signature
        address recoveredAddress = messageHash.recover(_enclaveSig);

        // Convert the public key to address
        address enclaveAddress = _pubKeyToAddress(_enclavePubKey);

        // Compare the recovered address with the enclave address
        return recoveredAddress == enclaveAddress;
    }

    function verifyKMSSig(bytes32 _imageId, bytes calldata _enclavePubKey, bytes calldata _kmsSig)
        public
        view
        returns (bool)
    {
        // Reconstruct URI (must match the format signed by the KMS)
        // Check: https://github.com/marlinprotocol/oyster-monorepo/tree/master/kms/root-server#public-endpoints
        string memory uri = string(abi.encodePacked("/derive/secp256k1/public?image_id=", _imageId, "&path=", kmsPath));

        // Combine URI and binary public key
        bytes memory message = abi.encodePacked(bytes(uri), _enclavePubKey);

        // Hash the message
        bytes32 messageHash = keccak256(message);

        // Recover signer address
        address kmsRootAddress = _pubKeyToAddress(kmsRootServerPubKey);
        address recovered = messageHash.recover(_kmsSig);

        // Compare with known trusted signer
        return recovered == kmsRootAddress;
    }

    //-------------------------------- Helpers end --------------------------------//

    //-------------------------------- Getters start --------------------------------//

    function getProposalId(
        address[] calldata _targets,
        uint256[] calldata _values,
        bytes[] calldata _calldatas,
        bytes32 _descriptionHash,
        address _proposer,
        uint256 _nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(_targets, _values, _calldatas, _descriptionHash, _proposer, _nonce));
    }

    function getProposalTimeInfo(bytes32 _proposalId) public view returns (ProposalTimeInfo memory) {
        return proposals[_proposalId].proposalTimeInfo;
    }

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

    function getDescriptionHash(string calldata _title, string calldata _description) public pure returns (bytes32) {
        return keccak256(abi.encode(_title, _description));
    }

    function getNetworkHash() public view returns (bytes32) {
        return networkHash;
    }

    /// @notice Returns the hash of the contract data for a given proposal ID
    /// @notice Contract data hash is
    function getContractDataHash(bytes32 _proposalId) public view returns (bytes32) {
        return keccak256(abi.encode(getNetworkHash(), getVoteHash(_proposalId)));
    }

    /// @notice Returns the network hash for a given proposal ID
    function getVoteHash(bytes32 _proposalId) public view returns (bytes32) {
        // reverts if proposal does not exist
        require(proposals[_proposalId].proposalInfo.proposer != address(0), ProposalDoesNotExist());

        // reverts if voting is not done
        ProposalTimeInfo storage proposalTimeInfo = proposals[_proposalId].proposalTimeInfo;
        require(block.timestamp >= proposalTimeInfo.voteDeadlineTimestamp, VotingNotDone());

        ProposalVoteInfo storage proposalVoteInfo = proposals[_proposalId].proposalVoteInfo;
        return proposalVoteInfo.voteHash;
    }

    function getVoteCount(bytes32 _proposalI) external view returns (uint256) {
        // reverts if proposal does not exist
        require(proposals[_proposalI].proposalInfo.proposer != address(0), ProposalDoesNotExist());

        // reverts if voting is not done
        ProposalTimeInfo storage proposalTimeInfo = proposals[_proposalI].proposalTimeInfo;
        require(block.timestamp >= proposalTimeInfo.voteDeadlineTimestamp, VotingNotDone());

        return proposals[_proposalI].proposalVoteInfo.voteCount;
    }

    function getVoteInfo(bytes32 _proposalId, uint256 _idx) external view returns (address, bytes memory) {
        return (
            proposals[_proposalId].proposalVoteInfo.votes[_idx].voter,
            proposals[_proposalId].proposalVoteInfo.votes[_idx].voteEncrypted
        );
    }

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

    function getNetworkList() external view returns (uint256[] memory, TokenNetworkConfig[] memory) {
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
