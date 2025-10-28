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
import {IGovernanceEnclave} from "./interfaces/IGovernanceEnclave.sol";

/* Libraries */
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
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

    // ========== Constants ==========
    bytes32 public constant CONFIG_SETTER_ROLE = keccak256("CONFIG_SETTER_ROLE");

    // ========== Storage Gaps ==========
    uint256[500] private __gap0;

    // ========== State Variables ==========

    // Core Contracts
    address public treasury;
    address public governanceEnclave;
    mapping (uint256 chainId => address governanceDelegation) public governanceDelegations;
    uint256[] public delegationChainIds;
    bytes32 public contractConfigHash;

    // Proposal Management
    mapping(address token => uint256 amount) public proposalDepositAmounts;
    mapping(bytes32 id => Proposal) private proposals;
    mapping(bytes32 id => bool) public executionQueue;
    mapping(bytes32 proposalId => bytes) public voteDecryptionKeys;
    mapping(address proposer => uint256 nonce) public proposerNonce;

    // Proposal Configuration
    ProposalTimingConfig private proposalTimingConfig;
    uint256 public minQuorumThreshold;
    uint256 public proposalPassVetoThreshold;
    uint256 public vetoSlashRate;

    uint256[50] private __gap1;

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), Governance__OnlyDefaultAdmin());
        _;
    }

    modifier onlyConfigSetter() {
        require(hasRole(CONFIG_SETTER_ROLE, _msgSender()), Governance__OnlyConfigSetter());
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
    function initialize(
        address _admin,
        address _configSetter,
        address _treasury,
        address _governanceEnclave,
        uint256 _minQuorumThreshold,
        uint256 _proposalPassVetoThreshold,
        uint256 _vetoSlashRate,
        uint256 _voteActivationDelay,
        uint256 _voteDuration,
        uint256 _proposalDuration
    ) public initializer {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __Pausable_init_unchained();

        // Set Roles
        require(_admin != address(0), Governance__InvalidAddress());
        require(_configSetter != address(0), Governance__InvalidAddress());
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(CONFIG_SETTER_ROLE, _configSetter);

        // Set Treasury Address
        _setTreasury(_treasury);

        // Set Governance Enclave
        _setGovernanceEnclave(_governanceEnclave);

        // Set Proposal Pass Threshold
        _setProposalPassVetoThreshold(_proposalPassVetoThreshold);

        // Set Min Quorum Threshold
        _setMinQuorumThreshold(_minQuorumThreshold);

        // Set Veto Slash Rate
        _setVetoSlashRate(_vetoSlashRate);

        // Set Proposal Time Config
        _setProposalTimingConfig(_voteActivationDelay, _voteDuration, _proposalDuration);

        // Note: setTokenLockAmount, setNetworkConfig should be seperately called after initialization
    }

    //-------------------------------- Initializer end --------------------------------//

    //-------------------------------- Admin start --------------------------------//

    function setGovernanceEnclave(address _governanceEnclave) external onlyConfigSetter {
        _setGovernanceEnclave(_governanceEnclave);
    }

    function _setGovernanceEnclave(address _governanceEnclave) internal {
        require(_governanceEnclave != address(0), Governance__InvalidAddress());
        governanceEnclave = _governanceEnclave;
        
        // Update contract config hash when governance enclave changes
        contractConfigHash = _calcContractConfigHash();
        
        emit GovernanceEnclaveSet(_governanceEnclave);
    }

    /// @notice Adds a governance delegation for a specific chain
    /// @dev Adds the chain ID to delegationChainIds array if not already present
    /// @param _chainId The chain ID to add delegation for
    /// @param _governanceDelegation The governance delegation contract address
    function addGovernanceDelegation(uint256 _chainId, address _governanceDelegation) external onlyConfigSetter {
        require(_chainId != 0, Governance__InvalidAddress());
        require(_governanceDelegation != address(0), Governance__InvalidAddress());
        require(governanceDelegations[_chainId] == address(0), Governance__InvalidAddress());

        governanceDelegations[_chainId] = _governanceDelegation;
        delegationChainIds.push(_chainId);
        
        // Update contract config hash
        contractConfigHash = _calcContractConfigHash();
        
        emit GovernanceDelegationAdded(_chainId, _governanceDelegation);
    }

    /// @notice Removes a governance delegation at a specific index
    /// @dev Removes by swapping with the last element and popping
    /// @param _index The index in delegationChainIds array to remove
    function removeGovernanceDelegation(uint256 _index) external onlyConfigSetter {
        require(_index < delegationChainIds.length, Governance__InvalidAddress());

        uint256 chainIdToRemove = delegationChainIds[_index];
        
        // Remove from mapping
        delete governanceDelegations[chainIdToRemove];
        
        // Remove from array by swapping with last element and popping
        delegationChainIds[_index] = delegationChainIds[delegationChainIds.length - 1];
        delegationChainIds.pop();
        
        // Update contract config hash
        contractConfigHash = _calcContractConfigHash();
        
        emit GovernanceDelegationRemoved(chainIdToRemove);
    }

    /// @notice Calculates the contract config hash from governanceEnclave and all configured governance delegations
    /// @dev Uses iterative hashing for gas efficiency - hashes governanceEnclave first, then chains each 
    ///      (chainId, address) pair to create a hash for integrity verification
    /// @return currentHash The computed contract config hash representing the current governance configuration
    function _calcContractConfigHash() internal view returns (bytes32) {
        bytes32 currentHash = sha256(abi.encode(governanceEnclave));
        for (uint256 i = 0; i < delegationChainIds.length; ++i) {
            uint256 chainId = delegationChainIds[i];
            address delegation = governanceDelegations[chainId];
            currentHash = sha256(abi.encode(currentHash, chainId, delegation));
        }
        return currentHash;
    }

    /// @notice Sets the required deposit amount for a specific token when creating proposals
    /// @dev This function allows config setters to specify how much of a particular token must be deposited to create a proposal
    /// @param _token The address of the token for which to set the deposit amount
    /// @param _amount The amount of tokens required as deposit for proposal creation
    function setTokenLockAmount(address _token, uint256 _amount) external onlyConfigSetter {
        require(_amount > 0, Governance__InvalidAddress());
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
        require(_proposalPassVetoThreshold > 0, Governance__ZeroProposalPassThreshold());
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
        require(_minQuorumThreshold > 0, Governance__InvalidMinQuorumThreshold());
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
        require(_vetoSlashRate <= 1e18, Governance__InvalidVetoSlashRate());
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
        require(_treasury != address(0), Governance__InvalidAddress());
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

    function _setProposalTimingConfig(uint256 _voteActivationDelay, uint256 _voteDuration, uint256 _proposalDuration)
        internal
    {
        require(_voteActivationDelay + _voteDuration + _proposalDuration > 0, Governance__ZeroProposalTimeConfig());
        _updateTimingConfigs(_voteActivationDelay, _voteDuration, _proposalDuration);
        require(
            proposalTimingConfig.voteActivationDelay + proposalTimingConfig.voteDuration
                < proposalTimingConfig.proposalDuration,
            Governance__InvalidProposalTimeConfig()
        );
    }

    function _updateTimingConfigs(uint256 _voteActivationDelay, uint256 _voteDuration, uint256 _proposalDuration)
        internal
    {
        if (_voteActivationDelay > 0) _setVoteActivationDelay(_voteActivationDelay);
        if (_voteDuration > 0) _setVoteDuration(_voteDuration);
        if (_proposalDuration > 0) _setProposalDuration(_proposalDuration);
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
        _validateProposalInput(_params);
        bytes32 proposalId = _createProposalId(_params);
        require(proposals[proposalId].proposalInfo.proposer == address(0), Governance__ProposalAlreadyExists());

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

    function _validateProposalInput(ProposeInputParams calldata _params) internal view {
        require(
            _params.targets.length == _params.values.length && _params.targets.length == _params.calldatas.length,
            Governance__InvalidInputLength()
        );
        require(
            bytes(_params.title).length > 0 && bytes(_params.description).length > 0, Governance__InvalidTitleLength()
        );
        for (uint256 i = 0; i < _params.targets.length; ++i) {
            require(_params.targets[i] != address(this), Governance__InvalidAddress());
        }
        uint256 valueSum;
        for (uint256 i = 0; i < _params.values.length; ++i) {
            if (_params.values[i] > 0) valueSum += _params.values[i];
        }
        require(valueSum == msg.value, Governance__InvalidMsgValue());
        require(proposalDepositAmounts[_params.depositToken] > 0, Governance__TokenNotSupported());

        // Check if at least one supported chain is configured
        require(
            IGovernanceEnclave(governanceEnclave).getSupportedChainIdsLength() > 0,
            Governance__NoSupportedChainConfigured()
        );
    }

    function _createProposalId(ProposeInputParams calldata _params) internal view returns (bytes32) {
        bytes32 descriptionHash = sha256(abi.encode(_params.title, _params.description));
        return sha256(
            abi.encode(
                _params.targets,
                _params.values,
                _params.calldatas,
                descriptionHash,
                msg.sender,
                proposerNonce[msg.sender]
            )
        );
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

        proposals[_proposalId].networkHash = _getCurrentNetworkHash();
        proposals[_proposalId].contractConfigHash = contractConfigHash;
        proposals[_proposalId].imageId = IGovernanceEnclave(governanceEnclave).getImageId();
    }

    //-------------------------------- Propose end --------------------------------//

    //-------------------------------- Vote start --------------------------------//

    /// @notice Submits encrypted votes for a proposal
    /// @dev This function can only be called during the active voting period of the proposal
    /// @dev The votes are encrypted and stored along with the voter's address
    /// @param _proposalId The proposal ID to vote on
    /// @param _encryptedVotes Array of encrypted vote data
    /// @param _delegators Array of delegator addresses, address(0) if not delegated
    /// @param _delegatorChainIds Array of chain IDs to vote on
    function vote(
        bytes32 _proposalId,
        bytes[] calldata _encryptedVotes,
        address[] calldata _delegators,
        uint256[] calldata _delegatorChainIds
    ) external {
        require(
            _encryptedVotes.length == _delegators.length && _encryptedVotes.length == _delegatorChainIds.length,
            Governance__InvalidInputLength()
        );

        require(proposals[_proposalId].proposalInfo.proposer != address(0), Governance__ProposalDoesNotExist());
        ProposalTimeInfo storage proposalTimeInfo = proposals[_proposalId].proposalTimeInfo;
        require(
            block.timestamp >= proposalTimeInfo.voteActivationTimestamp
                && block.timestamp < proposalTimeInfo.voteDeadlineTimestamp,
            Governance__VotingNotActive()
        );

        ProposalVoteInfo storage proposalVoteInfo = proposals[_proposalId].proposalVoteInfo;

        for (uint256 i = 0; i < _encryptedVotes.length; ++i) {
            bytes calldata _encryptedVote = _encryptedVotes[i];
            address delegator = _delegators[i];
            uint256 delegatorChainId = _delegatorChainIds[i];

            // Validate delegator and chainId combination
            require(
                (delegator == address(0) && delegatorChainId == 0)
                    || (delegator != address(0) && delegatorChainId != 0),
                Governance__InvalidDelegatorAndChainId()
            );

            if (delegatorChainId != 0) {
                require(
                    governanceDelegations[delegatorChainId] != address(0),
                    Governance__InvalidDelegatorChainId()
                );
            }

            uint256 voteIdx = proposalVoteInfo.voteCount;
            proposalVoteInfo.votes[voteIdx] = Vote({
                voter: msg.sender,
                delegator: delegator,
                delegatorChainId: delegatorChainId,
                voteEncrypted: _encryptedVote
            });
            proposalVoteInfo.voteCount++;

            // Hash Vote struct
            bytes32 voteEncryptedHash = sha256(_encryptedVote);
            bytes32 currentVoteHash = sha256(abi.encode(msg.sender, delegator, delegatorChainId, voteEncryptedHash));
            proposalVoteInfo.voteHash = sha256(abi.encode(proposalVoteInfo.voteHash, currentVoteHash));

            emit VoteSubmitted(_proposalId, msg.sender, delegator, delegatorChainId, voteIdx, _encryptedVote);
        }
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

        require(proposals[proposalId].proposalInfo.proposer != address(0), Governance__ProposalDoesNotExist());

        // Check if the proposal in Result Submission Phase
        ProposalTimeInfo storage proposalTimeInfo = proposals[proposalId].proposalTimeInfo;
        require(
            block.timestamp >= proposalTimeInfo.voteDeadlineTimestamp
                && block.timestamp < proposalTimeInfo.proposalDeadlineTimestamp,
            Governance__NotResultSubmissionPhase()
        );

        // Check if the result of the proposal is not already submitted
        require(proposals[proposalId].voteOutcome == VoteOutcome.Pending, Governance__ResultAlreadySubmitted());

        // Verify KMS sig
        require(
            _verifyKMSSig(proposals[proposalId].imageId, _params.enclavePubKey, _params.kmsSig, proposalId),
            Governance__InvalidKMSSignature()
        );

        // Verify Enclave Sig
        bytes32 contractDataHash = sha256(
            abi.encode(
                address(this),
                proposalTimeInfo.proposedTimestamp,
                proposals[proposalId].contractConfigHash,
                proposals[proposalId].networkHash,
                proposals[proposalId].proposalVoteInfo.voteHash
            )
        );
        bytes memory message = abi.encode(contractDataHash, proposalId, voteDecisionResult);
        bytes32 messageHash = sha256(message);
        require(
            _verifyEnclaveSig(_params.enclavePubKey, _params.enclaveSig, messageHash), Governance__InvalidEnclaveSignature()
        );

        // Store vote decryption key
        voteDecryptionKeys[proposalId] = _params.voteDecryptionKey;
        emit VoteDecryptionKeyStored(proposalId, _params.voteDecryptionKey);

        // Handle the result
        VoteOutcome voteOutcome = _calcVoteResult(voteDecisionResult);
        _handleVoteOutcome(proposalId, voteOutcome);

        emit ResultSubmitted(proposalId, voteDecisionResult, voteOutcome);
    }

    /// @notice Refund the value sent for the proposal when result is not submitted and deadline has passed
    /// @dev Note: Deposited tokens cannot be fully refunded only when result is submitted with Passed or Failed
    function refund(bytes32 _proposalId) external nonReentrant {
        // If voteOutcome is still Pending, and the proposal deadline has passed, refund the deposit
        require(proposals[_proposalId].proposalInfo.proposer != address(0), Governance__ProposalDoesNotExist());
        ProposalTimeInfo storage proposalTimeInfo = proposals[_proposalId].proposalTimeInfo;
        VoteOutcome proposalVoteOutcome = proposals[_proposalId].voteOutcome;

        require(proposalVoteOutcome == VoteOutcome.Pending, Governance__NotRefundableProposal());
        require(
            block.timestamp >= proposalTimeInfo.proposalDeadlineTimestamp && proposalVoteOutcome == VoteOutcome.Pending,
            Governance__NotRefundableProposal()
        );

        // Set voteOutcome to Failed to prevent multiple refunds
        proposals[_proposalId].voteOutcome = VoteOutcome.Failed;

        uint256 valueSum = _getValueSum(_proposalId);
        require(valueSum > 0, Governance__NoValueToRefund());
        _refundValue(_proposalId, valueSum);

        // Clear the values array to prevent multiple refunds
        delete proposals[_proposalId].proposalInfo.values;

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
        require(executionQueue[_proposalId] == false, Governance__ProposalAlreadyInQueue());
        require(proposals[_proposalId].executed == false, Governance__ProposalAlreadySubmitted());

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
        require(executionQueue[_proposalId] == true, Governance__ProposalNotInQueue());
        require(proposals[_proposalId].executed == false, Governance__ProposalAlreadySubmitted());

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

    /// @dev Verifies the signature from an enclave using the provided public key
    /// @return isValid True if the signature is valid, false otherwise
    function _verifyEnclaveSig(bytes memory _enclavePubKey, bytes memory _enclaveSig, bytes32 _messageHash)
        internal
        view
        returns (bool)
    {
        return IGovernanceEnclave(governanceEnclave).verifyEnclaveSig(_enclavePubKey, _enclaveSig, _messageHash);
    }

    /// @notice Verifies a KMS signature for enclave public key derivation
    /// @dev This function reconstructs the URI and verifies the signature against the KMS root server public key
    /// @param _imageId The image ID used in the KMS path
    /// @param _enclavePubKey The enclave public key to verify
    /// @param _kmsSig The KMS signature to verify
    /// @param _proposalId The proposal ID used as the KMS path
    /// @return isValid True if the signature is valid, false otherwise
    function _verifyKMSSig(bytes32 _imageId, bytes calldata _enclavePubKey, bytes calldata _kmsSig, bytes32 _proposalId)
        internal
        view
        returns (bool)
    {
        return IGovernanceEnclave(governanceEnclave).verifyKMSSig(_imageId, _enclavePubKey, _kmsSig, _proposalId);
    }

    //-------------------------------- Helpers end --------------------------------//

    //-------------------------------- Getters start --------------------------------//

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
    function _getCurrentNetworkHash() internal view returns (bytes32) {
        return IGovernanceEnclave(governanceEnclave).getNetworkHash();
    }

    /// @notice Returns the vote hash for a given proposal ID
    /// @dev This hash represents the cumulative hash of all votes cast for the proposal
    /// @dev This does not check if the vote is done, so the hash could not be the final hash
    /// @param _proposalId The unique identifier of the proposal
    /// @return voteHash The vote hash for the proposal
    function getVoteHash(bytes32 _proposalId) public view returns (bytes32) {
        // reverts if proposal does not exist
        require(proposals[_proposalId].proposalInfo.proposer != address(0), Governance__ProposalDoesNotExist());

        ProposalVoteInfo storage proposalVoteInfo = proposals[_proposalId].proposalVoteInfo;
        return proposalVoteInfo.voteHash;
    }

    /// @notice Returns the total vote count for a given proposal
    /// @dev This function does not check if the vote is done, so the count could not be the final count
    /// @param _proposalId The unique identifier of the proposal
    /// @return voteCount The total number of votes cast for the proposal
    function getVoteCount(bytes32 _proposalId) external view returns (uint256) {
        // reverts if proposal does not exist
        require(proposals[_proposalId].proposalInfo.proposer != address(0), Governance__ProposalDoesNotExist());

        return proposals[_proposalId].proposalVoteInfo.voteCount;
    }

    /// @notice Returns the vote information for a specific vote index in a proposal
    /// @dev Returns the voter address and encrypted vote data for the specified vote index
    /// @param _proposalId The unique identifier of the proposal
    /// @param _idx The index of the vote to retrieve
    /// @return voter The address of the voter
    /// @return voteEncrypted The encrypted vote data
    function getVoteInfo(bytes32 _proposalId, uint256 _idx) external view returns (address, bytes memory) {
        require(_idx < proposals[_proposalId].proposalVoteInfo.voteCount, Governance__InvalidVoteIndex());
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

    /// @notice Returns the vote outcome of a specific proposal
    /// @param _proposalId The unique identifier of the proposal
    /// @return voteOutcome The outcome of the proposal (Pending, Passed, Failed, or Vetoed)
    function getVoteOutcome(bytes32 _proposalId) external view returns (VoteOutcome) {
        require(proposals[_proposalId].proposalInfo.proposer != address(0), Governance__ProposalDoesNotExist());
        return proposals[_proposalId].voteOutcome;
    }

    /// @notice Returns whether a proposal has been executed
    /// @dev Returns false for non-existent proposals (same as non-executed proposals)
    /// @param _proposalId The unique identifier of the proposal
    /// @return executed True if the proposal has been executed, false otherwise
    function isProposalExecuted(bytes32 _proposalId) external view returns (bool) {
        return proposals[_proposalId].executed;
    }

    /// @notice Returns all hash values associated with a proposal
    /// @param _proposalId The unique identifier of the proposal
    /// @return imageId The image ID representing the enclave configuration
    /// @return networkHash The network hash representing the state of all supported chains
    /// @return contractConfigHash The contract configuration hash
    function getProposalHashes(bytes32 _proposalId) external view returns (bytes32, bytes32, bytes32) {
        require(proposals[_proposalId].proposalInfo.proposer != address(0), Governance__ProposalDoesNotExist());
        return (proposals[_proposalId].imageId, proposals[_proposalId].networkHash, proposals[_proposalId].contractConfigHash);
    }

    /// @notice Returns the token lock information for a specific proposal
    /// @param _proposalId The unique identifier of the proposal
    /// @return token The address of the locked token
    /// @return amount The amount of tokens locked
    function getTokenLockInfo(bytes32 _proposalId) external view returns (address token, uint256 amount) {
        require(proposals[_proposalId].proposalInfo.proposer != address(0), Governance__ProposalDoesNotExist());
        TokenLockInfo storage tokenLockInfo = proposals[_proposalId].tokenLockInfo;
        return (tokenLockInfo.token, tokenLockInfo.amount);
    }

    /// @notice Checks if a proposal exists
    /// @param _proposalId The unique identifier of the proposal
    /// @return exists True if the proposal exists, false otherwise
    function proposalExists(bytes32 _proposalId) external view returns (bool) {
        return proposals[_proposalId].proposalInfo.proposer != address(0);
    }

    /// @notice Returns the complete state of a proposal in a single call
    /// @dev This is a gas-efficient way to get all proposal state information at once
    /// @param _proposalId The unique identifier of the proposal
    /// @return voteOutcome The outcome of the proposal
    /// @return executed Whether the proposal has been executed
    /// @return inExecutionQueue Whether the proposal is in the execution queue
    /// @return imageId The image ID for enclave verification
    /// @return networkHash The network hash representing supported chains state
    function getProposalState(bytes32 _proposalId)
        external
        view
        returns (VoteOutcome voteOutcome, bool executed, bool inExecutionQueue, bytes32 imageId, bytes32 networkHash)
    {
        require(proposals[_proposalId].proposalInfo.proposer != address(0), Governance__ProposalDoesNotExist());
        Proposal storage proposal = proposals[_proposalId];
        return (proposal.voteOutcome, proposal.executed, executionQueue[_proposalId], proposal.imageId, proposal.networkHash);
    }

    /// @notice Returns the number of delegation chain IDs
    /// @return length The number of delegation chain IDs
    function getDelegationChainIdsLength() external view returns (uint256) {
        return delegationChainIds.length;
    }

    /// @notice Returns the complete array of delegation chain IDs
    /// @dev This allows external contracts and users to get all delegation chains in a single call
    /// @return chainIds Array of all delegation chain IDs
    function getAllDelegationChainIds() external view returns (uint256[] memory) {
        return delegationChainIds;
    }

    /// @notice Checks if a governance delegation is configured for a specific chain ID
    /// @param _chainId The chain ID to check
    /// @return governanceDelegation The governance delegation contract address
    function getGovernanceDelegation(uint256 _chainId) external view returns (address) {
        return governanceDelegations[_chainId];
    }

    /// @notice Returns the proposal timing configuration
    /// @return voteActivationDelay The delay before voting starts
    /// @return voteDuration The duration of the voting period
    /// @return proposalDuration The total duration of the proposal
    function getProposalTimingConfig() external view returns (uint256 voteActivationDelay, uint256 voteDuration, uint256 proposalDuration) {
        return (proposalTimingConfig.voteActivationDelay, proposalTimingConfig.voteDuration, proposalTimingConfig.proposalDuration);
    }

    //-------------------------------- Getters end --------------------------------//

    uint256[500] private __gap2;
}
