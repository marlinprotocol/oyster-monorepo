// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IInflationRewardsManager.sol";
import "./interfaces/IRewardDelegators.sol";
import "./interfaces/IInflationRewardsEmitter.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract InflationRewardsManager is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC
    AccessControlEnumerableUpgradeable, // RBAC enumeration
    ERC1967UpgradeUpgradeable, // delegate slots, proxy admin, private upgrade
    UUPSUpgradeable, // public upgrade,
    IInflationRewardsManager // interface
{
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor() initializer {}

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "only admin");
        _;
    }

    //-------------------------------- Overrides start --------------------------------//

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _grantRole(
        bytes32 role,
        address account
    ) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._grantRole(role, account);
    }

    function _revokeRole(
        bytes32 role,
        address account
    ) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, "Cannot be adminless");
    }

    function _authorizeUpgrade(address /*account*/) internal view override onlyAdmin {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap1;

    function initialize(address _rewardDelegators) public initializer {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        rewardDelegators = IRewardDelegators(_rewardDelegators);
    }

    //-------------------------------- Initializer end --------------------------------//

    IRewardDelegators public rewardDelegators;
    IInflationRewardsEmitter public inflationRewardsEmitter;

    mapping(address executor => uint256 jobCount) public executorEpochJobCount;
    // epoch => total jobs
    mapping(uint256 epoch => uint256 jobCount) public totalEpochJobCount;

    struct DelegationAmountInfo {
        mapping(bytes32 tokenId => uint256 amounts) activeDelegation;
        mapping(bytes32 tokenId => uint256 amounts) pendingDelegation;
    }

    struct DelegationEpochInfo {
        uint256 epochActive;
        uint256 epochPending;
    }

    struct ExecutorEpochInfo {
        uint256 lastDistributedEpoch;
        uint256 lastJobDoneEpoch;
    }

    // This is updated each time an Executor completes first job of new epoch
    // Or, this can be manually updated by anyone
    // executor => epoch => tokenId => amount
    // mapping (address executor => mapping(uint256 epoch => mapping(bytes32 tokenId => uint256 amount))) executorRewardPerToken;
    // executor => tokenId => amount
    mapping (address executor => mapping(bytes32 tokenId => uint256 amount)) executorRewardPerToken;


    // Total delegation amounts of each tokenId over all Executors
    // DelegationAmountInfo totalDelegationInfo;

    // Total delegation amounts of each tokenId of each Executor 
    mapping (address executor => ExecutorEpochInfo) executorEpochInfo;
    mapping (address executor => DelegationAmountInfo) executorDelegationInfo;

    // Delegation info of each Delegator
    mapping (address executor => mapping(address delegator => DelegationEpochInfo)) delegatorDelegationEpochInfo;
    mapping (address executor => mapping(address delegator => DelegationAmountInfo)) delegatorDelegationInfo;
    // mapping (address delegator => mapping(bytes32 token => uint256 amount)) delegatorRewardDebt;
    mapping (address executor => mapping(address delegator => mapping(bytes32 token => uint256 amount))) delegatorRewardDebt;

    // uint256 public activeEpoch;
    mapping(uint256 epoch => uint256 reward) public epochRewards;

    bytes32 public constant JOBS_ROLE = keccak256("JOBS_ROLE");

    error InflationRewardsManager_OnlyRewardDelegators();

    modifier onlyRewardDelegators() {
        if(_msgSender() != address(rewardDelegators))
            revert InflationRewardsManager_OnlyRewardDelegators();
        _;
    }

    function setInflationRewardsEmitter(
        address _inflationRewardsEmitter
    ) external onlyAdmin {
        inflationRewardsEmitter = IInflationRewardsEmitter(_inflationRewardsEmitter);
    }

    function notifyOutputSubmission(
        address _executor
    ) external onlyRole(JOBS_ROLE) {
        bytes32[] memory tokens = rewardDelegators.getTokenList();

        uint256 currentEpoch = inflationRewardsEmitter.getCurrentEpoch();
        if(currentEpoch > executorEpochInfo[_executor].lastJobDoneEpoch) {
            _updateRewards(_executor, tokens);
            _activateExecutorStake(_executor, tokens);

            // executorEpochInfo[_executor].lastDistributedEpoch = executorEpochInfo[_executor].lastJobDoneEpoch;
            executorEpochInfo[_executor].lastJobDoneEpoch = currentEpoch;

            executorEpochJobCount[_executor] = 1;
            totalEpochJobCount[currentEpoch] = 1;
            // activeEpoch = currentEpoch;

            epochRewards[currentEpoch] = inflationRewardsEmitter.emitInflationaryReward();
        } else {
            executorEpochJobCount[_executor] += 1;
            totalEpochJobCount[currentEpoch] += 1;
        }
    }

    function updateInflationRewards(
        address _executor,
        address _delegator,
        bytes32[] memory _tokens,
        uint256[] memory _amounts,
        bool _isDelegation
    ) external onlyRewardDelegators {
        _updateTokens(_executor, _delegator, _tokens, _amounts, _isDelegation);
    }

    // function delegate(
    //     address _executor,
    //     address _delegator,
    //     bytes32[] memory _tokens,
    //     uint256[] memory _amounts
    // ) external onlyRewardDelegators {
    //     _updateTokens(_executor, _delegator, _tokens, _amounts, true);
    // }

    function _updateTokens(
        address _executor,
        address _delegator,
        bytes32[] memory _tokens,
        uint256[] memory _amounts,
        bool _isDelegation
    ) internal {
        require(_tokens.length == _amounts.length, "Tokens and amounts length mismatch");

        uint256 currentEpoch = inflationRewardsEmitter.getCurrentEpoch();
        // checks if it is the first update for the executor in the current epoch
        bool isFirstEpochUpdate = (currentEpoch > executorEpochInfo[_executor].lastJobDoneEpoch && 
            executorEpochInfo[_executor].lastJobDoneEpoch != executorEpochInfo[_executor].lastDistributedEpoch);

        if(isFirstEpochUpdate) {
            // update rewards for the executor till last job done epoch
            _updateRewards(_executor, _tokens);
        }

        uint256 reward;
        for (uint256 i = 0; i < _tokens.length; i++) {
            bytes32 tokenId = _tokens[i];
            uint256 amount = _amounts[i];

            // Update executor's delegation amounts
            _updateExecutorDelegationInfo(_executor, isFirstEpochUpdate, tokenId, amount, _isDelegation);

            // Update delegator's delegation amounts
            reward += _updateDelegatorDelegationInfo(_executor, _delegator, tokenId, amount, _isDelegation);
        }

        // delegatorDelegationEpochInfo[_executor][_delegator].epochPending = currentEpoch;

        if(reward != 0) {
            IERC20 rewardToken = inflationRewardsEmitter.rewardToken();
            rewardToken.transfer(_delegator, reward);
        }
    }

    function _updateExecutorDelegationInfo(
        address _executor,
        bool _isFirstEpochUpdate,
        bytes32 _tokenId,
        uint256 _amount,
        bool _isDelegation
    ) internal {
        if(_isFirstEpochUpdate) {
            // Update executor's delegation amounts
            _activateExecutorTokenStake(_executor, _tokenId);
            if(_isDelegation) {
                executorDelegationInfo[_executor].pendingDelegation[_tokenId] = _amount;
            } else {
                executorDelegationInfo[_executor].activeDelegation[_tokenId] -= _amount;
            }
        } else {
            if(_isDelegation) {
                executorDelegationInfo[_executor].pendingDelegation[_tokenId] += _amount;
            } else {
                uint256 executorPendingAmount = executorDelegationInfo[_executor].pendingDelegation[_tokenId];
                uint256 minAmount = _amount < executorPendingAmount ? _amount : executorPendingAmount;
                executorDelegationInfo[_executor].pendingDelegation[_tokenId] -= minAmount;
                // If the amount to be undelegated is more than the pending delegation
                if(_amount - minAmount > 0) {
                    executorDelegationInfo[_executor].activeDelegation[_tokenId] -= (_amount - minAmount);
                }
            }
        }
    }

    function _updateDelegatorDelegationInfo(
        address _executor,
        address _delegator,
        bytes32 _tokenId,
        uint256 _amount,
        bool _isDelegation
    ) internal returns (uint256 reward) {
        uint256 currentEpoch = inflationRewardsEmitter.getCurrentEpoch();
        if(currentEpoch > delegatorDelegationEpochInfo[_executor][_delegator].epochPending) {
            uint256 oldBalance = delegatorDelegationInfo[_executor][_delegator].activeDelegation[_tokenId];
            uint256 newBalance = oldBalance + delegatorDelegationInfo[_executor][_delegator].pendingDelegation[_tokenId];

            // Update delegator's delegation amounts
            _activateDelegatorTokenStake(_executor, _delegator, _tokenId);
            
            if(_isDelegation) {
                delegatorDelegationInfo[_executor][_delegator].pendingDelegation[_tokenId] = _amount;
            } else {
                newBalance -= _amount;
                delegatorDelegationInfo[_executor][_delegator].activeDelegation[_tokenId] -= _amount;
            }

            // Update delegator's reward debt
            reward = _updateDelegatorRewards(_executor, _delegator, _tokenId, oldBalance, newBalance);

            delegatorDelegationEpochInfo[_executor][_delegator].epochPending = currentEpoch;
        } else {
            if(_isDelegation) {
                delegatorDelegationInfo[_executor][_delegator].pendingDelegation[_tokenId] += _amount;
            } else {
                uint256 delegatorPendingAmount = delegatorDelegationInfo[_executor][_delegator].pendingDelegation[_tokenId];
                uint256 minAmount = _amount < delegatorPendingAmount ? _amount : delegatorPendingAmount;
                delegatorDelegationInfo[_executor][_delegator].pendingDelegation[_tokenId] -= minAmount;
                // If the _amount to be undelegated is more than the pending delegation
                if(_amount - minAmount > 0) {
                    delegatorDelegationInfo[_executor][_delegator].activeDelegation[_tokenId] -= (_amount - minAmount);
                }
            }
        }
    }

    // Update the rewardPerShare till the lastJobDoneEpoch
    // to be only called once in an epoch for each executor
    function _updateRewards(
        address _executor,
        bytes32[] memory tokens
    ) internal {
        uint256 lastJobDoneEpoch = executorEpochInfo[_executor].lastJobDoneEpoch;
        uint256 executorReward = epochRewards[lastJobDoneEpoch] * executorEpochJobCount[_executor] / 
                                    totalEpochJobCount[lastJobDoneEpoch];
        if(executorReward == 0)
            return;

        uint256 delegatedTokens;
        uint256[] memory tokenDelegations = new uint256[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            bytes32 tokenId = tokens[i];

            tokenDelegations[i] = executorDelegationInfo[_executor].activeDelegation[tokenId];
            if(tokenDelegations[i] > 0)
                ++delegatedTokens;
        }

        for (uint256 i = 0; i < tokens.length; i++) {
            bytes32 tokenId = tokens[i];
            if(tokenDelegations[i] > 0)
                executorRewardPerToken[_executor][tokenId] += ((executorReward * (10**30) / delegatedTokens) / 
                                                                tokenDelegations[i]);
        }

        executorEpochInfo[_executor].lastDistributedEpoch = executorEpochInfo[_executor].lastJobDoneEpoch;
    }

    function _activateExecutorStake(
        address _executor,
        bytes32[] memory tokens
    ) internal {
        // Update the executor's delegation amounts
        for (uint256 i = 0; i < tokens.length; i++) {
            bytes32 tokenId = tokens[i];
            _activateExecutorTokenStake(_executor, tokenId);
        }
    }

    function _activateExecutorTokenStake(
        address _executor,
        bytes32 _token
    ) internal {
        executorDelegationInfo[_executor].activeDelegation[_token] += 
            executorDelegationInfo[_executor].pendingDelegation[_token];

        executorDelegationInfo[_executor].pendingDelegation[_token] = 0;
    }

    function _activateDelegatorTokenStake(
        address _executor,
        address _delegator,
        bytes32 _token
    ) internal {
        delegatorDelegationInfo[_executor][_delegator].activeDelegation[_token] += 
            delegatorDelegationInfo[_executor][_delegator].pendingDelegation[_token];

        delegatorDelegationInfo[_executor][_delegator].pendingDelegation[_token] = 0;
    }

    function _updateDelegatorRewards(
        address _executor,
        address _delegator,
        bytes32 _token,
        uint256 _oldBalance,
        uint256 _newBalance
    ) internal returns (uint256 reward) {
        // update delegation reward debt for the delegator

        // uint256 lastJobDoneEpoch = executorEpochInfo[_executor].lastJobDoneEpoch;
        // uint256 currentEpoch = inflationRewardsEmitter.getCurrentEpoch();
        // // No need to update if the last job done epoch is same as current epoch
        // if(lastJobDoneEpoch == currentEpoch)
        //     return;

        uint256 executorAccruedReward = executorRewardPerToken[_executor][_token];
        uint256 rewardDebt = delegatorRewardDebt[_executor][_delegator][_token];

        uint256 executorReward = executorAccruedReward * _oldBalance / (10**30);
        reward = executorReward - rewardDebt;

        delegatorRewardDebt[_executor][_delegator][_token] = executorAccruedReward * _newBalance / (10**30);
    }

    // function undelegate(
    //     address _executor,
    //     address _delegator,
    //     bytes32[] memory _tokens,
    //     uint256[] memory _amounts
    // ) external onlyRewardDelegators {
    //     _updateTokens(_executor, _delegator, _tokens, _amounts, false);
    // }

    // function withdrawRewards(
    //     address _executor,
    //     address _delegator,
    //     uint256[] memory _amounts,
    //     bytes32[] memory _tokens
    // ) external onlyRewardDelegators {
    //     _updateTokens(_executor, _delegator, _tokens, _amounts, true);
    // }

}