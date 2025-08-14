// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/MathUpgradeable.sol";
import "./interfaces/IClusterRewards.sol";
import "./interfaces/IClusterRegistry.sol";
import "./interfaces/IRewardDelegators.sol";
import "./ClusterSelector.sol";
import "./interfaces/IOperatorRegistry.sol";
import "./interfaces/IOperatorManager.sol";
import "./interfaces/IOperatorRewards.sol";
import "./interfaces/IOperatorSelector.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "./interfaces/IInflationRewardsManager.sol";
import "./interfaces/IStakeManager.sol";

contract RewardDelegators is
    Initializable,  // initializer
    ContextUpgradeable,  // _msgSender, _msgData
    ERC165Upgradeable,  // supportsInterface
    AccessControlUpgradeable,  // RBAC
    AccessControlEnumerableUpgradeable,  // RBAC enumeration
    ERC1967UpgradeUpgradeable,  // delegate slots, proxy admin, private upgrade
    UUPSUpgradeable,  // public upgrade
    IRewardDelegators  // interface
{
    using MathUpgradeable for uint256;

    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor() initializer {}

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()));
        _;
    }

    modifier onlyClusterRegistry()  {
        require(address(clusterRegistry) == _msgSender());
        _;
    }

//-------------------------------- Overrides start --------------------------------//

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _grantRole(bytes32 role, address account) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._grantRole(role, account);
    }

    function _revokeRole(bytes32 role, address account) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0);
    }

    function _authorizeUpgrade(address /*account*/) onlyAdmin internal view override {}

//-------------------------------- Overrides end --------------------------------//

//-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap1;

    function initialize(
        address _stakeAddress,
        address _clusterRewardsAddress,
        address _clusterRegistry,
        address _PONDAddress,
        bytes32[] memory _tokenIds,
        uint256[] memory _rewardFactors,
        uint128[] memory _weightsForThreshold,
        uint128[] memory _weightsForDelegation,
        bytes32[] memory _networkIds,
        uint256[] memory _thresholdsForSection
    )
        initializer
        public
    {
        require(
            _tokenIds.length == _rewardFactors.length,
            "RD:I-Each TokenId should have a corresponding Reward Factor and vice versa"
        );
        require(
            _networkIds.length == _thresholdsForSection.length,
            "RD:I-Each NetworkId should have a corresponding threshold for selection and vice versa"
        );

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        stakeAddress = _stakeAddress;
        emit StakeAddressUpdated(_stakeAddress);

        clusterRegistry = IClusterRegistry(_clusterRegistry);
        emit ClusterRegistryUpdated(_clusterRegistry);

        clusterRewards = IClusterRewards(_clusterRewardsAddress);
        emit ClusterRewardsAddressUpdated(_clusterRewardsAddress);

        PONDToken = IERC20Upgradeable(_PONDAddress);
        emit PONDAddressUpdated(_PONDAddress);

        for(uint256 i=0; i < _tokenIds.length; i++) {
            rewardFactor[_tokenIds[i]] = _rewardFactors[i];
            _updateTokenWeights(_tokenIds[i], _weightsForThreshold[i], _weightsForDelegation[i]);
            tokenIndex[_tokenIds[i]] = tokenList.length;
            tokenList.push(_tokenIds[i]);
            emit AddReward(_tokenIds[i], _rewardFactors[i]);
        }

        for(uint256 i=0; i <  _networkIds.length; i++) {
            _updateThresholdForSelection(_networkIds[i], _thresholdsForSection[i]);
        }
    }

//-------------------------------- Initializer end --------------------------------//


    struct Cluster {
        mapping(bytes32 => uint256) totalDelegations;
        mapping(address => mapping(bytes32 => uint256)) delegators;
        mapping(address => mapping(bytes32 => uint256)) rewardDebt;
        mapping(bytes32 => uint256) accRewardPerShare;
    }

    struct TokenWeight {
        uint128 forThreshold;
        uint128 forDelegation;
    }

    mapping(address => Cluster) clusters;

    address public stakeAddress;
    mapping(bytes32 => uint256) public rewardFactor;
    mapping(bytes32 => uint256) public tokenIndex;
    bytes32[] public tokenList;
    IClusterRewards public clusterRewards;
    IClusterRegistry public clusterRegistry;
    IERC20Upgradeable public PONDToken;

    // @dev For services other than relay clusters, the networkId will be operatorManagerId
    mapping(bytes32 => uint256) public thresholdForSelection; // networkId -> threshold
    mapping(bytes32 => TokenWeight) public tokenWeights; // tokenId -> TokenWeight

    // NEW STORAGE VARS
    // bytes32 public constant JOBS_ROLE = keccak256("JOBS_ROLE");
    IOperatorRegistry public operatorRegistry;
    IInflationRewardsManager public inflationRewardsManager;

    // // total delegation locked for the operator
    // mapping(address operator => mapping(bytes32 token => uint256 amount)) public operatorLockedStake;

    // // individual lock info
    // // lockId should be defined in each Service contracts (lockId = keccak256(executor, jobId))
    // mapping(bytes32 lockId => mapping(bytes32 token => uint256 amount)) public lockedStakes;

    struct OperatorSlashData {
        mapping(bytes32 tokenId => uint256) slashPerShare;
        mapping(address delegator => mapping(bytes32 tokenId => uint256)) slashDebt;
    }

    mapping(address operator => OperatorSlashData) operatorSlashData;

    using SafeERC20Upgradeable for IERC20Upgradeable;

    mapping(address operator => mapping(bytes32 tokenId => uint256 amount)) public operatorSlashedStake;
    mapping(address operator => uint256 amount) public operatorLockedStake;
    mapping(bytes32 lockId => uint256 amount) public lockedStake;

    event AddReward(bytes32 tokenId, uint256 rewardFactor);
    event RemoveReward(bytes32 tokenId);
    event RewardsUpdated(bytes32 tokenId, uint256 rewardFactor);
    event ClusterRewardDistributed(address cluster);
    event RewardsWithdrawn(address cluster, address delegator, bytes32[] tokenIds, uint256 rewards);
    event StakeAddressUpdated(address _updatedStakeAddress);
    event ClusterRewardsAddressUpdated(address _updatedClusterRewards);
    event ClusterRegistryUpdated(address _updatedClusterRegistry);
    event PONDAddressUpdated(address _updatedPOND);

    error RewardDelegators_InvalidOperatorManager();
    error RewardDelegators_InvalidOperatorSelector();

    modifier onlyStake() {
        require(_msgSender() == stakeAddress, "RD:OS-only stake contract can invoke");
        _;
    }

    function _checkIfOperatorManager(address _operator) internal view returns (bytes32 operatorManagerId) {
        operatorManagerId = operatorRegistry.operatorToManagerId(_operator);
        address operatorManager = operatorRegistry.getOperatorManager(operatorManagerId);
        if(_msgSender() != operatorManager)
            revert RewardDelegators_InvalidOperatorManager();
    }

    function _checkIfOperatorSelector(address _operator) internal view {
        bytes32 operatorManagerId = operatorRegistry.operatorToManagerId(_operator);
        address operatorSelector = operatorRegistry.getOperatorSelector(operatorManagerId);
        if(_msgSender() != operatorSelector)
            revert RewardDelegators_InvalidOperatorSelector();
    }

    function addRewardFactor(bytes32 _tokenId, uint256 _rewardFactor) external onlyAdmin {
        require(rewardFactor[_tokenId] == 0, "RD:AR-Reward already exists");
        require(_rewardFactor != 0, "RD:AR-Reward cant be 0");
        rewardFactor[_tokenId] = _rewardFactor;
        tokenIndex[_tokenId] = tokenList.length;
        tokenList.push(_tokenId);
        emit AddReward(_tokenId, _rewardFactor);
    }

    function removeRewardFactor(bytes32 _tokenId) external onlyAdmin {
        require(rewardFactor[_tokenId] != 0, "RD:RR-Reward doesnt exist");
        bytes32 tokenToReplace = tokenList[tokenList.length - 1];
        uint256 originalTokenIndex = tokenIndex[_tokenId];
        tokenList[originalTokenIndex] = tokenToReplace;
        tokenIndex[tokenToReplace] = originalTokenIndex;
        tokenList.pop();
        delete rewardFactor[_tokenId];
        delete tokenIndex[_tokenId];
        emit RemoveReward(_tokenId);
    }

    function updateRewardFactor(bytes32 _tokenId, uint256 _updatedRewardFactor) external onlyAdmin {
        require(rewardFactor[_tokenId] != 0, "RD:UR-Cant update reward that doesnt exist");
        require(_updatedRewardFactor != 0, "RD:UR-Reward cant be 0");
        rewardFactor[_tokenId] = _updatedRewardFactor;
        emit RewardsUpdated(_tokenId, _updatedRewardFactor);
    }

    // TODO: is this intended to be a public function?
    function _updateRewards(address _cluster, bytes32 _operatorManagerId) public {
        // uint256 reward = clusterRewards.claimReward(_cluster);
        // get operatorRewards contract address for the service
        address operatorRewards = operatorRegistry.getOperatorRewards(_operatorManagerId);
        uint256 reward = IOperatorRewards(operatorRewards).claimReward(_cluster);

        if(reward == 0) {
            return;
        }

        // (uint256 _commission, address _rewardAddress) = clusterRegistry.getRewardInfo(_cluster);
        // get operatorManager for the service
        address operatorManager = operatorRegistry.getOperatorManager(_operatorManagerId);
        (uint256 _commission, address _rewardAddress) = IOperatorManager(operatorManager).getRewardInfo(_cluster);

        uint256 commissionReward = (reward * _commission) / 100;
        uint256 delegatorReward = reward - commissionReward;
        bytes32[] memory tokens = tokenList;
        uint256[] memory delegations = new uint256[](tokens.length);
        uint256 delegatedTokens = 0;
        for(uint i=0; i < tokens.length; i++) {
            delegations[i] = clusters[_cluster].totalDelegations[tokens[i]];
            if(delegations[i] != 0) {
                delegatedTokens++;
            }
        }
        for(uint i=0; i < tokens.length; i++) {
            // clusters[_cluster].accRewardPerShare[tokens[i]] = clusters[_cluster].accRewardPerShare[tokens[i]].add(
            //                                                         delegatorReward
            //                                                         .mul(rewardFactor[tokens[i]])
            //                                                         .mul(10**30)
            //                                                         .div(weightedStake)
            //                                                     );
            if(delegations[i] != 0) {
                clusters[_cluster].accRewardPerShare[tokens[i]] = clusters[_cluster].accRewardPerShare[tokens[i]] +
                                                                   (((delegatorReward * (10**30)) / delegatedTokens) / delegations[i]);

            }
        }
        if(commissionReward != 0) {
            address rewardToken = operatorRegistry.getRewardToken(_operatorManagerId);
            transferRewards(rewardToken, _rewardAddress, commissionReward);
        }
        emit ClusterRewardDistributed(_cluster);
    }

    function delegate(
        address _delegator,
        address _cluster,
        bytes32[] memory _tokens,
        uint256[] memory _amounts
    ) public onlyStake {
        _updateTokens(_delegator, _cluster, _tokens, _amounts, true);
    }

    function _updateTokens(
        address _delegator,
        address _cluster,
        bytes32[] memory _tokens,
        uint256[] memory _amounts,
        bool _isDelegation
    ) internal returns(uint256 _aggregateReward) {
        bytes32 operatorManagerId = operatorRegistry.operatorToManagerId(_cluster);
        _updateRewards(_cluster, operatorManagerId);

        for(uint256 i = 0; i < _tokens.length; i++) {
            bytes32 _tokenId = _tokens[i];
            uint256 _amount = _amounts[i];

            (uint256 _oldBalance, uint256 _newBalance) = _updateBalances(
                _cluster,
                _delegator,
                _tokenId,
                _amount,
                _isDelegation
            );

            uint256 _reward = _updateDelegatorRewards(
                _cluster,
                _delegator,
                _tokenId,
                _oldBalance,
                _newBalance
            );

            _aggregateReward = _aggregateReward + _reward;
        }

        // if case for relay service, and else case for other services(serverless executors, gateways, etc.)
        if(operatorManagerId == keccak256("RELAY")) {
            bytes32 _networkId = clusterRegistry.getNetwork(_cluster);
            IClusterSelector _clusterSelector = clusterRewards.clusterSelectors(_networkId);
            _updateClusterSelector(_networkId, _cluster, _clusterSelector);
        } else {
            uint256 totalDelegations = getEffectiveDelegation(_cluster, operatorManagerId);
            address operatorSelector = operatorRegistry.getOperatorSelector(operatorManagerId);
            IOperatorSelector(operatorSelector).updateOperatorSelector(_cluster, totalDelegations);
        }

        if(_aggregateReward != 0) {
            address rewardToken = operatorRegistry.getRewardToken(operatorManagerId);
            transferRewards(rewardToken, _delegator, _aggregateReward);
            emit RewardsWithdrawn(_cluster, _delegator, _tokens, _aggregateReward);
        }

        // to get the inflation rewards
        inflationRewardsManager.updateInflationRewards(
            _cluster,
            _delegator,
            _tokens,
            _amounts,
            _isDelegation
        );
    }

    function _updateBalances(
        address _cluster,
        address _delegator,
        bytes32 _tokenId,
        uint256 _amount,
        bool _isDelegation
    ) internal returns(uint256 _oldBalance, uint256 _newBalance) {
        _oldBalance = clusters[_cluster].delegators[_delegator][_tokenId];

        // short circuit
        if(_amount == 0) {
            _newBalance = _oldBalance;
            return (_oldBalance, _newBalance);
        }

        // update balances
        if(_isDelegation) {
            _newBalance =  _oldBalance + _amount;
            clusters[_cluster].totalDelegations[_tokenId] = clusters[_cluster].totalDelegations[_tokenId]
                                                             + _amount;
        } else {
            _newBalance =  _oldBalance - _amount;
            clusters[_cluster].totalDelegations[_tokenId] = clusters[_cluster].totalDelegations[_tokenId]
                                                             - _amount;
        }
        clusters[_cluster].delegators[_delegator][_tokenId] = _newBalance;
    }

    function _updateDelegatorRewards(
        address _cluster,
        address _delegator,
        bytes32 _tokenId,
        uint256 _oldBalance,
        uint256 _newBalance
    ) internal returns(uint256 _reward) {
        uint256 _accRewardPerShare = clusters[_cluster].accRewardPerShare[_tokenId];
        uint256 _rewardDebt = clusters[_cluster].rewardDebt[_delegator][_tokenId];

        // pending rewards
        uint256 _tokenPendingRewards = (_accRewardPerShare * _oldBalance) / (10**30);

        // calculating pending rewards for the delegator if any
        _reward = _tokenPendingRewards - _rewardDebt;

        uint256 slashPerShare = operatorSlashData[_cluster].slashPerShare[_tokenId];
        uint256 slashDebt = operatorSlashData[_cluster].slashDebt[_delegator][_tokenId];
        uint256 slashAmount = (slashPerShare * _oldBalance) - slashDebt;
        
        // remove the slashed amount from the reward
        _reward = _reward - slashAmount;

        // short circuit
        if(_oldBalance == _newBalance && _reward == 0) {
            return _reward;
        }

        // update the debt for next reward calculation
        clusters[_cluster].rewardDebt[_delegator][_tokenId] = (_accRewardPerShare * _newBalance) / (10**30);
        operatorSlashData[_cluster].slashDebt[_delegator][_tokenId] = (slashPerShare * _newBalance);
    }

    function _updateClusterSelector(bytes32 _networkId, address _cluster, IClusterSelector _clusterSelector) internal {
        uint256 totalDelegations = getEffectiveDelegation(_cluster, _networkId);

        if(address(_clusterSelector) != address(0)) {
            // if total delegation is more than 0.5 million pond, then insert into selector
            if(totalDelegations != 0){
                // divided by 1e6 to bring the range of totalDelegations(maxSupply is 1e28) into uint64
                _clusterSelector.upsert(_cluster, uint64(totalDelegations.sqrt()));
            }
            // if not, update it to zero
            else{
                _clusterSelector.deleteIfPresent(_cluster);
            }
        }
    }

    function _updateClusterDelegation(address _cluster, bytes32 _networkId) internal {
        IClusterSelector _clusterSelector = clusterRewards.clusterSelectors(_networkId);
        if(address(_clusterSelector) != address(0)) {
            _updateClusterSelector(_networkId, _cluster, _clusterSelector);
        }
    }

    function updateClusterDelegation(address _cluster, bytes32 _networkId) public onlyClusterRegistry {
        _updateClusterDelegation(_cluster, _networkId);
    }

    function updateOperatorDelegation(address _operator, bytes memory _data) external {
        bytes32 operatorManagerId = _checkIfOperatorManager(_operator);

        if(operatorManagerId == keccak256("RELAY")) {
            // decode the networkId from the data
            (bytes32 networkId) = abi.decode(_data, (bytes32));
            _updateClusterDelegation(_operator, networkId);
        } else {
            uint256 totalDelegations = getEffectiveDelegation(_operator, operatorManagerId);
            // if the operator is a serverless service, we need to update the operator selector
            address operatorSelector = operatorRegistry.getOperatorSelector(operatorManagerId);
            IOperatorSelector(operatorSelector).updateOperatorSelector(_operator, totalDelegations);
        }
    }

    function _removeClusterDelegation(address _cluster, bytes32 _networkId) internal {
        IClusterSelector _clusterSelector = clusterRewards.clusterSelectors(_networkId);
        if(address(_clusterSelector) != address(0)) {
            _clusterSelector.deleteIfPresent(_cluster);
        }
    }

    function removeClusterDelegation(address _cluster, bytes32 _networkId) public onlyClusterRegistry {
        _removeClusterDelegation(_cluster, _networkId);
    }

    function removeOperatorDelegation(address _operator, bytes memory _data) external {
        bytes32 operatorManagerId = _checkIfOperatorManager(_operator);

        if(operatorManagerId == keccak256("RELAY")) {
            // decode the networkId from the data
            (bytes32 networkId) = abi.decode(_data, (bytes32));
            _removeClusterDelegation(_operator, networkId);
        } else {
            // ( , uint256 totalDelegations) = getTotalDelegation(_operator);
            // if the operator is a serverless service, we need to update the operator selector
            address operatorSelector = operatorRegistry.getOperatorSelector(operatorManagerId);
            IOperatorSelector(operatorSelector).removeOperatorSelector(_operator);
        }
    }

    function undelegate(
        address _delegator,
        address _cluster,
        bytes32[] memory _tokens,
        uint256[] memory _amounts
    ) public onlyStake {
        _updateTokens(_delegator, _cluster, _tokens, _amounts, false);
    }

    function withdrawRewards(address _delegator, address _cluster) public returns(uint256) {
        return _updateTokens(_delegator, _cluster, tokenList, new uint256[](tokenList.length), true);
    }

    function withdrawRewards(address _delegator, address[] calldata _clusters) external {
        for(uint256 i=0; i < _clusters.length; i++) {
            withdrawRewards(_delegator, _clusters[i]);
        }
    }

    function transferRewards(address token, address _to, uint256 _amount) internal {
        // PONDToken.transfer(_to, _amount);
        IERC20Upgradeable(token).safeTransfer(_to, _amount);
    }

    function getClusterDelegation(address _cluster, bytes32 _tokenId)
        external
        view
        returns(uint256)
    {
        return clusters[_cluster].totalDelegations[_tokenId];
    }

    function getDelegation(address _cluster, address _delegator, bytes32 _tokenId)
        external
        view
        returns(uint256)
    {
        return clusters[_cluster].delegators[_delegator][_tokenId];
    }

    function updateStakeAddress(address _updatedStakeAddress) external onlyAdmin {
        require(
            _updatedStakeAddress != address(0),
            "RD:USA-Stake contract address cant be 0"
        );
        stakeAddress = _updatedStakeAddress;
        emit StakeAddressUpdated(_updatedStakeAddress);
    }

    function updateClusterRewards(
        address _updatedClusterRewards
    ) external onlyAdmin {
        require(
            _updatedClusterRewards != address(0),
            "RD:UCR-ClusterRewards address cant be 0"
        );
        clusterRewards = IClusterRewards(_updatedClusterRewards);
        emit ClusterRewardsAddressUpdated(_updatedClusterRewards);
    }

    function updateClusterRegistry(
        address _updatedClusterRegistry
    ) external onlyAdmin {
        require(
            _updatedClusterRegistry != address(0),
            "RD:UCR-Cluster Registry address cant be 0"
        );
        clusterRegistry = IClusterRegistry(_updatedClusterRegistry);
        emit ClusterRegistryUpdated(_updatedClusterRegistry);
    }

    function updatePONDAddress(address _updatedPOND) external onlyAdmin {
        require(
            _updatedPOND != address(0),
            "RD:UPA-Updated POND token address cant be 0"
        );
        PONDToken = IERC20Upgradeable(_updatedPOND);
        emit PONDAddressUpdated(_updatedPOND);
    }

    function getAccRewardPerShare(address _cluster, bytes32 _tokenId) external view returns(uint256) {
        return clusters[_cluster].accRewardPerShare[_tokenId];
    }

    event ThresholdForSelectionUpdated(bytes32 networkId, uint256 newThreshold);
    function updateThresholdForSelection(bytes32 networkId, uint256 newThreshold) onlyAdmin external {
        _updateThresholdForSelection(networkId, newThreshold);
    }

    function _updateThresholdForSelection(bytes32 _networkId, uint256 _newThreshold) internal {
        thresholdForSelection[_networkId] = _newThreshold;
        emit ThresholdForSelectionUpdated(_networkId, _newThreshold);
    }

    event TokenWeightsUpdated(bytes32 tokenId, uint256 thresholdWeight, uint256 delegationWeight);
    function updateTokenWeights(bytes32 tokenId, uint128 thresholdWeight, uint128 delegationWeight) onlyAdmin external {
        _updateTokenWeights(tokenId, thresholdWeight, delegationWeight);
    }

    function _updateTokenWeights(bytes32 tokenId, uint128 thresholdWeight, uint128 delegationWeight) internal {
        tokenWeights[tokenId] = TokenWeight(thresholdWeight, delegationWeight);
        emit TokenWeightsUpdated(tokenId, thresholdWeight, delegationWeight);
    }

    event RefreshClusterDelegation(address indexed cluster);
    function refreshClusterDelegation(bytes32 _networkId, address[] calldata clusterList) onlyAdmin external {
        address[] memory validClusters = new address[](clusterList.length);
        uint64[] memory balances = new uint64[](clusterList.length);
        IClusterSelector _clusterSelector = clusterRewards.clusterSelectors(_networkId);

        uint256 noOfClustersToUpdate;
        unchecked {
            for (uint256 index = 0; index < clusterList.length; ++index) {
                address cluster = clusterList[index];
                bytes32 _clusterNetwork = clusterRegistry.getNetwork(cluster);
                require(_networkId == _clusterNetwork, "RD:RCD-incorrect network");

                uint256 totalDelegations = getEffectiveDelegation(cluster, _networkId);

                if(totalDelegations == 0) continue;

                validClusters[noOfClustersToUpdate] = clusterList[index];
                balances[noOfClustersToUpdate] = uint64(totalDelegations.sqrt());
                ++noOfClustersToUpdate;
                emit RefreshClusterDelegation(cluster);
            }
        }

        assembly {
            mstore(validClusters, noOfClustersToUpdate)
            mstore(balances, noOfClustersToUpdate)
        }

        _clusterSelector.upsertMultiple(validClusters, balances);
    }

    // @dev For services other than relay clusters, the networkId will be operatorManagerId
    function getEffectiveDelegation(address cluster, bytes32 networkId) public view returns(uint256 totalDelegations){
        uint256 _totalWeight;
        // (_totalWeight, totalDelegations) = getTotalDelegation(cluster);
        for(uint256 i=0; i < tokenList.length; i++) {
            bytes32 _tokenId = tokenList[i];
            TokenWeight memory _weights = tokenWeights[_tokenId];
            // subtract the slashed amount from the total delegation
            uint256 _clusterTokenDelegation = clusters[cluster].totalDelegations[_tokenId] - operatorSlashedStake[cluster][_tokenId];
            if(_weights.forThreshold != 0) {
                _totalWeight += _weights.forThreshold * _clusterTokenDelegation;
            }
            if(_weights.forDelegation != 0) {
                totalDelegations += _weights.forDelegation * _clusterTokenDelegation;
            }
        }
        if(_totalWeight < thresholdForSelection[networkId]){
            // if threshold is not met, delegations don't count
            return 0;
        }
        totalDelegations -= operatorLockedStake[cluster]; // subtract the locked stake from the total delegations
    }

    // function getTotalDelegation(
    //     address cluster
    // ) public view returns(uint256 _totalWeight, uint256 totalDelegations) {
    //     for(uint256 i=0; i < tokenList.length; i++) {
    //         bytes32 _tokenId = tokenList[i];
    //         TokenWeight memory _weights = tokenWeights[_tokenId];
    //         uint256 _clusterTokenDelegation = clusters[cluster].totalDelegations[_tokenId];
    //         if(_weights.forThreshold != 0) {
    //             _totalWeight += _weights.forThreshold * _clusterTokenDelegation;
    //         }
    //         if(_weights.forDelegation != 0) {
    //             totalDelegations += _weights.forDelegation * _clusterTokenDelegation;
    //         }
    //     }
    // }

    // function _getTotalActiveDelegation(
    //     address cluster
    // ) internal view returns(uint256 _totalWeight, uint256 totalDelegations) {
    //     for(uint256 i=0; i < tokenList.length; i++) {
    //         bytes32 _tokenId = tokenList[i];
    //         TokenWeight memory _weights = tokenWeights[_tokenId];
    //         uint256 _clusterTokenDelegation = clusters[cluster].totalDelegations[_tokenId] - operatorLockedStake[cluster][_tokenId];
    //         if(_weights.forThreshold != 0) {
    //             _totalWeight += _weights.forThreshold * _clusterTokenDelegation;
    //         }
    //         if(_weights.forDelegation != 0) {
    //             totalDelegations += _weights.forDelegation * _clusterTokenDelegation;
    //         }
    //     }
    // }

    function lockTokens(
        address _operator,
        bytes32 _lockId,
        uint256 _lockAmount // amount of POND to be locked
    ) external {
        _checkIfOperatorSelector(_operator);

        if(_lockAmount > 0) {
            operatorLockedStake[_operator] += _lockAmount;
            lockedStake[_lockId] = _lockAmount;
        }
        // TODO: need to update tree
        // remove the executor node from tree if effective delegation falls below lock amount
    }

    // for each executor selected for a job, we need to lock some of its stake tokens
    // function lockTokens(
    //     address _operator,
    //     bytes32 _lockId,
    //     uint256 _amount     // amount of usdc deposited for the job
    //     // bytes32[] memory _tokens,
    //     // uint256[] memory _amounts
    // ) external onlyRole(JOBS_ROLE) {
    //     // require(_tokens.length == _amounts.length, "RD:LT-Invalid input lengths");
    //     bytes32[] memory tokens = tokenList;
    //     uint len = tokens.length;
    //     for(uint i=0; i < len; i++) {
    //         if(clusters[_operator].totalDelegations[tokens[i]] != 0) {
    //             bytes32 tokenId = tokens[i];
    //             // calculate the amount to lock
    //             uint256 amount = _amount * (10**15);
    //             operatorLockedStake[_operator][tokenId] += amount;
    //             lockedStakes[_lockId][tokenId] = amount;
    //         }
    //     }

    //     // bytes32[] memory tokens = tokenList;
    //     // uint256[] memory delegations = new uint256[](tokens.length);
    //     // uint256 delegatedTokens = 0;
    //     // for(uint i=0; i < tokens.length; i++) {
    //     //     delegations[i] = clusters[_operator].totalDelegations[tokens[i]];
    //     //     if(delegations[i] != 0) {
    //     //         delegatedTokens++;
    //     //     }
    //     // }

    //     // for(uint256 i = 0; i < tokens.length; i++) {
    //     //     bytes32 tokenId = tokens[i];
    //     //     if(delegations[i] != 0) {
    //     //         // calculate the amount to lock
    //     //         uint256 amount = ((_amount * (10**30)) / delegatedTokens) / delegations[i];
    //     //         operatorLockedStake[_operator][tokenId] += amount;
    //     //         lockedStakes[_lockId][tokenId] = amount;
    //     //     }
    //     // }

    //     // TODO: do we need to update the stake tree?
    // }

    function unlockTokens(
        address _operator,
        bytes32 _lockId
    ) external {
        _checkIfOperatorSelector(_operator);

        uint256 lockedAmount = lockedStake[_lockId];
        operatorLockedStake[_operator] -= lockedAmount;
        delete lockedStake[_lockId];
    }

    // to be called via Jobs contract when the selected executor submits the output
    // function unlockTokens(
    //     address _operator,
    //     bytes32 _lockId
    // ) external onlyRole(JOBS_ROLE) {
    //     for(uint256 i = 0; i < tokenList.length; i++) {
    //         bytes32 tokenId = tokenList[i];
    //         if(lockedStakes[_lockId][tokenId] > 0) {
    //             operatorLockedStake[_operator][tokenId] -= lockedStakes[_lockId][tokenId];
    //             delete lockedStakes[_lockId][tokenId];
    //         }
    //     }

    //     // TODO: do we need to update the stake tree?
    // }

    function slash(
        address _operator,
        bytes32 _lockId,
        address _recipient
    ) external returns (address[] memory tokens, uint256[] memory amounts) {
        _checkIfOperatorSelector(_operator);

        uint256 effectiveLockedAmount = lockedStake[_lockId];
        uint256 mpondSlashPending;
        uint256 len = tokenList.length;
        tokens = new address[](len);
        amounts = new uint256[](len);
        for(uint256 i = 0; i < len; i++) {
            bytes32 tokenId = tokenList[i];
            uint256 lockedTokens;
            // for MPOND
            if(i == 0) {
                uint256 effectiveMPondLocked = effectiveLockedAmount / 2;
                lockedTokens = effectiveMPondLocked / tokenWeights[tokenId].forDelegation;
                // remaining effective locked amount will be for POND
                effectiveLockedAmount -= effectiveMPondLocked;
            }
            // for POND
            else {
                lockedTokens = effectiveLockedAmount / tokenWeights[tokenId].forDelegation;
            }

            uint256 totalDelegation = clusters[_operator].totalDelegations[tokenId];
            uint256 slashedAmount = operatorSlashedStake[_operator][tokenId];
            // if the total delegation falls below 0.5 MPOND, we don't slash MPOND
            // rather we slash equivalent amount of POND
            if(i == 0 && (totalDelegation - slashedAmount - lockedTokens) < (5 * 10**17)) {
                mpondSlashPending = (5 * 10**17) - (totalDelegation - slashedAmount - lockedTokens);
                lockedTokens = (totalDelegation - slashedAmount) - (5 * 10**17);
            }
            else if(i == 1) {
                // calculating the extra equivalent POND to slash due to insufficient MPOND
                lockedTokens += (mpondSlashPending * 10**6);
            }

            // update slashPerShare for the operator and add the locked tokens to the slashed stake
            operatorSlashData[_operator].slashPerShare[tokenId] += (lockedTokens / totalDelegation);
            operatorSlashedStake[_operator][tokenId] += lockedTokens;

            // TODO
            address token = IStakeManager(stakeAddress).transferSlashedToken(tokenId, lockedTokens, _recipient);
            tokens[i] = token;
            amounts[i] = lockedTokens;
        }

        operatorLockedStake[_operator] -= lockedStake[_lockId];
        delete lockedStake[_lockId];
    }

    // slash the operator's locked stake
    // function slash(
    //     address _operator,
    //     bytes32 _lockId
    // ) external onlyRole(JOBS_ROLE) {
    //     for(uint256 i = 0; i < tokenList.length; i++) {
    //         bytes32 tokenId = tokenList[i];
    //         uint256 lockedAmount = lockedStakes[_lockId][tokenId];
    //         if(lockedAmount > 0) {
    //             uint256 totalDelegation = clusters[_operator].totalDelegations[tokenId];
    //             require(totalDelegation >= lockedAmount, "RD:S-Insufficient locked stake to slash");
    //             operatorSlashData[_operator].slashPerShare[tokenId] += (lockedAmount / totalDelegation);

    //             // TODO: shall we transfer the slashed token to the jobs contract? YES, multiple tokens
    //             // TODO: and no update in totalDelegations mapping? YES
    //             operatorLockedStake[_operator][tokenId] -= lockedAmount;
    //             delete lockedStakes[_lockId][tokenId];
    //         }
    //     }
    // }

    function getTokenList() external view returns (bytes32[] memory) {
        return tokenList;
    }

}
