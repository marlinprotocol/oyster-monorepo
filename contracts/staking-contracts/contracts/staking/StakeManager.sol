// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "./interfaces/IRewardDelegators.sol";
import "./interfaces/IStakeManager.sol";
import "../token/MPond.sol";


contract StakeManager is
    Initializable,  // initializer
    ContextUpgradeable,  // _msgSender, _msgData
    ERC165Upgradeable,  // supportsInterface
    AccessControlUpgradeable,  // RBAC
    AccessControlEnumerableUpgradeable,  // RBAC enumeration
    ERC1967UpgradeUpgradeable,  // delegate slots, proxy admin, private upgrade
    UUPSUpgradeable,  // public upgrade
    IStakeManager  // interface
{
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
        bytes32[] memory _tokenIds,
        address[] memory _tokenAddresses,
        bool[] memory _delegatable,
        address _rewardDelegatorsAddress,
        uint256 _redelegationWaitTime,
        uint256 _undelegationWaitTime
    )
        initializer
        public
    {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        for(uint256 i=0; i < _tokenIds.length; i++) {
            _addToken(_tokenIds[i], _tokenAddresses[i]);
            if(_delegatable[i]) {
                _setupRole(DELEGATABLE_TOKEN_ROLE, _tokenAddresses[i]);
            }
        }
        _updateRewardDelegators(_rewardDelegatorsAddress);
        _updateLockWaitTime(REDELEGATION_LOCK_SELECTOR, _redelegationWaitTime);
        _updateLockWaitTime(UNDELEGATION_LOCK_SELECTOR, _undelegationWaitTime);
    }

//-------------------------------- Initializer end --------------------------------//

//-------------------------------- Locks start --------------------------------//

    struct Lock {
        uint256 unlockTime;
        uint256 iValue;
    }

    mapping(bytes32 => Lock) public locks;
    mapping(bytes32 => uint256) public lockWaitTime;

    uint256[48] private __gap2;

    enum LockStatus {
        None,
        Unlocked,
        Locked
    }

    event LockWaitTimeUpdated(bytes32 indexed selector, uint256 prevLockTime, uint256 updatedLockTime);
    event LockCreated(bytes32 indexed selector, bytes32 indexed key, uint256 iValue, uint256 unlockTime);
    event LockDeleted(bytes32 indexed selector, bytes32 indexed key, uint256 iValue);

    function _lockStatus(bytes32 _selector, bytes32 _key) internal view returns (LockStatus) {
        bytes32 _lockId = keccak256(abi.encodePacked(_selector, _key));
        uint256 _unlockTime = locks[_lockId].unlockTime;
        if(_unlockTime == 0) {
            return LockStatus.None;
        } else if(_unlockTime <= block.timestamp) {
            return LockStatus.Unlocked;
        } else {
            return LockStatus.Locked;
        }
    }

    function _lock(bytes32 _selector, bytes32 _key, uint256 _iValue) internal returns (uint256) {
        require(_lockStatus(_selector, _key) == LockStatus.None);

        uint256 _duration = lockWaitTime[_selector];
        bytes32 _lockId = keccak256(abi.encodePacked(_selector, _key));
        uint256 _unlockTime = block.timestamp + _duration;
        locks[_lockId].unlockTime = _unlockTime;
        locks[_lockId].iValue = _iValue;

        emit LockCreated(_selector, _key, _iValue, _unlockTime);

        return _unlockTime;
    }

    function _revertLock(bytes32 _selector, bytes32 _key) internal returns (uint256) {
        bytes32 _lockId = keccak256(abi.encodePacked(_selector, _key));
        uint256 _iValue = locks[_lockId].iValue;
        delete locks[_lockId];

        emit LockDeleted(_selector, _key, _iValue);

        return _iValue;
    }

    function _unlock(bytes32 _selector, bytes32 _key) internal returns (uint256) {
        require(_lockStatus(_selector, _key) == LockStatus.Unlocked);
        return _revertLock(_selector, _key);
    }

    function _cloneLock(bytes32 _selector, bytes32 _fromKey, bytes32 _toKey) internal {
        bytes32 _fromLockId = keccak256(abi.encodePacked(_selector, _fromKey));
        bytes32 _toLockId = keccak256(abi.encodePacked(_selector, _toKey));

        uint256 _unlockTime = locks[_fromLockId].unlockTime;
        uint256 _iValue = locks[_fromLockId].iValue;

        locks[_toLockId].unlockTime = _unlockTime;
        locks[_toLockId].iValue = _iValue;

        emit LockCreated(_selector, _toKey, _iValue, _unlockTime);
    }

    function _updateLockWaitTime(bytes32 _selector, uint256 _updatedWaitTime) internal {
        emit LockWaitTimeUpdated(_selector, lockWaitTime[_selector], _updatedWaitTime);
        lockWaitTime[_selector] = _updatedWaitTime;
    }

    function updateLockWaitTime(bytes32 _selector, uint256 _updatedWaitTime) external onlyAdmin {
        _updateLockWaitTime(_selector, _updatedWaitTime);
    }

//-------------------------------- Locks end --------------------------------//

//-------------------------------- Tokens start --------------------------------//

    bytes32 public constant DELEGATABLE_TOKEN_ROLE = keccak256("DELEGATABLE_TOKEN_ROLE");
    bytes32 public constant ACTIVE_TOKEN_ROLE = keccak256("ACTIVE_TOKEN_ROLE");

    mapping(bytes32 => address) public tokens;
    bytes32[] public tokenList;
    mapping(bytes32 => uint256) public tokenIndex;

    uint256[47] private __gap3;

    event TokenAdded(bytes32 tokenId, address tokenAddress);
    event TokenUpdated(bytes32 tokenId, address oldTokenAddress, address newTokenAddress);

    function _addToken(bytes32 _tokenId, address _address) internal {
        require(_address != address(0));
        require(tokens[_tokenId] == address(0));

        tokens[_tokenId] = _address;
        tokenIndex[_tokenId] = tokenList.length;
        tokenList.push(_tokenId);

        emit TokenAdded(_tokenId, _address);
        _enableToken(_tokenId);
    }

    function _enableToken(bytes32 _tokenId) internal {
        require(hasRole(ACTIVE_TOKEN_ROLE, tokens[_tokenId]) == false);
        _grantRole(ACTIVE_TOKEN_ROLE, tokens[_tokenId]);
    }

    function _disableToken(bytes32 _tokenId) internal {
        require(hasRole(ACTIVE_TOKEN_ROLE, tokens[_tokenId]) == true);
        _revokeRole(ACTIVE_TOKEN_ROLE, tokens[_tokenId]);
    }

    function _updateToken(bytes32 _tokenId, address _address) internal {
        require(_address != address(0));
        address _oldAddress = tokens[_tokenId];
        require(_oldAddress != address(0));

        tokens[_tokenId] = _address;

        emit TokenUpdated(_tokenId, _oldAddress, _address);
    }

    function addToken(bytes32 _tokenId, address _address) external onlyAdmin {
        _addToken(_tokenId, _address);
    }

    function enableToken(bytes32 _tokenId) external onlyAdmin {
        _enableToken(_tokenId);
    }

    function disableToken(bytes32 _tokenId) external onlyAdmin {
        _disableToken(_tokenId);
    }

    function updateToken(bytes32 _tokenId, address _address) external onlyAdmin {
        _updateToken(_tokenId, _address);
    }

    using SafeERC20Upgradeable for IERC20Upgradeable;

    function _lockTokens(bytes32 _tokenId, uint256 _amount, address _delegator) internal {
        address tokenAddress = tokens[_tokenId];
        // pull tokens from mpond/pond contract
        // if mpond transfer the governance rights back
        IERC20Upgradeable(tokenAddress).safeTransferFrom(
            _delegator,
            address(this),
            _amount
        );
        if(hasRole(DELEGATABLE_TOKEN_ROLE, tokenAddress)) {
            // send a request to delegate governance rights for the amount to delegator
            MPond(tokenAddress).delegate(
                _delegator,
                uint96(_amount)
            );
        }
    }

    function _unlockTokens(bytes32 _tokenId, uint256 _amount, address _delegator) internal {
        address tokenAddress = tokens[_tokenId];
        if(hasRole(DELEGATABLE_TOKEN_ROLE, tokenAddress)) {
            // send a request to undelegate governacne rights for the amount to previous delegator
            MPond(tokenAddress).undelegate(
                _delegator,
                uint96(_amount)
            );
        }
        IERC20Upgradeable(tokenAddress).safeTransfer(
            _delegator,
            _amount
        );
    }

//-------------------------------- Tokens end --------------------------------//

//-------------------------------- Stash internals start --------------------------------//

    struct Stash {
        address staker;
        address delegatedCluster;
        mapping(bytes32 => uint256) amounts;
        mapping(bytes32 => address) __unused_govDelegations;
    }

    // stashId to stash
    // stashId = keccak256(index)
    mapping(bytes32 => Stash) public stashes;
    // Stash index for unique id generation
    uint256 public stashIndex;

    IRewardDelegators public rewardDelegators;

    uint256[47] private __gap4;

    event StashCreated(bytes32 indexed stashId, address indexed creator);
    event StashDeposit(bytes32 indexed stashId, bytes32[] tokenIds, uint256[] amounts);
    event StashWithdraw(bytes32 indexed stashId, bytes32[] tokenIds, uint256[] amounts);
    event StashMove(bytes32 indexed fromStashId, bytes32 indexed toStashId, bytes32[] tokenIds, uint256[] amounts);
    event StashDelegated(bytes32 indexed stashId, address indexed delegatedCluster);
    event StashUndelegated(bytes32 indexed stashId, address indexed delegatedCluster);
    event RewardDelegatorsUpdated(address from, address to);

    function _newId() internal returns (bytes32) {
        uint256 _stashIndex = stashIndex;
        bytes32 _stashId = keccak256(abi.encodePacked(_stashIndex));
        stashIndex = _stashIndex + 1;

        return _stashId;
    }

    function _newStash(address _staker) internal returns (bytes32) {
        bytes32 _stashId = _newId();
        stashes[_stashId].staker = _staker;

        emit StashCreated(_stashId, _staker);
        return _stashId;
    }

    function _deposit(
        bytes32 _stashId,
        bytes32[] memory _tokenIds,
        uint256[] memory _amounts
    ) internal {
        for(uint256 i = 0; i < _tokenIds.length; i++) {
            bytes32 _tokenId = _tokenIds[i];
            require(
                hasRole(ACTIVE_TOKEN_ROLE, tokens[_tokenId])
            );
            if(_amounts[i] != 0) {
                stashes[_stashId].amounts[_tokenId] = stashes[_stashId].amounts[_tokenId] + _amounts[i];
                _lockTokens(_tokenId, _amounts[i], _msgSender());
            }
        }

        emit StashDeposit(_stashId, _tokenIds, _amounts);
    }

    function _withdraw(
        bytes32 _stashId,
        bytes32[] memory _tokenIds,
        uint256[] memory _amounts
    ) internal {
        for(uint256 i = 0; i < _tokenIds.length; i++) {
            bytes32 _tokenId = _tokenIds[i];
            if(_amounts[i] != 0) {
                stashes[_stashId].amounts[_tokenId] = stashes[_stashId].amounts[_tokenId] - _amounts[i];
                _unlockTokens(_tokenId, _amounts[i], _msgSender());
            }
        }

        emit StashWithdraw(_stashId, _tokenIds, _amounts);
    }

    function _move(
        bytes32 _fromStashId,
        bytes32 _toStashId,
        bytes32[] memory _tokenIds,
        uint256[] memory _amounts
    ) internal {
        for(uint256 i = 0; i < _tokenIds.length; i++) {
            bytes32 _tokenId = _tokenIds[i];
            stashes[_fromStashId].amounts[_tokenId] = stashes[_fromStashId].amounts[_tokenId] - _amounts[i];
            stashes[_toStashId].amounts[_tokenId] = stashes[_toStashId].amounts[_tokenId] + _amounts[i];
        }

        emit StashMove(_fromStashId, _toStashId, _tokenIds, _amounts);
    }

    function _delegate(
        address _staker,
        bytes32 _stashId,
        bytes32[] memory _tokenIds,
        uint256[] memory _amounts,
        address _delegatedCluster
    ) internal {
        stashes[_stashId].delegatedCluster = _delegatedCluster;
        rewardDelegators.delegate(_staker, _delegatedCluster, _tokenIds, _amounts);

        emit StashDelegated(_stashId, stashes[_stashId].delegatedCluster);
    }

    function _undelegate(
        address _staker,
        bytes32 _stashId,
        bytes32[] memory _tokenIds,
        uint256[] memory _amounts,
        address _delegatedCluster
    ) internal {
        rewardDelegators.undelegate(_staker, _delegatedCluster, _tokenIds, _amounts);
        // event order was incorrect in previous versions of contract
        // do not rely on data from old events
        emit StashUndelegated(_stashId, stashes[_stashId].delegatedCluster);
        delete stashes[_stashId].delegatedCluster;
    }

    function _updateRewardDelegators(address _updatedRewardDelegator) internal {
        emit RewardDelegatorsUpdated(address(rewardDelegators), _updatedRewardDelegator);
        rewardDelegators = IRewardDelegators(_updatedRewardDelegator);
    }

    function updateRewardDelegators(
        address _updatedRewardDelegator
    ) external onlyAdmin {
        _updateRewardDelegators(_updatedRewardDelegator);
    }

//-------------------------------- Stash internals end --------------------------------//

//-------------------------------- Stash externals start --------------------------------//

    bytes32 public constant REDELEGATION_LOCK_SELECTOR = keccak256("REDELEGATION_LOCK");
    bytes32 public constant UNDELEGATION_LOCK_SELECTOR = keccak256("UNDELEGATION_LOCK");

    uint256[50] private __gap5;

    modifier onlyStakerOf(bytes32 _stashId) {
        require(stashes[_stashId].staker == _msgSender());
        _;
    }

    function createStashAndDelegate(
        bytes32[] memory _tokens,
        uint256[] memory _amounts,
        address _delegatedCluster
    ) public {
        bytes32 stashId = createStash(_tokens, _amounts);
        delegateStash(stashId, _delegatedCluster);
    }

    function createStash(
        bytes32[] memory _tokens,
        uint256[] memory _amounts
    ) public returns(bytes32) {
        require(
            _tokens.length == _amounts.length
        );
        require(
            _tokens.length != 0
        );
        bytes32 _stashId = _newStash(_msgSender());
        _deposit(_stashId, _tokens, _amounts);

        return _stashId;
    }

    function addToStash(
        bytes32 _stashId,
        bytes32[] calldata _tokens,
        uint256[] calldata _amounts
    ) external onlyStakerOf(_stashId) {
        require(
            _tokens.length == _amounts.length
        );
        _deposit(_stashId, _tokens, _amounts);

        address _delegatedCluster = stashes[_stashId].delegatedCluster;
        if(_delegatedCluster != address(0)) {
            _delegate(_msgSender(), _stashId, _tokens, _amounts, _delegatedCluster);
        }
    }

    function delegateStash(bytes32 _stashId, address _delegatedCluster) public onlyStakerOf(_stashId) {
        require(
            _delegatedCluster != address(0)
        );
        require(
            stashes[_stashId].delegatedCluster == address(0)
        );
        require(
            _lockStatus(UNDELEGATION_LOCK_SELECTOR, _stashId) != LockStatus.Locked
        );
        _revertLock(UNDELEGATION_LOCK_SELECTOR, _stashId);
        bytes32[] memory _tokens = tokenList;
        uint256[] memory _amounts = new uint256[](_tokens.length);
        for(uint256 i = 0; i < _tokens.length; i++) {
            _amounts[i] = stashes[_stashId].amounts[_tokens[i]];
        }

        _delegate(_msgSender(), _stashId, _tokens, _amounts, _delegatedCluster);
    }

    function requestStashRedelegation(bytes32 _stashId, address _newCluster) public onlyStakerOf(_stashId) {
        require(
            stashes[_stashId].delegatedCluster != address(0)
        );
        require(
            _newCluster != address(0)
        );
        _lock(REDELEGATION_LOCK_SELECTOR, _stashId, uint256(uint160(_newCluster)));
    }

    function requestStashRedelegations(bytes32[] memory _stashIds, address[] memory _newClusters) public {
        require(_stashIds.length == _newClusters.length);
        for(uint256 i=0; i < _stashIds.length; i++) {
            requestStashRedelegation(_stashIds[i], _newClusters[i]);
        }
    }

    function redelegateStash(bytes32 _stashId) public onlyStakerOf(_stashId) {
        require(
             stashes[_stashId].delegatedCluster != address(0)
        );
        address _updatedCluster = address(uint160(_unlock(REDELEGATION_LOCK_SELECTOR, _stashId)));
        _redelegateStash(_stashId,  stashes[_stashId].delegatedCluster, _updatedCluster);
    }

    // assumes neither _delegatedCluster nor _updatedCluster can be zero
    function _redelegateStash(
        bytes32 _stashId,
        address _delegatedCluster,
        address _updatedCluster
    ) internal {
        bytes32[] memory _tokens = tokenList;
        uint256[] memory _amounts = new uint256[](_tokens.length);
        for(uint256 i=0; i < _tokens.length; i++) {
            _amounts[i] = stashes[_stashId].amounts[_tokens[i]];
        }

        _undelegate(_msgSender(), _stashId, _tokens, _amounts, _delegatedCluster);
        _delegate(_msgSender(), _stashId, _tokens, _amounts, _updatedCluster);
    }

    function redelegateStashes(bytes32[] memory _stashIds) public {
        for(uint256 i=0; i < _stashIds.length; i++) {
            redelegateStash(_stashIds[i]);
        }
    }

    function cancelRedelegation(bytes32 _stashId) public onlyStakerOf(_stashId) {
        require(_cancelRedelegation(_stashId));
    }

    function _cancelRedelegation(bytes32 _stashId) internal returns(bool) {
        bool _exists = _lockStatus(REDELEGATION_LOCK_SELECTOR, _stashId) != LockStatus.None;
        if(_exists) {
            _revertLock(REDELEGATION_LOCK_SELECTOR, _stashId);
        }
        return _exists;
    }

    function splitStash(bytes32 _stashId, bytes32[] calldata _tokens, uint256[] calldata _amounts) external onlyStakerOf(_stashId) {
        require(
            _tokens.length != 0
        );
        require(
            _tokens.length == _amounts.length
        );
        bytes32 _newStashId = _newStash(_msgSender());
        _move(_stashId, _newStashId, _tokens, _amounts);
        stashes[_newStashId].delegatedCluster = stashes[_stashId].delegatedCluster;
        _cloneLock(UNDELEGATION_LOCK_SELECTOR, _stashId, _newStashId);
    }

    function mergeStash(bytes32 _stashId1, bytes32 _stashId2) external onlyStakerOf(_stashId1) onlyStakerOf(_stashId2) {
        require(_stashId1 != _stashId2);
        require(
            stashes[_stashId1].delegatedCluster == stashes[_stashId2].delegatedCluster
        );
        require(
            _lockStatus(UNDELEGATION_LOCK_SELECTOR, _stashId1) != LockStatus.Locked &&
            _lockStatus(UNDELEGATION_LOCK_SELECTOR, _stashId2) != LockStatus.Locked &&
            _lockStatus(REDELEGATION_LOCK_SELECTOR, _stashId1) == LockStatus.None &&
            _lockStatus(REDELEGATION_LOCK_SELECTOR, _stashId2) == LockStatus.None
        );

        bytes32[] memory _tokens = tokenList;
        uint256[] memory _amounts = new uint256[](_tokens.length);
        for(uint256 i=0; i < _tokens.length; i++) {
            _amounts[i] = stashes[_stashId2].amounts[_tokens[i]];
        }

        _move(_stashId2, _stashId1, _tokens, _amounts);

        delete stashes[_stashId2];
    }

    function undelegateStash(bytes32 _stashId) public onlyStakerOf(_stashId) {
        address _delegatedCluster = stashes[_stashId].delegatedCluster;
        require(
            _delegatedCluster != address(0)
        );

        bytes32[] memory _tokens = tokenList;
        uint256[] memory _amounts = new uint256[](_tokens.length);
        for(uint256 i=0; i < _tokens.length; i++) {
            _amounts[i] = stashes[_stashId].amounts[_tokens[i]];
        }

        _undelegate(_msgSender(), _stashId, _tokens, _amounts, _delegatedCluster);

        _lock(UNDELEGATION_LOCK_SELECTOR, _stashId, uint256(uint160(_delegatedCluster)));
        _cancelRedelegation(_stashId);
    }

    function undelegateStashes(bytes32[] memory _stashIds) public {
        for(uint256 i=0; i < _stashIds.length; i++) {
            undelegateStash(_stashIds[i]);
        }
    }

    function cancelUndelegation(bytes32 _stashId) public onlyStakerOf(_stashId) {
        require(
            _lockStatus(UNDELEGATION_LOCK_SELECTOR, _stashId) == LockStatus.Locked
        );
        address _delegatedCluster = address(uint160(_revertLock(UNDELEGATION_LOCK_SELECTOR, _stashId)));

        bytes32[] memory _tokens = tokenList;
        uint256[] memory _amounts = new uint256[](_tokens.length);
        for(uint256 i=0; i < _tokens.length; i++) {
            _amounts[i] = stashes[_stashId].amounts[_tokens[i]];
        }

        _delegate(_msgSender(), _stashId, _tokens, _amounts, _delegatedCluster);
    }

    function withdrawStash(bytes32 _stashId) external onlyStakerOf(_stashId) {
        require(
            stashes[_stashId].delegatedCluster == address(0)
        );
        require(
            _lockStatus(UNDELEGATION_LOCK_SELECTOR, _stashId) != LockStatus.Locked
        );
        bytes32[] memory _tokens = tokenList;
        uint256[] memory _amounts = new uint256[](_tokens.length);
        for(uint256 i=0; i < _tokens.length; i++) {
            _amounts[i] = stashes[_stashId].amounts[_tokens[i]];
        }

        _withdraw(_stashId, _tokens, _amounts);
    }

    function withdrawStash(
        bytes32 _stashId,
        bytes32[] calldata _tokens,
        uint256[] calldata _amounts
    ) external onlyStakerOf(_stashId) {
        require(
            stashes[_stashId].delegatedCluster == address(0)
        );
        require(
            _lockStatus(UNDELEGATION_LOCK_SELECTOR, _stashId) != LockStatus.Locked
        );
        require(
            _tokens.length == _amounts.length
        );
        _withdraw(_stashId, _tokens, _amounts);
    }

    function stashes__amounts(bytes32 _stashId, bytes32 _tokenId) external view returns(uint256) {
        return stashes[_stashId].amounts[_tokenId];
    }

//-------------------------------- Stash externals end --------------------------------//

    uint256[50] private __gap6;
}
