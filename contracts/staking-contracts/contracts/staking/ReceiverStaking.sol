// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "./lib/ERC20SnapshotUpgradeable.sol";


contract ReceiverStaking is
    Initializable,  // initializer
    ContextUpgradeable,  // _msgSender, _msgData
    ERC165Upgradeable,  // supportsInterface
    AccessControlUpgradeable,  // RBAC
    AccessControlEnumerableUpgradeable, // RBAC enumerable
    ERC1967UpgradeUpgradeable,  // delegate slots, proxy admin, private upgrade
    UUPSUpgradeable,  // public upgrade
    ERC20Upgradeable,  // ERC20
    ERC20SnapshotUpgradeable  // snapshots
{
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap_0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(uint256 _startTime, uint256 _epochLength, address _stakingToken) initializer {
        START_TIME = _startTime;
        EPOCH_LENGTH = _epochLength;
        STAKING_TOKEN = IERC20Upgradeable(_stakingToken);
    }

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
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, "cannot be adminless");
    }

    function _authorizeUpgrade(address /*account*/) internal view override onlyAdmin {}

//-------------------------------- Overrides end --------------------------------//

//-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap_1;

    function initialize(address _admin, string calldata _name, string calldata _symbol) initializer public {
        // initialize parents
        __Context_init_unchained();
        __ERC20Snapshot_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __ERC20_init_unchained(_name, _symbol);
        __ERC20Snapshot_init_unchained();

        // set sender as admin
        _setupRole(DEFAULT_ADMIN_ROLE, _admin);
    }

//-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable START_TIME;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable EPOCH_LENGTH;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20Upgradeable public immutable STAKING_TOKEN;

    mapping(address => address) public signerToStaker;
    mapping(address => address) public stakerToSigner;

    event SignerUpdated(address indexed staker, address indexed from, address indexed to);
    event BalanceUpdated(address indexed staker, uint256 indexed epoch, uint256 balance);

    function _setSigner(address _staker, address _signer) internal {
        require(signerToStaker[_signer] == address(0), "signer has a staker");

        address _oldSigner = stakerToSigner[_staker];
        if(_oldSigner != address(0)) {
            delete signerToStaker[_oldSigner];
        }
        stakerToSigner[_staker] = _signer;

        if(_signer != address(0)) {
            signerToStaker[_signer] = _staker;
        }
        emit SignerUpdated(_staker, _oldSigner, _signer);
    }

    function setSigner(address _signer) external {
        _setSigner(_msgSender(), _signer);
    }

    function _deposit(uint256 _amount, address _from, address _to) internal {
        STAKING_TOKEN.transferFrom(_from, address(this), _amount);
        _mint(_to, _amount);
    }

    function deposit(uint256 _amount) external {
        _deposit(_amount, _msgSender(), _msgSender());
    }

    function depositFor(uint256 _amount, address _staker) external {
        _deposit(_amount, _msgSender(), _staker);
    }

    function depositAndSetSigner(uint256 _amount, address _signer) external {
        _deposit(_amount, _msgSender(), _msgSender());
        _setSigner(_msgSender(), _signer);
    }

    function withdraw(uint256 _amount) external {
        address _sender = _msgSender();
        _burn(_sender, _amount);
        STAKING_TOKEN.transfer(_sender, _amount);
    }

    function getStakeInfo(address _user, uint256 _epoch) external view returns(uint256 _userStake, uint256 _totalStake, uint256 _currentEpoch) {
        _userStake = balanceOfAt(_user, _epoch);
        (_totalStake, _currentEpoch) = getEpochInfo(_epoch);
    }

    function getEpochInfo(uint256 epoch) public view returns(uint256 totalStake, uint256 currentEpoch) {
        totalStake = totalSupplyAt(epoch);
        currentEpoch = _getCurrentSnapshotId();
    }

    function getCurrentEpoch() public view returns (uint256) {
        return _getCurrentSnapshotId();
    }

    function balanceOfSignerAt(address signer, uint256 snapshotId) public view returns (uint256 balance, address account) {
        account = signerToStaker[signer];
        balance = ERC20SnapshotUpgradeable.balanceOfAt(account, snapshotId);
    }

    function balanceOfSignerAtRanged(address signer, uint256 _from, uint256 _count) public view returns (uint256[] memory balances, address account) {
        account = signerToStaker[signer];
        balances = new uint256[](_count);
        uint256 i = 0;
        while (i < _count) {
            balances[i] = balanceOfAt(account, _from);
            unchecked {
                ++_from;
                ++i;
            }
        }
    }

    function _getCurrentSnapshotId() internal view override returns (uint256) {
        if(block.timestamp < START_TIME) return 0;
        return (block.timestamp - START_TIME)/EPOCH_LENGTH + 1;
    }

    function totalSupplyAtRanged(uint256 _from, uint256 _count) public view returns (uint256[] memory stakes) {
        stakes = new uint256[](_count);
        uint256 i = 0;
        while (i < _count) {
            stakes[i] = totalSupplyAt(_from);
            unchecked {
                ++_from;
                ++i;
            }
        }
    }

    function _beforeTokenTransfer(
        address _from,
        address _to,
        uint256 _amount
    ) internal virtual override(ERC20Upgradeable, ERC20SnapshotUpgradeable) {
        require(_from == address(0) || _to == address(0), "Staking Positions transfer not allowed");
        super._beforeTokenTransfer(_from, _to, _amount);
    }

    function _afterTokenTransfer(
        address _from,
        address _to,
        uint256
    ) internal virtual override {
        if(_to == address(0)) {
            // burn
            uint256 _updatedBalance = balanceOf(_from);
            Snapshots storage userSnapshots = _accountBalanceSnapshots[_from];
            if(
                userSnapshots.values.length > 0 &&
                userSnapshots.values[userSnapshots.values.length - 1] > _updatedBalance
            ) {
                uint256 _dropInMin = userSnapshots.values[userSnapshots.values.length - 1] - _updatedBalance;
                uint256 _currentSnapshotId = _getCurrentSnapshotId();
                uint256 _previousSnapshotId = _currentSnapshotId - 1;
                // Lowest balance in epoch
                if(
                    userSnapshots.values.length == 1 ||
                    userSnapshots.ids[userSnapshots.values.length - 2] != _previousSnapshotId
                ) {
                    // Last epoch didn't have a snapshot for user
                    userSnapshots.ids[userSnapshots.ids.length - 1] = _previousSnapshotId;
                    userSnapshots.ids.push(_currentSnapshotId);
                    userSnapshots.values.push(_updatedBalance);
                }
                if(
                    _totalSupplySnapshots.values.length == 1 ||
                    _totalSupplySnapshots.ids[_totalSupplySnapshots.values.length - 2] != _previousSnapshotId
                ) {
                    // Previous epoch didn't have a snapshot
                    _totalSupplySnapshots.ids[_totalSupplySnapshots.values.length - 1] = _previousSnapshotId;
                    _totalSupplySnapshots.ids.push(_currentSnapshotId);
                    _totalSupplySnapshots.values.push(
                        _totalSupplySnapshots.values[_totalSupplySnapshots.values.length - 1]
                    );
                }
                _totalSupplySnapshots.values[_totalSupplySnapshots.values.length - 1] -= _dropInMin;
                userSnapshots.values[userSnapshots.values.length - 1] = _updatedBalance;
                emit BalanceUpdated(_from, _currentSnapshotId, _updatedBalance);
            }
        }
    }
}
