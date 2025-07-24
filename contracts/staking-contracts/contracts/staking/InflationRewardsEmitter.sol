// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./interfaces/IInflationRewardsEmitter.sol";
import "./interfaces/IInflationRewardsManager.sol";

contract InflationRewardsEmitter is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC
    AccessControlEnumerableUpgradeable, // RBAC enumeration
    ERC1967UpgradeUpgradeable, // delegate slots, proxy admin, private upgrade
    UUPSUpgradeable, // public upgrade,
    IInflationRewardsEmitter // interface
{
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap0;

    using SafeERC20 for IERC20;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(uint256 _epochLength, uint256 _startTime) initializer {
        EPOCH_LENGTH = _epochLength;
        START_TIME = _startTime;
    }

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

    function initialize(
        address _rewardToken,
        address _inflationRewardsManager,
        uint256 _rewardPerEpoch
    ) public initializer {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        rewardToken = IERC20(_rewardToken);
        inflationRewardsManager = _inflationRewardsManager;
        rewardPerEpoch = _rewardPerEpoch;
    }

    //-------------------------------- Initializer end --------------------------------//

    // the token to be used for inflationary rewards
    IERC20 public rewardToken;

    address public inflationRewardsManager;

    uint256 public immutable START_TIME;
    uint256 public immutable EPOCH_LENGTH;

    uint256 public lastEmittedEpoch;

    uint256 public rewardPerEpoch;

    error InflationRewardsEmitter_OnlyInflationRewardsManager();
    error InflationRewardsEmitter_AlreadyEmitted();

    modifier onlyInflationRewardsManager() {
        if(_msgSender() != inflationRewardsManager)
            revert InflationRewardsEmitter_OnlyInflationRewardsManager();
        _;
    }

    function getCurrentEpoch() public view returns (uint256) {
        return (block.timestamp - START_TIME) / EPOCH_LENGTH;
    }

    function emitInflationaryReward() external onlyInflationRewardsManager returns (uint256) {
        uint256 currentEpoch = getCurrentEpoch();
        if(lastEmittedEpoch < currentEpoch) {
            lastEmittedEpoch = currentEpoch;
            rewardToken.transfer(inflationRewardsManager, rewardPerEpoch);
            return rewardPerEpoch;
        }
        revert InflationRewardsEmitter_AlreadyEmitted();
    }

}
