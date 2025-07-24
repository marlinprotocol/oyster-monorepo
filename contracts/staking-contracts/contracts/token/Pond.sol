// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20CappedUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import "./IArbToken.sol";

contract Pond is
    Initializable,  // initializer
    ContextUpgradeable,  // _msgSender, _msgData
    ERC165Upgradeable,  // supportsInterface
    AccessControlUpgradeable,  // RBAC
    AccessControlEnumerableUpgradeable,  // RBAC enumeration
    ERC20Upgradeable,  // token
    ERC20CappedUpgradeable,  // supply cap
    ERC1967UpgradeUpgradeable,  // delegate slots, proxy admin, private upgrade
    UUPSUpgradeable,  // public upgrade
    IArbToken  // Arbitrum bridge support
{
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor() initializer {}

    function initialize(
        string memory _name,
        string memory _symbol
    ) public initializer {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC20_init_unchained(_name, _symbol);
        __ERC20Capped_init_unchained(10000000000e18);
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setRoleAdmin(BRIDGE_ROLE, DEFAULT_ADMIN_ROLE);
        _mint(_msgSender(), 10000000000e18);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return interfaceId == type(IArbToken).interfaceId || super.supportsInterface(interfaceId);
    }

    function _grantRole(bytes32 role, address account) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._grantRole(role, account);
    }

    function _revokeRole(bytes32 role, address account) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, "Cannot be adminless");
    }

    function _mint(address account, uint256 amount) internal virtual override(ERC20Upgradeable, ERC20CappedUpgradeable) {
        super._mint(account, amount);
    }

    function _authorizeUpgrade(address /*account*/) internal view override {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "Pond: must be admin to upgrade");
    }

//-------------------------------- Bridge start --------------------------------//

    // bridge mint/burn functions are implemented using transfers to/from the token contract itself
    // limits exposure to contract balance in case the bridge is compromised

    bytes32 public constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");

    address public l1Address;
    uint256[49] private __gap1;

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()));
        _;
    }

    modifier onlyBridge() {
        require(hasRole(BRIDGE_ROLE, _msgSender()));
        _;
    }

    function setL1Address(address _l1Address) external onlyAdmin {
        l1Address = _l1Address;
    }

    function bridgeMint(address _account, uint256 _amount) external onlyBridge {
        _transfer(address(this), _account, _amount);
    }

    function bridgeBurn(address _account, uint256 _amount) external onlyBridge {
        _transfer(_account, address(this), _amount);
    }

    function withdraw(uint256 _amount) external onlyAdmin {
        _transfer(address(this), _msgSender(), _amount);
    }

//-------------------------------- Bridge end --------------------------------//
}

