// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

/* 
    18/07/2025
    
    [Marlin Governance Token]
    Arbitrum Sepolia: 0x9E72284B0E205b592731C30EBb8064E853FEe3E8
    Ethereum Sepolia: 0xFF25f1caeFDdaacf7067940b04012aAcdeAE2d68

    [Deposit Token]
    Arbitrum Sepolia: 0x5C891c16bdC9bBA00707f2aDbeBe3AF52D180Fa9
 */
contract MockERC20 is
    Initializable,
    ContextUpgradeable,
    AccessControlEnumerableUpgradeable,
    ERC20Upgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    error NoAdminExists();
    error OnlyAdmin();
    error OnlyMinter();
    error OnlyBurner();

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE"); // 0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE"); // 0x3c11d16cbaffd01df69ce1c404f6340ee057498f5f00246190ea54220576a848

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), OnlyAdmin());
        _;
    }

    modifier onlyMinter() {
        require(hasRole(MINTER_ROLE, _msgSender()), OnlyMinter());
        _;
    }

    modifier onlyBurner() {
        require(hasRole(BURNER_ROLE, _msgSender()), OnlyBurner());
        _;
    }

    //-------------------------------- Overrides start --------------------------------//

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _revokeRole(bytes32 role, address account) internal override {
        super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, NoAdminExists());
    }

    function _authorizeUpgrade(address /*account*/ ) internal view override {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), OnlyAdmin());
    }

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() initializer {}

    function initialize(
        string calldata _name,
        string calldata _symbol,
        address _admin,
        address _minter,
        address _burner
    ) public initializer {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC20_init_unchained(_name, _symbol);
        __UUPSUpgradeable_init_unchained();
        __Pausable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(MINTER_ROLE, _minter);
        _grantRole(BURNER_ROLE, _burner);
    }
    //-------------------------------- Initializer end --------------------------------//

    //-------------------------------- Token Mint/Burn start --------------------------------//

    function mint(address _to, uint256 _amount) external whenNotPaused {
        require(hasRole(MINTER_ROLE, _msgSender()), OnlyMinter());

        _mint(_to, _amount);
    }

    function burn(address _from, uint256 _amount) external whenNotPaused {
        require(hasRole(BURNER_ROLE, _msgSender()), OnlyBurner());

        _burn(_from, _amount);
    }

    //-------------------------------- Token Mint/Burn end --------------------------------//

    //-------------------------------- Admin start --------------------------------//

    function grantMinterRole(address _account) external {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), OnlyAdmin());

        _grantRole(MINTER_ROLE, _account);
    }

    function revokeMinterRole(address _account) external {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), OnlyAdmin());

        _revokeRole(MINTER_ROLE, _account);
    }

    function grantBurnerRole(address _account) external {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), OnlyAdmin());

        _grantRole(BURNER_ROLE, _account);
    }

    function revokeBurnerRole(address _account) external {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), OnlyAdmin());

        _revokeRole(BURNER_ROLE, _account);
    }

    //-------------------------------- Admin end --------------------------------//
}
