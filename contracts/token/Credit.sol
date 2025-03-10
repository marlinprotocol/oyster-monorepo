// SPDX-License-Identifier: MIT

pragma solidity 0.8.26;

/* Libraries */
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/* Contracts */
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {AccessControlEnumerableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

/* Interfaces */
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";


contract Credit is
    ContextUpgradeable,  // _msgSender, _msgData
    AccessControlEnumerableUpgradeable,  // RBAC enumeration
    ERC20Upgradeable,  // token
    UUPSUpgradeable,  // public upgrade
    PausableUpgradeable  // pause/unpause
{   
    using SafeERC20 for IERC20;

    uint256[500] private __gap0;

    error OnlyAdmin();
    error OnlyTransferAllowedRole();
    error NoAdminExists();
    error OnlyOysterMarket();
    error NotEnoughUSDC();
    error OnlyToEmergencyWithdrawRole();

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE"); // 0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6
    bytes32 public constant TRANSFER_ALLOWED_ROLE = keccak256("TRANSFER_ALLOWED_ROLE"); // 0xed89ee80d998965e2804dad373576bf7ffc490ba5986d52deb7d526e93617101
    bytes32 public constant EMERGENCY_WITHDRAW_ROLE = keccak256("EMERGENCY_WITHDRAW_ROLE"); // 0x66f144ecd65ad16d38ecdba8687842af4bc05fde66fe3d999569a3006349785f

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), OnlyAdmin());
        _;
    }

    modifier onlyOysterMarket() {
        require(_msgSender() == i_oysterMarket, OnlyOysterMarket());
        _;
    }

    //-------------------------------- Overrides start --------------------------------/

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function _revokeRole(bytes32 role, address account) internal override {
        super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, NoAdminExists());
    }

    function _beforeTokenTransfer(address from, address to, uint256 /* amount */) internal virtual override {
        require(hasRole(TRANSFER_ALLOWED_ROLE, from) || hasRole(TRANSFER_ALLOWED_ROLE, to), OnlyTransferAllowedRole());
    }

    function _authorizeUpgrade(address /*account*/) internal view override {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), OnlyAdmin());
    }

    //-------------------------------- Overrides end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address immutable i_oysterMarket;
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address immutable i_usdc;

    uint256[500] private __gap1;

    //-------------------------------- Initializer start --------------------------------/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address _oysterMarket, address _usdc) {
        i_oysterMarket = _oysterMarket;
        i_usdc = _usdc;
    }

    function initialize(address _admin) public initializer {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC20_init_unchained("Oyster Credit", "CREDIT");
        __UUPSUpgradeable_init_unchained();
        
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer end --------------------------------/

    //-------------------------------- Token Mint/Burn start --------------------------------/

    function mint(address _to, uint256 _amount) external onlyRole(MINTER_ROLE) {
        _mint(_to, _amount);
    }

    function burn(address _from, uint256 _amount) external onlyRole(MINTER_ROLE) {
        _burn(_from, _amount);
    }

    //-------------------------------- Token Mint/Burn end --------------------------------//
    
    //-------------------------------- Oyster Market start --------------------------------//

    function redeemAndBurn(address _to, uint256 _amount) external whenNotPaused onlyOysterMarket {
        require(IERC20(i_usdc).balanceOf(address(this)) >= _amount, NotEnoughUSDC());
        IERC20(i_usdc).safeTransfer(_to, _amount);
        _burn(_msgSender(), _amount);
    }

    //-------------------------------- Oyster Market end --------------------------------//

    //-------------------------------- Emergency Withdraw start --------------------------------//

    function emergencyWithdraw(address _token, address _to, uint256 _amount) external onlyAdmin {
        require(hasRole(EMERGENCY_WITHDRAW_ROLE, _msgSender()), OnlyToEmergencyWithdrawRole());
        IERC20(_token).safeTransfer(_to, _amount);
    }

    //-------------------------------- Emergency Withdraw end --------------------------------//
}