// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./AttestationAutherUpgradeable.sol";

contract AttestationAutherSample is Initializable,  // initializer
    ContextUpgradeable,  // _msgSender, _msgData
    ERC165Upgradeable,  // supportsInterface
    AccessControlUpgradeable,  // RBAC
    AccessControlEnumerableUpgradeable,  // RBAC enumeration
    ERC1967UpgradeUpgradeable,  // delegate slots, proxy admin, private upgrade
    UUPSUpgradeable,  // public upgrade
    AttestationAutherUpgradeable  // auther
{
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap_0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(IAttestationVerifier attestationVerifier, uint256 maxAge)
        initializer
        AttestationAutherUpgradeable(attestationVerifier, maxAge) {}

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "only admin");
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
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, "AAS:RR-All admins cant be removed");
    }

    function _authorizeUpgrade(address /*account*/) onlyAdmin internal view override {}

//-------------------------------- Overrides end --------------------------------//

//-------------------------------- Initializer start --------------------------------//

    function initialize(EnclaveImage[] memory images, address _admin) external initializer {
        require(images.length != 0, "AAS:I-At least one image necessary");
        require(_admin != address(0), "AAS:I-At least one admin necessary");

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(images);

        _setupRole(DEFAULT_ADMIN_ROLE, _admin);
    }

//-------------------------------- Initializer start --------------------------------//

//-------------------------------- Admin methods start --------------------------------//

    function whitelistEnclaveImage(bytes memory PCR0, bytes memory PCR1, bytes memory PCR2) external onlyAdmin returns (bytes32) {
        return _whitelistEnclaveImage(EnclaveImage(PCR0, PCR1, PCR2));
    }

    function revokeEnclaveImage(bytes32 imageId) external onlyAdmin {
        return _revokeEnclaveImage(imageId);
    }

    function whitelistEnclaveKey(bytes memory enclavePubKey, bytes32 imageId) external onlyAdmin {
        return _whitelistEnclaveKey(enclavePubKey, imageId);
    }

    function revokeEnclaveKey(bytes memory enclavePubKey) external onlyAdmin {
        return _revokeEnclaveKey(enclavePubKey);
    }

//-------------------------------- Admin methods end --------------------------------//

//-------------------------------- Open methods start -------------------------------//

    string public constant SIGNATURE_PREFIX = "attestation-auther-sample-";

    function verify(
        bytes memory signature, 
        string memory message
    ) external view {
        bytes32 digest = keccak256(abi.encodePacked(
            SIGNATURE_PREFIX,
            message
        ));

        address signer = ECDSAUpgradeable.recover(digest, signature);

        _allowOnlyVerified(signer);
    }

//-------------------------------- Open methods end -------------------------------//
}
