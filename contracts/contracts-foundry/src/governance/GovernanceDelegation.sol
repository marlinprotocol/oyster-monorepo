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

contract GovernanceDelegation is
    Initializable, // initializer
    ContextUpgradeable,
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC enumeration
    PausableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable
{
    error GovernanceDelegation__OnlyDefaultAdmin();
    error GovernanceDelegation__DelegationAlreadySet();
    error GovernanceDelegation__InvalidAddress();

    event DelegationSet(address delegator, address delegatee);

    mapping(address delegator => address delegatee) public delegations;

    //-------------------------------- Modifiers start --------------------------------//
    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), GovernanceDelegation__OnlyDefaultAdmin());
        _;
    }
    //-------------------------------- Modifiers end --------------------------------//

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

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    constructor() initializer {}

    function initialize(address _admin) public initializer {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __Pausable_init_unchained();
        __ReentrancyGuard_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer end --------------------------------//

    //-------------------------------- Functions start --------------------------------//

    function setDelegation(address delegatee) external {
        require(delegatee != address(0), GovernanceDelegation__InvalidAddress());
        address existingDelegatee = delegations[msg.sender];
        require(existingDelegatee != delegatee, GovernanceDelegation__DelegationAlreadySet());
        delegations[msg.sender] = delegatee;
        emit DelegationSet(msg.sender, delegatee);
    }

    function getDelegator(address delegator) external view returns (address) {
        return delegations[delegator];
    }

    function isDelegationSet(address delegator, address delegatee) external view returns (bool) {
        require(delegator != address(0) && delegatee != address(0), GovernanceDelegation__InvalidAddress());
        return delegations[delegator] == delegatee;
    }

    //-------------------------------- Functions end --------------------------------//
}
