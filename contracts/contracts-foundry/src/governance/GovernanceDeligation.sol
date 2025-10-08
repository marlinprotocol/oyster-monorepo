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

    error NotDefaultAdmin();
    error DelegationAlreadySet();

    event DelegationSet(address delegator, address delegatee);

    mapping(address delegator => address delegatee) public delegations;

    //-------------------------------- Modifiers start --------------------------------//
    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), NotDefaultAdmin());
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

    //-------------------------------- Initializer end --------------------------------//

    //-------------------------------- Functions start --------------------------------//

    function setDelegation(address delegatee) external {
        address existingDelegatee = delegations[msg.sender];
        delegations[msg.sender] = delegatee;
        require(existingDelegatee != delegatee, DelegationAlreadySet());
        emit DelegationSet(msg.sender, delegatee);
    }

    function getDelegator(address delegator) external view returns (address) {
        return delegations[delegator];
    }

    function isDelegationSet(address delegator, address delegatee) external view returns (bool) {
        return delegations[delegator] == delegatee;
    }

    //-------------------------------- Functions end --------------------------------//
}