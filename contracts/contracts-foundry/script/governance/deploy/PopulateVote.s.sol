// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Governance} from "../../../src/governance/Governance.sol";
import {HelperConfig, ConfigFactory} from "../HelperConfig.s.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";

contract PopulateVote is Script {
    
    Governance gov = Governance(0x5F5e03D26419f8fa106Dea7336B4872DC3a7AE48);
    bytes32 constant proposal = bytes32(0x3BE84B543725B5F068FAC7EF9C02C72EF81F58A06EEBC25FA6F105528894CD16);
    bytes constant encrypted_vote = hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000c104a61925f077da454abb18cc0e3b95f118ddf55ee7353bdcfa99b355593732ad85647b2d02c4fa3e13e12522c04d42251668d74e5bc5f5d9b5a0b6a6843a104781c5291e051eb7c79013d9c7ee8c23424f1d56d9ca60da51fd5f5be3cc0037cacdbc6e0f166abd60749eceff8422d8a5bf2858cd1a4ed110f83242f428ba7485d90ca9d102a86a7b5d2a810d048ac1e70a5ef8ffbeab8770020c8b9880c4b319c3297d3a1ada67b29e3d02a36ab34ca1ed7eb09100ccd6e7c8025bf1e8cc29c1a100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004181bab243a1ecce9bdd26dfda25572954ac860f73d1e9d94d561a059c3c75de9602237c5f16e18af464611c94389003184c3f4de55b25ee91394ceae8df4cffee1b00000000000000000000000000000000000000000000000000000000000000";
    address constant delegator = 0xC1858Ebc21FA2553257e95D1Aa95dC0e18AB56aF;
    uint256 constant chain_id = 421614;

    function run() external {
        vm.startBroadcast();
        if(block.chainid == 421614){
            _populate_vote();
        }else{
            console.log("Can't populate votes on unsupported chainid");
        }
        vm.stopBroadcast();
    }

    function _populate_vote() internal {
        console.log("===  Populating vote ===");
        console.log("Chain ID:", block.chainid);
        console.log("timestamp", block.timestamp);

        bytes[] memory votes = new bytes[](1);
        votes[0] = encrypted_vote;

        address[] memory delegators = new address[](1);
        delegators[0] = delegator;

        uint256[] memory chainIds = new uint256[](1);
        chainIds[0] = chain_id;

        gov.vote(proposal, votes, delegators, chainIds);

        console.log("Vote populated.");
    }
}