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
    bytes32 constant proposal = bytes32(0x572259748840B294EF1A7DD08281A01723ECD1AF5B63A8202220E39D1BB03FC2);
    bytes constant encrypted_vote =
        hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000c1042b3605afaa4c28a4fda25a56448a07fe8569957b3462b34a82f5cea87fb9f73eb27ee7f16d0e7df2f8b98591ed611afda4ab22e425092e14d67c4e7ba935e843cf10a6025c1282a8c6a6d25c3b24a1947d108d2d99c05b6ded7a30596ef80b7f7418825260d67d71addaf6d2196cf9c92e4371174e4921c4d2580ba772d66e5d730dfc1b91b5744b865ae5cd5efd27212387185cc2213d20689493f95fd67095c2eb33904e406dc9bd0dba9f7be98668080fa78ceb4f1c1973f07d32a5605a3f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004127e1854616dbd7616643ed338feda24132e616b83ad83af7572a06200d88f41b3d9ac98cf0b9f7e0c3acfa8828f154bfa0d24c48a4dacf73e154e5c8fe98bee41b00000000000000000000000000000000000000000000000000000000000000";
    address constant delegator = 0x7E82Da6A7D4f9Bcc01372e8Fe2E882e18fAd9C5A;
    uint256 constant chain_id = 421614;

    function run() external {
        vm.startBroadcast();
        if (block.chainid == 421614) {
            _populate_vote();
        } else {
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
