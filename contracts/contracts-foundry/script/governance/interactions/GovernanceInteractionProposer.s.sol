// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {GovernanceInteraction} from "./GovernanceInteraction.s.sol";
import {console} from "forge-std/console.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract GovernanceInteractionProposer is GovernanceInteraction {
    constructor() {}

    // Reads proposals.json and proposes only the proposal at the given index
    function proposeByIndex(uint256 idx) public {
        string memory json = vm.readFile("./script/governance/interactions/inputs/proposals.json");
        string memory base = string.concat("[", vm.toString(idx), "]");

        address depositToken = vm.parseJsonAddress(json, string.concat(base, ".depositToken"));
        address[] memory targets = vm.parseJsonAddressArray(json, string.concat(base, ".targets"));
        uint256[] memory values = vm.parseJsonUintArray(json, string.concat(base, ".values"));
        bytes[] memory calldatas = vm.parseJsonBytesArray(json, string.concat(base, ".calldatas"));
        string memory title = vm.parseJsonString(json, string.concat(base, ".title"));
        string memory description = vm.parseJsonString(json, string.concat(base, ".description"));

        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            depositToken: depositToken,
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: title,
            description: description
        });

        // Submit Tx
        uint256 proposerPrivateKey = vm.envUint("PROPOSER_PRIVATE_KEY");
        vm.startBroadcast(proposerPrivateKey);
        IERC20(depositToken).approve(address(governance), type(uint256).max);
        governance.propose(params);
        vm.stopBroadcast();

        console.log("Proposal submitted successfully!\n");
        console.log("title:");
        console.log(title);
        console.log("description:");
        console.log(description);
        console.log("depositToken:", depositToken);
        console.log("targets:");
        for (uint256 i = 0; i < targets.length; i++) {
            console.log(targets[i]);
        }

        console.log("values:");
        for (uint256 i = 0; i < values.length; i++) {
            console.log(values[i]);
        }

        console.log("calldatas:");
        for (uint256 i = 0; i < calldatas.length; i++) {
            console.logBytes(calldatas[i]);
        }

        // console.log("Proposal Id: ");
        // address proposer = vm.addr(proposerPrivateKey);
        // bytes32 descriptionHash = governance.getDescriptionHash(title, description);
        // uint256 nonce = governance.proposerNonce(proposer);
        // bytes32 proposalId = governance.getProposalId(
        //     targets,
        //     values,
        //     calldatas,
        //     descriptionHash,
        //     proposer,
        //     nonce
        // );
        // console.log("proposalId:");
        // console.logBytes32(proposalId);
        // console.log("Proposer Address: ", proposer);
    }

    // Entrypoint for Foundry script execution
    function run() external {
        uint256 idx = vm.envUint("PROPOSAL_INDEX"); // Pass the index via environment variable
        proposeByIndex(idx);
    }
}
