// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Governance} from "../../../src/governance/Governance.sol";
import {HelperConfig, ConfigFactory} from "../HelperConfig.s.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";

contract PopulateProposal is Script {
    
    Governance gov = Governance(0x800E2486D128E6B0a543ddfCd783de22341B84fE);

    function run() external {
        ConfigFactory factory = new ConfigFactory();
        HelperConfig helperConfig = factory.getConfig();

        vm.startBroadcast();
        if(block.chainid == 421614){
            for (uint i = 0; i < 10; i++) {
                _populate_proposal(helperConfig, string(abi.encode("title", i+1)), string(abi.encode("description", i+1)));
            }
        }else{
            console.log("Can't populate proposals on unsupported chainid");
        }
        vm.stopBroadcast();
    }

    function _populate_proposal(HelperConfig helperConfig, string memory title, string memory description) internal {
        console.log("===  Populating Proposal ===");
        console.log("Chain ID:", block.chainid);
        console.log("");

        IERC20 depositToken = IERC20(helperConfig.getDepositTokenAddress());

        uint256 proposalDepositAmount = gov.proposalDepositAmounts(address(depositToken));
        depositToken.approve(address(gov), proposalDepositAmount);

        gov.propose(
            IGovernanceTypes.ProposeInputParams({
                depositToken: address(depositToken),
                targets: new address[](0) ,
                values: new uint256[](0) ,
                calldatas: new bytes[](0) ,
                title: title,
                description: description
            })
        );
    }
}