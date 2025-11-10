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
    bytes32 constant proposal = bytes32(0x4BDD9FF7539E67FCB8AB981E85F2F7B8495B8C3EA155AF4A81CE2FBB5D194B08);
    bytes constant encrypted_vote = hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000c1047979816ad46c5bcfad9100e9c7a63d5b31c5f057ecf3b3cf2d9641c196532a698b7ffec13df930b467fa50f9e129d91a3b9c3e8418882d8533fbb2cb544cf553c46588a8fd8725ad8c387de8d70544a438e9556b31f55127959d5fae30da673e7edeaff1379aefea0839d6ba237f288349dd53e859520d9327ccf82cb0c8613f31253fcba74724d97c528d3f5251a40d6ba3e9e6b5542a27be9838c0ac7332737f793a703a94bfc7adce55c89fa8421656415a602746f205c6b850b18fabe02f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000416b91837e4c1b0e07704eb5bd0b106d0cade3d1f50fcf2b801ecab9ee632bcc8521507a05a59f6ba1fcfb72e8a5c810626a08ca5782192bcb889cd8091d32709d1b00000000000000000000000000000000000000000000000000000000000000";
    address constant delegator = 0xd6BDe11742740c4085c50C18B6Fd17658eAc0E5A;
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