// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {console2} from "forge-std/console2.sol";
import {IGovernanceTypes} from "../../src/governance/interfaces/IGovernanceTypes.sol";
import {IGovernanceErrors} from "../../src/governance/interfaces/IGovernanceErrors.sol";
import {Governance} from "../../src/governance/Governance.sol";
import {GovernanceEnclave} from "../../src/governance/GovernanceEnclave.sol";
import {MockERC20} from "../../src/governance/mocks/MockERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {GovernanceSetup} from "./GovernanceSetup.t.sol";
import {MockEnclave} from "./mocks/MockEnclave.t.sol";
import {IGovernanceTypes} from "../../src/governance/interfaces/IGovernanceTypes.sol";
import {IGovernanceEvents} from "../../src/governance/interfaces/IGovernanceEvents.sol";
import {MockGovernanceReceptor} from "../../src/governance/mocks/MockGovernanceReceptor.sol";

contract GovernanceProposeExecute is GovernanceSetup {
    MockEnclave public mockEnclave;

    /* Mock Governance Receptors*/
    MockGovernanceReceptor mockGovernanceReceptor1;
    MockGovernanceReceptor mockGovernanceReceptor2;

    function setUp() public override {
        super.setUp();
        mockEnclave = new MockEnclave();
        mockGovernanceReceptor1 = new MockGovernanceReceptor();
        mockGovernanceReceptor2 = new MockGovernanceReceptor();
    }

    function test_proposal_execute_1() public {
        // Prepare proposal with multiple targets
        address[] memory targets = new address[](3);
        targets[0] = address(mockGovernanceReceptor1);
        targets[1] = address(mockGovernanceReceptor2);
        targets[2] = address(mockGovernanceReceptor1);

        uint256[] memory values = new uint256[](3);
        uint256 weiValue = 1012;
        values[0] = weiValue;
        values[1] = weiValue;
        values[2] = 0;

        bytes[] memory calldatas = new bytes[](3);
        calldatas[0] =
            abi.encodeWithSignature("actWithWei(bool,uint256,bytes,uint256)", true, 12312, new bytes[](10), 1012);
        calldatas[1] =
            abi.encodeWithSignature("actWithWei(bool,uint256,bytes,uint256)", true, 23984, new bytes[](10), 1012);
        calldatas[2] =
            abi.encodeWithSignature("act(string,address,bytes32,uint8)", "some data", address(1), bytes32(0), 12);

        for (uint256 i = 0; i < calldatas.length; i++) {
            console.log("########## start ###########");
            console.log("value[", i, "]");
            console.log(values[i]);
            console.log("----------------------------");
            console.log("calldata[", i, "]");
            console.logBytes(calldatas[i]);
            console.log("##########  end  ###########");
        }

        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: "Multi-Target Proposal",
            description: "Proposal with multiple targets and values",
            depositToken: address(depositToken)
        });

        // Fund proposer with ETH (for two proposal worth)
        vm.deal(proposer, weiValue + weiValue);

        vm.prank(proposer);
        bytes32 proposalId = governance.propose{value: weiValue + weiValue}(params);

        assertTrue(proposalId != bytes32(0), "Proposal ID should not be zero");

        _warpToVotingPeriod(proposalId);

        // Setup delegation
        address delegator = makeAddr("delegator");
        vm.prank(delegator);
        governanceDelegation.setDelegation(voter1);

        // Vote with mix of direct and delegated votes
        bytes[] memory voteEncrypteds = new bytes[](3);
        address[] memory delegators = new address[](3);
        uint256[] memory delegatorChainIds = new uint256[](3);

        voteEncrypteds[0] = abi.encode("direct_vote");
        voteEncrypteds[1] = abi.encode("delegated_vote1");
        voteEncrypteds[2] = abi.encode("direct_vote2");
        delegators[0] = address(0); // Direct vote
        delegators[1] = delegator; // Delegated vote
        delegators[2] = address(0); // Direct vote
        delegatorChainIds[0] = 0;
        delegatorChainIds[1] = block.chainid;
        delegatorChainIds[2] = 0;

        vm.prank(voter1);
        governance.vote(proposalId, voteEncrypteds, delegators, delegatorChainIds);

        // Verify all votes were recorded
        assertEq(governance.getVoteCount(proposalId), 3);

        _warpToResultPeriod(proposalId);

        MockEnclave.VotePercentage memory votePercentage =
            MockEnclave.VotePercentage({yes: 0.6 * 1e18, no: 0, abstain: 0, noWithVeto: 0});

        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(proposalId);
        bytes32 networkHash = governanceEnclave.getNetworkHash();
        bytes32 voteHash = governance.getVoteHash(proposalId);

        // Get signed result from MockEnclave
        (bytes32 imageId,,) = governance.getProposalHashes(proposalId);
        IGovernanceTypes.SubmitResultInputParams memory submitResultParams = mockEnclave.getResult(
            proposalId,
            imageId,
            votePercentage,
            address(governance),
            timeInfo.proposedTimestamp,
            networkHash,
            governance.contractConfigHash(),
            voteHash
        );

        // Submit the result - should result in veto
        vm.prank(admin);

        console2.log("minQuorumThreshold", minQuorumThreshold);

        vm.expectEmit(true, false, false, false);
        emit IGovernanceEvents.ProposalQueued(proposalId);

        governance.submitResult(submitResultParams);

        _warpPastDeadline(proposalId);

        governance.execute(proposalId);
    }
}
