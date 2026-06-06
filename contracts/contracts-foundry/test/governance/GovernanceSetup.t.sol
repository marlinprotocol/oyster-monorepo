// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {IGovernanceTypes} from "../../src/governance/interfaces/IGovernanceTypes.sol";
import {Governance} from "../../src/governance/Governance.sol";
import {GovernanceEnclave} from "../../src/governance/GovernanceEnclave.sol";
import {GovernanceDelegation} from "../../src/governance/GovernanceDelegation.sol";
import {MockERC20} from "../../src/governance/mocks/MockERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract GovernanceSetup is Test {
    Governance public governance;
    GovernanceEnclave public governanceEnclave;
    GovernanceDelegation public governanceDelegation;

    uint256 constant GAS_FUND_AMOUNT = 10 ether;
    uint256 constant DEPOSIT_AMOUNT = 100 * 1e18;

    /* Addresses */
    address public admin;
    address public configSetter;
    address public treasury;
    address public proposer;
    address public voter1;
    address public voter2;
    address public voter3;
    address public voter4;

    /* Configurations */
    uint256 public proposalPassVetoThreshold;
    uint256 public minQuorumThreshold;
    uint256 public vetoSlashRate;
    uint256 public voteActivationDelay;
    uint256 public voteDuration;
    uint256 public proposalDuration;
    uint256 public maxRPCUrlsPerChain;

    bytes public pcr0;
    bytes public pcr1;
    bytes public pcr2;
    bytes public pcr16;
    bytes public kmsRootServerPubKey;

    /* Tokens */
    MockERC20 public depositToken;
    MockERC20 public marlinGovernanceToken;

    constructor() {
        // Initialize test addresses
        admin = makeAddr("admin");
        configSetter = makeAddr("configSetter");
        treasury = makeAddr("treasury");
        proposer = makeAddr("proposer");
        voter1 = makeAddr("voter1");
        voter2 = makeAddr("voter2");
        voter3 = makeAddr("voter3");
        voter4 = makeAddr("voter4");

        // Initialize configuration addresses (these will be set to actual contract addresses in setUp)
        proposalPassVetoThreshold = 1 * 10e18 / 100; // 1% of total supply
        minQuorumThreshold = 5 * 10e18 / 100; // 5% of total supply
        vetoSlashRate = 30 * 1e18 / 100; // 30%
        voteActivationDelay = 1 * 60; // 1 minute
        voteDuration = 2 * 60; // 2 minutes
        proposalDuration = 10 * 60; // 10 minutes (must be > voteActivationDelay + voteDuration)
        maxRPCUrlsPerChain = 10;

        pcr0 = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        pcr1 = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        pcr2 = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        pcr16 = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        kmsRootServerPubKey =
            hex"d8ad28c9f74e8bf4eb9199e638b2df049282e9c28e40edd096b443ef95b3b829ed785629e1aab7ce66459c76c9888ea26a8eae3a401ac6532824bde249b3292e";
    }

    function setUp() public virtual {
        vm.deal(admin, GAS_FUND_AMOUNT);
        vm.deal(configSetter, GAS_FUND_AMOUNT);
        vm.deal(treasury, GAS_FUND_AMOUNT);
        vm.deal(proposer, GAS_FUND_AMOUNT);
        vm.deal(voter1, GAS_FUND_AMOUNT);
        vm.deal(voter2, GAS_FUND_AMOUNT);
        vm.deal(voter3, GAS_FUND_AMOUNT);

        vm.label(admin, "admin");
        vm.label(configSetter, "configSetter");
        vm.label(treasury, "treasury");
        vm.label(proposer, "proposer");
        vm.label(voter1, "voter1");
        vm.label(voter2, "voter2");
        vm.label(voter3, "voter3");

        /* Deploy Tokens */
        depositToken = MockERC20(address(new ERC1967Proxy(address(new MockERC20()), "")));
        depositToken.initialize("Deposit Token", "DET", admin, admin, admin);

        marlinGovernanceToken = MockERC20(address(new ERC1967Proxy(address(new MockERC20()), "")));
        marlinGovernanceToken.initialize("Marlin Governance Token", "MGT", admin, admin, admin);

        /* Deploy GovernanceEnclave and initialize */
        vm.startPrank(admin);
        governanceEnclave = GovernanceEnclave(address(new ERC1967Proxy(address(new GovernanceEnclave()), "")));
        governanceEnclave.initialize(admin, kmsRootServerPubKey, pcr0, pcr1, pcr2, pcr16, maxRPCUrlsPerChain);

        // Grant configSetter role to configSetter address
        governanceEnclave.grantRole(governanceEnclave.GOVERNANCE_ADMIN_CONFIG_SETTER_ROLE(), configSetter);
        vm.stopPrank();

        /* Deploy GovernanceDelegation and initialize */
        vm.startPrank(admin);
        governanceDelegation = GovernanceDelegation(address(new ERC1967Proxy(address(new GovernanceDelegation()), "")));
        governanceDelegation.initialize(admin);
        vm.stopPrank();

        /* Deploy Governance and initialize */
        vm.startPrank(admin);
        governance = Governance(address(new ERC1967Proxy(address(new Governance()), "")));
        governance.initialize(
            admin,
            configSetter,
            treasury,
            address(governanceEnclave),
            minQuorumThreshold,
            proposalPassVetoThreshold,
            vetoSlashRate,
            voteActivationDelay,
            voteDuration,
            proposalDuration
        );
        _setUpConfig();
        vm.stopPrank();

        // Setup proposer with deposit tokens
        vm.startPrank(admin);
        depositToken.mint(proposer, 1000 * 1e18); // Mint 1000 tokens to proposer
        vm.stopPrank();

        vm.startPrank(proposer);
        depositToken.approve(address(governance), type(uint256).max); // Approve governance to spend tokens
        vm.stopPrank();
    }

    function _setUpConfig() internal {
        // Set network config on GovernanceEnclave (requires admin)
        vm.startPrank(admin);
        string[] memory rpcUrls = new string[](maxRPCUrlsPerChain);
        for (uint256 i = 0; i < maxRPCUrlsPerChain; i++) {
            rpcUrls[i] = "https://rpc.marlin.com";
        }

        governanceEnclave.setNetworkConfig(block.chainid, address(marlinGovernanceToken), rpcUrls);
        vm.stopPrank();

        // Set token lock amount and governance delegation (requires configSetter)
        vm.startPrank(configSetter);
        governance.setTokenLockAmount(address(depositToken), DEPOSIT_AMOUNT);
        governance.addGovernanceDelegation(block.chainid, address(governanceDelegation));
        vm.stopPrank();
    }

    //-------------------------------- Common Helpers start --------------------------------//

    /// @dev Helper to build ProposeInputParams with single target
    function _buildProposeParams(
        address target,
        uint256 value,
        bytes memory calldata_,
        string memory title,
        string memory description
    ) internal view returns (IGovernanceTypes.ProposeInputParams memory) {
        address[] memory targets = new address[](1);
        targets[0] = target;

        uint256[] memory values = new uint256[](1);
        values[0] = value;

        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = calldata_;

        return IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: title,
            description: description,
            depositToken: address(depositToken)
        });
    }

    /// @dev Helper to create a simple proposal with default params
    function _createSimpleProposal() internal returns (bytes32) {
        return _createProposal(
            makeAddr("target"), 0, abi.encodeWithSignature("function()"), "Test Proposal", "Test Description"
        );
    }

    /// @dev Helper to create a proposal with custom params
    function _createProposal(
        address target,
        uint256 value,
        bytes memory calldata_,
        string memory title,
        string memory description
    ) internal returns (bytes32) {
        address[] memory targets = new address[](1);
        targets[0] = target;

        uint256[] memory values = new uint256[](1);
        values[0] = value;

        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = calldata_;

        return _createProposalWithArrays(targets, values, calldatas, title, description);
    }

    /// @dev Helper to create a proposal with arrays
    function _createProposalWithArrays(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory title,
        string memory description
    ) internal returns (bytes32) {
        IGovernanceTypes.ProposeInputParams memory params = IGovernanceTypes.ProposeInputParams({
            targets: targets,
            values: values,
            calldatas: calldatas,
            title: title,
            description: description,
            depositToken: address(depositToken)
        });

        // Calculate total ETH needed
        uint256 totalValue = 0;
        for (uint256 i = 0; i < values.length; i++) {
            totalValue += values[i];
        }

        vm.prank(proposer);
        return governance.propose{value: totalValue}(params);
    }

    /// @dev Helper to mint additional tokens for proposer (if needed beyond initial 1000)
    function _mintTokensForProposer(uint256 amount) internal {
        vm.prank(admin);
        depositToken.mint(proposer, amount);
    }

    /// @dev Helper for single vote
    function _vote(bytes32 _proposalId, bytes memory _voteEncrypted, address _delegator, uint256 _delegatorChainId)
        internal
    {
        bytes[] memory voteEncrypteds = new bytes[](1);
        address[] memory delegators = new address[](1);
        uint256[] memory delegatorChainIds = new uint256[](1);

        voteEncrypteds[0] = _voteEncrypted;
        delegators[0] = _delegator;
        delegatorChainIds[0] = _delegatorChainId;

        governance.vote(_proposalId, voteEncrypteds, delegators, delegatorChainIds);
    }

    /// @dev Helper to warp to voting period
    function _warpToVotingPeriod(bytes32 _proposalId) internal {
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(_proposalId);
        vm.warp(timeInfo.voteActivationTimestamp + 1);
    }

    /// @dev Helper to warp to result submission period
    function _warpToResultPeriod(bytes32 _proposalId) internal {
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(_proposalId);
        vm.warp(timeInfo.voteDeadlineTimestamp + 1);
    }

    /// @dev Helper to warp past proposal deadline
    function _warpPastDeadline(bytes32 _proposalId) internal {
        IGovernanceTypes.ProposalTimeInfo memory timeInfo = governance.getProposalTimeInfo(_proposalId);
        vm.warp(timeInfo.proposalDeadlineTimestamp + 1);
    }

    //-------------------------------- Common Helpers end --------------------------------//
}
