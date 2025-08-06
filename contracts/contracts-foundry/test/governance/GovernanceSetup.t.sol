// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {DeployGovernance} from "../../script/governance/DeployGovernance.s.sol";
import {IGovernanceTypes} from "../../src/governance/interfaces/IGovernanceTypes.sol";
import {Governance} from "../../src/governance/Governance.sol";
import {MockERC20} from "../../src/governance/mocks/MockERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract GovernanceSetup is Test {
    Governance public governance;

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
    
    IGovernanceTypes.PCR public pcr;
    bytes public kmsRootServerPubKey;
    string public kmsPath;

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
        pcr = IGovernanceTypes.PCR({
                pcr0: hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                pcr1: hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                pcr2: hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            });

        kmsRootServerPubKey = hex"14eadecaec620fac17b084dcd423b0a75ed2c248b0f73be1bb9b408476567ffc221f420612dd995555650dc19dbe972e7277cb6bfe5ce26650ec907be759b276";
        kmsPath = "governance_test";
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
        depositToken.initialize(
            "Deposit Token",
            "DET",
            admin,
            admin,
            admin
        );

        marlinGovernanceToken = MockERC20(address(new ERC1967Proxy(address(new MockERC20()), "")));
        marlinGovernanceToken.initialize(
            "Marlin Governance Token",
            "MGT",
            admin,
            admin,
            admin
        );
        
        /* Deploy Governance and initialize */
        vm.startPrank(admin);
        governance = Governance(address(new ERC1967Proxy(address(new Governance()), "")));
        governance.initialize(
            admin,
            configSetter,
            treasury,
            minQuorumThreshold,
            proposalPassVetoThreshold,
            vetoSlashRate,
            voteActivationDelay,
            voteDuration,
            proposalDuration,
            maxRPCUrlsPerChain,
            pcr,
            kmsRootServerPubKey,
            kmsPath
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
        vm.startPrank(configSetter);
        governance.setTokenLockAmount(address(depositToken), DEPOSIT_AMOUNT);

        string[] memory rpcUrls = new string[](maxRPCUrlsPerChain);
        for (uint256 i = 0; i < maxRPCUrlsPerChain; i++) {
            rpcUrls[i] = "https://rpc.marlin.com";
        }

        governance.setNetworkConfig(
            block.chainid,
            address(marlinGovernanceToken),
            rpcUrls
        );
        vm.stopPrank();
    }
}