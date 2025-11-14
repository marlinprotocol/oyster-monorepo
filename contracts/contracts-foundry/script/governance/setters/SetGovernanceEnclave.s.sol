// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {GovernanceEnclave} from "../../../src/governance/GovernanceEnclave.sol";
import {GovernanceAddresses} from "../GovernanceAddresses.s.sol";

contract SetGovernanceEnclaveBase is GovernanceAddresses {
    
    GovernanceEnclave public governanceEnclave;
    constructor() {
        address governanceEnclaveProxy = vm.parseJsonAddress(addressesJson, ".GovernanceEnclave.proxy");
        governanceEnclave = GovernanceEnclave(governanceEnclaveProxy);
        
        console.log("Loaded GovernanceEnclave proxy:", governanceEnclaveProxy);
    }
}

// forge script script/governance/setters/SetGovernanceEnclave.s.sol:SetPCRConfig --rpc-url <RPC_URL> --broadcast
contract SetPCRConfig is SetGovernanceEnclaveBase {
    
    bytes constant PCR0 = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bytes constant PCR1 = hex"111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
    bytes constant PCR2 = hex"222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";
    
    function run() external {
        vm.startBroadcast();
        governanceEnclave.setPCRConfig(PCR0, PCR1, PCR2);
        vm.stopBroadcast();
        
        console.log("PCR config set");
        console.log("  PCR0 length:", PCR0.length);
        console.log("  PCR1 length:", PCR1.length);
        console.log("  PCR2 length:", PCR2.length);
    }
}

// forge script script/governance/setters/SetGovernanceEnclave.s.sol:SetKMSRootServerKey --rpc-url <RPC_URL> --broadcast
contract SetKMSRootServerKey is SetGovernanceEnclaveBase {
    
    bytes constant KMS_ROOT_SERVER_PUB_KEY = hex"d8ad28c9f74e8bf4eb9199e638b2df049282e9c28e40edd096b443ef95b3b829ed785629e1aab7ce66459c76c9888ea26a8eae3a401ac6532824bde249b3292e";
    
    function run() external {
        vm.startBroadcast();
        governanceEnclave.setKMSRootServerKey(KMS_ROOT_SERVER_PUB_KEY);
        vm.stopBroadcast();
        
        console.log("KMS root server key set, length:", KMS_ROOT_SERVER_PUB_KEY.length);
    }
}

// forge script script/governance/setters/SetGovernanceEnclave.s.sol:SetMaxRPCUrlsPerChain --rpc-url <RPC_URL> --broadcast
contract SetMaxRPCUrlsPerChain is SetGovernanceEnclaveBase {
    
    uint256 constant MAX_RPC_URLS_PER_CHAIN = 10;
    
    function run() external {
        vm.startBroadcast();
        governanceEnclave.setMaxRPCUrlsPerChain(MAX_RPC_URLS_PER_CHAIN);
        vm.stopBroadcast();
        
        console.log("Max RPC URLs per chain set:", MAX_RPC_URLS_PER_CHAIN);
    }
}

// forge script script/governance/setters/SetGovernanceEnclave.s.sol:SetNetworkConfig --rpc-url <RPC_URL> --broadcast
contract SetNetworkConfig is SetGovernanceEnclaveBase {
    
    uint256 constant CHAIN_ID = 421614; // Arbitrum Sepolia
    address constant TOKEN_ADDRESS = 0xCe815C7b2E4000f63146fF988F891D6335d262AE;
    
    function run() external {
        string[] memory rpcUrls = new string[](1);
        rpcUrls[0] = "https://arb-sepolia.g.alchemy.com/v2/YOUR_API_KEY";
        
        vm.startBroadcast();
        governanceEnclave.setNetworkConfig(CHAIN_ID, TOKEN_ADDRESS, rpcUrls);
        vm.stopBroadcast();
        
        console.log("Network config set for chain:", CHAIN_ID);
        console.log("  Token address:", TOKEN_ADDRESS);
        console.log("  RPC URLs count:", rpcUrls.length);
    }
}

// forge script script/governance/setters/SetGovernanceEnclave.s.sol:AddRpcUrls --rpc-url <RPC_URL> --broadcast
contract AddRpcUrls is SetGovernanceEnclaveBase {
    
    uint256 constant CHAIN_ID = 421614; // Arbitrum Sepolia
    
    function run() external {
        string[] memory rpcUrls = new string[](2);
        rpcUrls[0] = "https://new-rpc1.example.com";
        rpcUrls[1] = "https://new-rpc2.example.com";
        
        vm.startBroadcast();
        governanceEnclave.addRpcUrls(CHAIN_ID, rpcUrls);
        vm.stopBroadcast();
        
        console.log("RPC URLs added for chain:", CHAIN_ID);
        console.log("  Count:", rpcUrls.length);
    }
}

// forge script script/governance/setters/SetGovernanceEnclave.s.sol:RemoveRpcUrls --rpc-url <RPC_URL> --broadcast
contract RemoveRpcUrls is SetGovernanceEnclaveBase {
    
    uint256 constant CHAIN_ID = 421614; // Arbitrum Sepolia
    
    function run() external {
        uint256[] memory indexes = new uint256[](2);
        indexes[0] = 0;
        indexes[1] = 2;
        
        vm.startBroadcast();
        governanceEnclave.removeRpcUrlsAtIndexes(CHAIN_ID, indexes);
        vm.stopBroadcast();
        
        console.log("RPC URLs removed for chain:", CHAIN_ID);
        console.log("  Indexes count:", indexes.length);
    }
}

// forge script script/governance/setters/SetGovernanceEnclave.s.sol:UpdateRpcUrls --rpc-url <RPC_URL> --broadcast
contract UpdateRpcUrls is SetGovernanceEnclaveBase {
    
    uint256 constant CHAIN_ID = 421614; // Arbitrum Sepolia
    
    function run() external {
        uint256[] memory indexes = new uint256[](2);
        indexes[0] = 0;
        indexes[1] = 1;
        
        string[] memory rpcUrls = new string[](2);
        rpcUrls[0] = "https://updated-rpc1.example.com";
        rpcUrls[1] = "https://updated-rpc2.example.com";
        
        vm.startBroadcast();
        governanceEnclave.updateRpcUrlsAtIndexes(CHAIN_ID, indexes, rpcUrls);
        vm.stopBroadcast();
        
        console.log("RPC URLs updated for chain:", CHAIN_ID);
        console.log("  Updated count:", indexes.length);
    }
}

