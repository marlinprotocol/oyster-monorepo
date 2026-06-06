// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {GovernanceEnclave} from "../../../src/governance/GovernanceEnclave.sol";

contract GetGovernanceEnclaveBase is Script {
    GovernanceEnclave public governanceEnclave;

    constructor() {
        string memory chainIdStr = vm.toString(block.chainid);
        string memory root = vm.projectRoot();
        string memory filePath = string.concat(root, "/script/governance/addresses/", chainIdStr, ".json");
        string memory json = vm.readFile(filePath);

        address governanceEnclaveProxy = vm.parseJsonAddress(json, ".GovernanceEnclave.proxy");
        governanceEnclave = GovernanceEnclave(governanceEnclaveProxy);

        console.log("Loaded GovernanceEnclave proxy:", governanceEnclaveProxy);
    }
}

// forge script script/governance/getters/GetGovernanceEnclave.s.sol:GetPCRConfig --rpc-url <RPC_URL> -vvv
contract GetPCRConfig is GetGovernanceEnclaveBase {
    function run() external view {
        (bytes memory pcr0, bytes memory pcr1, bytes memory pcr2, bytes memory pcr16, bytes32 imageId) =
            governanceEnclave.getPCRConfig();
        console.log("PCR config:");
        console.log("  PCR0 length:", pcr0.length);
        console.log("  PCR1 length:", pcr1.length);
        console.log("  PCR2 length:", pcr2.length);
        console.log("  PCR16 length:", pcr16.length);
        console.log("  Image ID:");
        console.logBytes32(imageId);
    }
}

// forge script script/governance/getters/GetGovernanceEnclave.s.sol:GetKMSRootServerPubKey --rpc-url <RPC_URL> -vvv
contract GetKMSRootServerPubKey is GetGovernanceEnclaveBase {
    function run() external view {
        bytes memory key = governanceEnclave.kmsRootServerPubKey();
        console.log("KMS root server pub key length:", key.length);
    }
}

// forge script script/governance/getters/GetGovernanceEnclave.s.sol:GetMaxRPCUrlsPerChain --rpc-url <RPC_URL> -vvv
contract GetMaxRPCUrlsPerChain is GetGovernanceEnclaveBase {
    function run() external view {
        uint256 max = governanceEnclave.maxRPCUrlsPerChain();
        console.log("Max RPC URLs per chain:", max);
    }
}

// forge script script/governance/getters/GetGovernanceEnclave.s.sol:GetSupportedChainIds --rpc-url <RPC_URL> -vvv
contract GetSupportedChainIds is GetGovernanceEnclaveBase {
    function run() external view {
        uint256[] memory chainIds = governanceEnclave.getAllSupportedChainIds();
        console.log("Supported chain IDs count:", chainIds.length);
        for (uint256 i = 0; i < chainIds.length; i++) {
            console.log("  Chain ID:", chainIds[i]);
        }
    }
}

// forge script script/governance/getters/GetGovernanceEnclave.s.sol:GetTokenNetworkConfig --rpc-url <RPC_URL> -vvv
contract GetTokenNetworkConfig is GetGovernanceEnclaveBase {
    uint256 constant CHAIN_ID = 421614;

    function run() external view {
        GovernanceEnclave.TokenNetworkConfig memory config = governanceEnclave.getTokenNetworkConfig(CHAIN_ID);
        console.log("Token network config for chain:", CHAIN_ID);
        console.log("  Token:", config.tokenAddress);
        console.log("  Chain hash:");
        console.logBytes32(config.chainHash);
        console.log("  RPC URLs count:", config.rpcUrls.length);
    }
}

// forge script script/governance/getters/GetGovernanceEnclave.s.sol:GetNetworkHash --rpc-url <RPC_URL> -vvv
contract GetNetworkHash is GetGovernanceEnclaveBase {
    function run() external view {
        bytes32 networkHash = governanceEnclave.getNetworkHash();
        console.log("Network hash:");
        console.logBytes32(networkHash);
    }
}
