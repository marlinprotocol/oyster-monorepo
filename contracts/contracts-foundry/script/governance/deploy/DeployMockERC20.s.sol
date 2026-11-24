// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {MockERC20} from "../../../src/governance/mocks/MockERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {console} from "forge-std/console.sol";

contract DeployMockERC20 is Script {
    // Marlin Goverance Token, MGT: Arbitrum Sepolia, Ethereum Sepolia
    // Deposit Token: DET: Arbitrum Sepolia
    function run() external returns (address) {
        string memory _name = "Marlin Governance Tokens";
        string memory _symbol = "MGT";

        address mockErc20 = deployMockERC20(_name, _symbol);
        return mockErc20;
    }

    function deployMockERC20(string memory _name, string memory _symbol) public returns (address) {
        vm.startBroadcast();

        // Deploy Implementation
        MockERC20 mockERC20 = new MockERC20();

        // Deploy Proxy
        ERC1967Proxy proxy = new ERC1967Proxy(address(mockERC20), "");

        // Initialize Proxy
        MockERC20(address(proxy)).initialize(
            _name,
            _symbol,
            0x7E82Da6A7D4f9Bcc01372e8Fe2E882e18fAd9C5A, // Admin
            0x7E82Da6A7D4f9Bcc01372e8Fe2E882e18fAd9C5A, // Minter Role
            0x7E82Da6A7D4f9Bcc01372e8Fe2E882e18fAd9C5A // Burner Role
        );

        MockERC20(address(proxy)).grantMinterRole(0x7E82Da6A7D4f9Bcc01372e8Fe2E882e18fAd9C5A);

        vm.stopBroadcast();

        console.log("Token: ", _name);
        console.log("MockERC20 deployed at:", address(mockERC20));
        console.log("MockERC20 Proxy deployed at:", address(proxy));

        return address(mockERC20);
    }
}
