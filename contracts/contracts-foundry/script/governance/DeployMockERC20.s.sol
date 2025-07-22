// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {MockERC20} from "../../src/governance/Mocks/MockERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {console} from "forge-std/console.sol";

contract DeployMockERC20 is Script {
    // Marlin Goverance Token, MGT: Arbitrum Sepolia, Ethereum Sepolia
    // Deposlit Token: DET: Arbitrum Sepolia
    function run(string calldata _name, string calldata _symbol) external returns (address) {
        address mockErc20 = deployMockERC20(_name, _symbol);
        return mockErc20;
    }

    function deployMockERC20(string calldata _name, string calldata _symbol) public returns (address) {
        vm.startBroadcast();
        
        // Deploy Implementation
        MockERC20 mockERC20 = new MockERC20();

        // Deploy Proxy
        ERC1967Proxy proxy = new ERC1967Proxy(address(mockERC20), "");

        // Initialize Proxy
        MockERC20(address(proxy)).initialize(
            _name,
            _symbol,
            0x7C046645E21B811780Cf420021E6701A9E66935C, // Admin
            0x7C046645E21B811780Cf420021E6701A9E66935C, // Minter Role
            0x7C046645E21B811780Cf420021E6701A9E66935C  // Burner Role
        );

        MockERC20(address(proxy)).grantMinterRole(0xF2F8cCc2294748729D3d609c329A3F2c83517Ad5);

        vm.stopBroadcast();

        console.log("MockERC20 deployed at:", address(mockERC20));
        console.log("MockERC20 Proxy deployed at:", address(proxy));

        return address(mockERC20);
    }
}