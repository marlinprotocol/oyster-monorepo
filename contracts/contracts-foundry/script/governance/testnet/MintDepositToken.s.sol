// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {MockERC20} from "../../../src/governance/mocks/MockERC20.sol";

/**
 * @notice Mint deposit tokens for testnet testing
 * @dev Mints deposit tokens to specified proposer address
 * 
 * USAGE:
 * forge script script/governance/testnet/MintDepositToken.s.sol:MintDepositToken --rpc-url $ARBITRUM_SEPOLIA_RPC_URL --broadcast --account MarlinTestnetAdmin
 */
contract MintDepositToken is Script {
    
    // Token and receiver addresses (update for your testnet)
    address constant DEPOSIT_TOKEN = 0x293A148f62665f77ed0f18FC20C66A696cc7632C; // MockERC20 deposit token
    address constant RECEIVER = 0x51De4205a95fC8B5Dc4a616E616945cfB00facfd; // Proposer address
    
    // Mint amount (1000 tokens with 18 decimals)
    uint256 constant MINT_AMOUNT = 10_000 * 1e18;

    function run() external {
        console.log("=== Minting Deposit Tokens ===");
        console.log("Deposit Token Address:", DEPOSIT_TOKEN);
        console.log("Receiver Address:", RECEIVER);
        console.log("Mint Amount:", MINT_AMOUNT / 1e18, "tokens");
        
        vm.startBroadcast();
        
        MockERC20 depositToken = MockERC20(DEPOSIT_TOKEN);
        
        // Check current balance
        uint256 currentBalance = depositToken.balanceOf(RECEIVER);
        console.log("Current Balance:", currentBalance / 1e18, "tokens");
        
        // Mint tokens
        depositToken.mint(RECEIVER, MINT_AMOUNT);
        console.log("Minted", MINT_AMOUNT / 1e18, "tokens to", RECEIVER);
        
        // Check new balance
        uint256 newBalance = depositToken.balanceOf(RECEIVER);
        console.log("New Balance:", newBalance / 1e18, "tokens");
        
        vm.stopBroadcast();
        
        console.log("=== Mint Complete ===");
    }
}