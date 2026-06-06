// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @notice Check voter balances and percentages of GovernanceToken
 * @dev Reads voter addresses from .env and checks their token balances
 */
contract CheckVoterBalances is Script {
    // Voter addresses from .env
    address constant VOTER1 = 0xdEAE3CD8EE482a154ce49009046fF6315B1D6D17;
    address constant VOTER2 = 0x83c78929a0B9557003259f8001F6b3F46715E727;
    address constant VOTER3 = 0x74f50926AD2980FcA83d804f4a0dC275D67Ad8dC;
    address constant VOTER4 = 0xC3F1D02ED074Dd5414452c8139be1C419367042e;

    // GovernanceToken address from deployment
    address constant GOVERNANCE_TOKEN = 0xCe815C7b2E4000f63146fF988F891D6335d262AE;

    function run() external view {
        console.log("=== Voter Balance Check on Arbitrum Sepolia ===");
        console.log("GovernanceToken Address:", GOVERNANCE_TOKEN);
        console.log("");

        // Get total supply
        IERC20 governanceToken = IERC20(GOVERNANCE_TOKEN);
        uint256 totalSupply = governanceToken.totalSupply();
        console.log("Total Supply:", totalSupply);
        console.log("");

        // Check each voter's balance
        _checkVoterBalance(governanceToken, VOTER1, "Voter1", totalSupply);
        _checkVoterBalance(governanceToken, VOTER2, "Voter2", totalSupply);
        _checkVoterBalance(governanceToken, VOTER3, "Voter3", totalSupply);
        _checkVoterBalance(governanceToken, VOTER4, "Voter4", totalSupply);

        console.log("");
        console.log("=== Summary ===");

        // Calculate total voter holdings
        uint256 totalVoterHoldings = 0;
        totalVoterHoldings += governanceToken.balanceOf(VOTER1);
        totalVoterHoldings += governanceToken.balanceOf(VOTER2);
        totalVoterHoldings += governanceToken.balanceOf(VOTER3);
        totalVoterHoldings += governanceToken.balanceOf(VOTER4);

        console.log("Total Voter Holdings:", totalVoterHoldings);
        console.log("Total Voter Percentage:", (totalVoterHoldings * 10000) / totalSupply / 100, "%");
    }

    function _checkVoterBalance(IERC20 token, address voter, string memory voterName, uint256 totalSupply)
        internal
        view
    {
        uint256 balance = token.balanceOf(voter);
        uint256 percentage = totalSupply > 0 ? (balance * 10000) / totalSupply : 0;

        console.log("=== %s ===", voterName);
        console.log("Address:", voter);
        console.log("Balance:", balance);
        console.log("Percentage:", percentage / 100, "%");
        console.log("");
    }
}
