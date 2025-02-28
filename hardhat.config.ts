import '@typechain/hardhat';
import '@nomiclabs/hardhat-ethers';
import "@nomiclabs/hardhat-etherscan";
import '@openzeppelin/hardhat-upgrades';
import 'solidity-coverage';
import "hardhat-gas-reporter";
import "@nomicfoundation/hardhat-chai-matchers";
import "hardhat-tracer";

import dotenv from 'dotenv';

dotenv.config();

export default {
  networks: {
    hardhat: {
      accounts: {
        count: 500
      },
      allowBlocksWithSameTimestamp: true,
    },
    eth: {
      url: `https://mainnet.infura.io/v3/${process.env.INFURA_API_KEY}`,
      accounts: process.env.ETH_DEPLOYER_KEY !== undefined ? [process.env.ETH_DEPLOYER_KEY] : undefined,
    },
    arb1: {
      url: "https://arb1.arbitrum.io/rpc",
      accounts: process.env.ARBITRUM_DEPLOYER_KEY !== undefined ? [process.env.ARBITRUM_DEPLOYER_KEY] : undefined,
    },
    goerli: {
      url: "https://rpc.goerli.dev",
      accounts: process.env.GOERLI_DEPLOYER_KEY !== undefined ? [process.env.GOERLI_DEPLOYER_KEY] : undefined,
    },
    arbg: {
      url: "https://goerli-rollup.arbitrum.io/rpc",
      accounts: process.env.ARBITRUM_GOERLI_DEPLOYER_KEY !== undefined ? [process.env.ARBITRUM_GOERLI_DEPLOYER_KEY] : undefined,
    },
    arbs: {
      url: "https://sepolia-rollup.arbitrum.io/rpc",
      accounts: process.env.ARBITRUM_SEPOLIA_DEPLOYER_KEY !== undefined ? [process.env.ARBITRUM_SEPOLIA_DEPLOYER_KEY] : undefined,
    },
    linea: {
      url: "https://rpc.linea.build",
    },
    polygon: {
      url: "https://polygon-rpc.com/",
    },
  },
  solidity: {
    version: "0.8.17",
    settings: {
      // viaIR: true,
      optimizer: {
        enabled: true,
        runs: 10000,
      },
      // tried to use SMTChecker, gets killed, investigate later
      // modelChecker: {
      //   engine: "all",
      //   targets: [
      //     "assert",
      //     "overflow",
      //     "underflow",
      //     "divByZero",
      //     "constantCondition",
      //     "popEmptyArray",
      //     "outOfBounds",
      //     "balance",
      //   ],
      // },
    },
  },
  etherscan: {
    apiKey: {
      mainnet: process.env.ETHERSCAN_API_KEY,
      arb1: process.env.ARBISCAN_API_KEY,
      arbg: process.env.ARBISCAN_API_KEY,
      arbs: process.env.ARBISCAN_API_KEY,
      linea: process.env.LINEASCAN_API_KEY,
      polygon: process.env.POLYGONSCAN_API_KEY,
    },
    customChains: [{
      network: "arbg",
      chainId: 421613,
      urls: {
        apiURL: "https://api-goerli.arbiscan.io/api",
        browserURL: "https://goerli.arbiscan.io",
      },
    }, {
      network: "arbs",
      chainId: 421614,
      urls: {
        apiURL: "https://api-sepolia.arbiscan.io/api",
        browserURL: "https://sepolia.arbiscan.io",
      },
    }, {
      network: "arb1",
      chainId: 42161,
      urls: {
        apiURL: "https://api.arbiscan.io/api",
        browserURL: "https://arbiscan.io",
      },
    }, {
      network: "linea",
      chainId: 59144,
      urls: {
        apiURL: "https://api.lineascan.build/api",
        browserURL: "https://lineascan.build",
      },
    }],
  },
  gasReporter: {
    enabled: process.env?.GAS_REPORTER?.toLowerCase() == "true"
  }
};

