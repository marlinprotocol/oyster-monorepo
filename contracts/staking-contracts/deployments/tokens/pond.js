const networks = require("../networks");
const deployContract = require("../helpers");

if (!networks[process.env.NETWORK]) {
  console.log("NETWORK not declared or valid in env variables");
  process.exit(1);
} else {
  console.log(`Deploying contracts on ${networks[process.env.NETWORK]}`);
}

const Web3 = require("web3");
const web3 = new Web3(networks[process.env.NETWORK]);

var proxyAdmin;

if (!process.env.PRIV_KEY) {
  console.log("PRIV_KEY not defined in env variables");
} else {
  web3.eth.accounts.wallet.add(process.env.PRIV_KEY);
}

if (!process.env.PROXY_ADMIN) {
  console.log("PROXY_ADMIN is not defined");
  process.exit(1);
} else {
  proxyAdmin = process.env.PROXY_ADMIN;
}

const config = {
  deploymentConfig: {
    gas: 2000000,
    gasPrice: 54000000000,
    from: web3.eth.accounts.wallet[0].address,
  },
};

// standard script
const TokenLogicCompiled = require("../build/contracts/TokenLogic.json");
const TokenProxyCompiled = require("../build/contracts/TokenProxy.json");

async function deploy() {
  const TokenLogicAddress = await deployContract(
    web3,
    TokenLogicCompiled.abi,
    TokenLogicCompiled.bytecode,
    [],
    config.deploymentConfig
  );
  const TokenProxyAddress = await deployContract(
    web3,
    TokenProxyCompiled.abi,
    TokenProxyCompiled.bytecode,
    [TokenLogicAddress, proxyAdmin],
    config.deploymentConfig
  );
  return {
    TokenLogicAddress,
    TokenProxyAddress,
  };
}

deploy().then(console.table).catch(console.log);

// Deploying contracts on https://kovan.infura.io/v3/9dc997986f8840daa0e6ccb1d8d0d757
// 0x55aafb0d5ecc420087ccd56c340b458f2e5da104013cd4a352d2082d86469aaf
// 0x880820dee8446a232cc18ba8bd2df5536df1951225cca820ef0c14c1b4ba8c2e
// ┌───────────────────┬──────────────────────────────────────────────┐
// │      (index)      │                    Values                    │
// ├───────────────────┼──────────────────────────────────────────────┤
// │ TokenLogicAddress │ '0xe01571d3063d39998bd97F7d74c6b90215C7caaf' │
// │ TokenProxyAddress │ '0x92A583dB9F7cBA4847b290A0B5e9E8e28030643c' │
// └───────────────────┴──────────────────────────────────────────────┘

// Deploying contracts on https://mainnet.infura.io/v3/9dc997986f8840daa0e6ccb1d8d0d757
// 0xec452a57179ca048d3b27436daaf5f2f5250eb014d63b217eb4fbea655691f07
// 0xbb74d42076661cfd175537ac46f5ce084b97a384588007f737d00aaf19908173
// ┌───────────────────┬──────────────────────────────────────────────┐
// │      (index)      │                    Values                    │
// ├───────────────────┼──────────────────────────────────────────────┤
// │ TokenLogicAddress │ '0x9777BE0b086C3cc24EF4Ec8CE3bba3556B3AC31b' │
// │ TokenProxyAddress │ '0xDe045Ef9159d91CF93Cc89F4F2173632b1A8d6b8' │
// └───────────────────┴──────────────────────────────────────────────┘
