const networks = require("../networks");
const deployContract = require("../utils/helpers");

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
    gas: 5000000,
    gasPrice: 158000000000,
    from: web3.eth.accounts.wallet[0].address,
  },
};

const MPondLogic = require("../build/contracts/MPondLogic.json");
const MPondProxy = require("../build/contracts/MPondProxy.json");

async function deploy() {
  const MPondLogicAddress = await deployContract(
    web3,
    MPondLogic.abi,
    MPondLogic.bytecode,
    [],
    config.deploymentConfig
  );

  // const MPondProxyAddress = await deployContract(
  //   web3,
  //   MPondProxy.abi,
  //   MPondProxy.bytecode,
  //   [MPondLogicAddress, proxyAdmin],
  //   config.deploymentConfig
  // );
  const MPondProxyAddress = "Already Exists";
  return {
    MPondLogicAddress,
    MPondProxyAddress,
  };
}

const dropBridgeAddress = "0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf";

async function init() {
  var tokenAddress = "0x28C29ED8D3288d20719F828D75b1445D1aE4DF84";
  var tokenInstance = new web3.eth.Contract(MPondLogic.abi, tokenAddress);
  let result = await tokenInstance.methods
    .initialize(
      "0x0D53E7EB879B5318981a8377f5D459891e2503c5",
      "0xAE60C5F7D4720108813D4843F487F47439c4a5F4",
      dropBridgeAddress
    )
    .send(config.deploymentConfig);
  return result;
}

// init().then(console.log);
deploy().then(console.table).catch(console.log);

// Matic
// ┌───────────────────┬──────────────────────────────────────────────┐
// │      (index)      │                    Values                    │
// ├───────────────────┼──────────────────────────────────────────────┤
// │ MPondLogicAddress │ '0xf8888C42041bfe5b73066f0B4A45781d36D91253' │
// │ MPondProxyAddress │ '0x8B9D1Ce9769b6182988aa14a8013860315Db4513' │
// └───────────────────┴──────────────────────────────────────────────┘

// ETH Mainnet
// ┌───────────────────┬──────────────────────────────────────────────┐
// │      (index)      │                    Values                    │
// ├───────────────────┼──────────────────────────────────────────────┤
// │ MPondLogicAddress │ '0xf7F42f8F26C84898F8a32590dA797c94Af06104c' │
// │ MPondProxyAddress │ '0x7e88Aeaef1163bc6fA1D30cC360a3D5388e161ab' │
// └───────────────────┴──────────────────────────────────────────────┘

// ERC677BridgeToken
// 0xF9c7483851017744FE0A5D79607AC609619B9eA7

// copies
// eth-mpond, matic-mpond
// 0xB5dC1Ea91467adF8a6428063e29Cd83eF9DF1e11, 0xD2A4044881b46BfAc19ed1c73A0F3f277e5A6bA5
// 0x11DB7A790738a51f29809ff9416282677F8495C1, 0x4DE15c28b262356050E2Db74aA7f076B7a136337
// 0x28C29ED8D3288d20719F828D75b1445D1aE4DF84, 0x240C82Fdd68c7991e77f4222dA2A9Ef9a7AaFA67
