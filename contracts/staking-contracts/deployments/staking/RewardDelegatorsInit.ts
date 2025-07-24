import { ethers } from 'hardhat';
import * as fs from 'fs';
const config = require('./config');

export async function init(rewardDelegators: string, stakeManager: string, clusterRewards: string, clusterRegistry: string) {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  const chainConfig = config[chainId];

  var addresses: { [key: string]: { [key: string]: string } } = {};
  if (fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if (addresses[chainId] === undefined) {
    addresses[chainId] = {};
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const RewardDelegators = await ethers.getContractFactory('RewardDelegators');
  let rewardDelegatorsContract = await RewardDelegators.attach(rewardDelegators);

  const tokenIds = [];
  const rewardFactors = [];
  const weightForThreshold = [];
  const weightForDelegation = [];

  for (let token in chainConfig.staking.tokens) {
    const tokenInfo = chainConfig.staking.tokens[token];
    tokenIds.push(tokenInfo.id);
    rewardFactors.push(tokenInfo.rewardFactor);
    weightForThreshold.push(tokenInfo.weightForThreshold);
    weightForDelegation.push(tokenInfo.weightForDelegation);
  }

  await rewardDelegatorsContract.initialize(
    stakeManager,
    clusterRewards,
    clusterRegistry,
    chainConfig.staking.tokens.POND.address,
    tokenIds,
    rewardFactors,
    weightForThreshold,
    weightForDelegation,
    [],
    [],
  );

  for (let network in chainConfig.staking.thresholdForSelection) {
    await rewardDelegatorsContract.updateThresholdForSelection(ethers.utils.id(network), chainConfig.staking.thresholdForSelection[network]);
  }

  console.log("Initialized rewardDelegators at", rewardDelegators);
}
