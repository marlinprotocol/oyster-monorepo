import { ethers, run, upgrades } from 'hardhat';
import { Contract } from 'ethers';
import * as fs from 'fs';
import { upgrade as upgradeUtil } from '../utils/Upgrade';
const config = require('./config');

export async function deploy(rewardDelegators: string, receiverStaking: string, clusterSelectorMap: any, admin?: string, noLog?: boolean): Promise<Contract> {
  let chainId = (await ethers.provider.getNetwork()).chainId;

  const chainConfig = config[chainId];

  const ClusterRewards = await ethers.getContractFactory('ClusterRewards');

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(!noLog) {
    console.log("Chain Id:", chainId);

    if(fs.existsSync('address.json')) {
      addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
    }

    if(addresses[chainId] === undefined) {
      addresses[chainId] = {};
    }

    if(addresses[chainId]['ClusterRewards'] !== undefined) {
      console.log("Existing deployment:", addresses[chainId]['ClusterRewards']);
      return ClusterRewards.attach(addresses[chainId]['ClusterRewards']);
    }
  }


  const networkIds: string[] = [];
  const rewardWeights: string[] = [];
  const clusterSelectors: string[] = [];

  for(let network in chainConfig.staking.rewardWeights) {
    networkIds.push(ethers.utils.id(network));
    rewardWeights.push(chainConfig.staking.rewardWeights[network]);
    clusterSelectors.push(clusterSelectorMap[network]);
  }

  if(!admin) admin = chainConfig.admin;

  let clusterRewards = await upgrades.deployProxy(ClusterRewards, [
    admin,
    rewardDelegators,
    receiverStaking,
    networkIds,
    rewardWeights,
    clusterSelectors,
    chainConfig.totalRewardsPerEpoch
  ], { kind: "uups" });

  if(!noLog) {
    console.log("Deployed addr:", clusterRewards.address);

    addresses[chainId]['ClusterRewards'] = clusterRewards.address;

    fs.writeFileSync('address.json', JSON.stringify(addresses, null, 2), 'utf8');
  }

  return clusterRewards;
}

export async function upgrade() {
  await upgradeUtil('ClusterRewards', 'ClusterRewards', []);
}

export async function verify() {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined || addresses[chainId]['ClusterRewards'] === undefined) {
    throw new Error("Cluster Rewards not deployed");
  }

  const implAddress = await upgrades.erc1967.getImplementationAddress(addresses[chainId]['ClusterRewards']);

  await run("verify:verify", {
    address: implAddress,
    constructorArguments: []
  });

  console.log("Cluster Rewards verified");
}
