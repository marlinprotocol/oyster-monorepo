import { ethers, run, upgrades } from 'hardhat';
import { Contract } from 'ethers';
import * as fs from 'fs';
import { upgrade as upgradeUtil } from '../utils/Upgrade';

export async function deployNoInit(): Promise<Contract> {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined) {
    addresses[chainId] = {};
  }

  const RewardDelegators = await ethers.getContractFactory('RewardDelegators');
  if(addresses[chainId]['RewardDelegators'] !== undefined) {
    console.log("Existing deployment:", addresses[chainId]['RewardDelegators']);
    return RewardDelegators.attach(addresses[chainId]['RewardDelegators']);
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  let rewardDelegators = await upgrades.deployProxy(RewardDelegators, { kind: "uups", initializer: false });

  console.log("Deployed addr:", rewardDelegators.address);

  addresses[chainId]['RewardDelegators'] = rewardDelegators.address;

  fs.writeFileSync('address.json', JSON.stringify(addresses, null, 2), 'utf8');

  return rewardDelegators;
}

export async function upgrade() {
  await upgradeUtil('RewardDelegators', 'RewardDelegators', []);
}

export async function verify() {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined || addresses[chainId]['RewardDelegators'] === undefined) {
    throw new Error("Reward Delegators not deployed");
  }

  const implAddress = await upgrades.erc1967.getImplementationAddress(addresses[chainId]['RewardDelegators']);

  await run("verify:verify", {
    address: implAddress,
    constructorArguments: []
  });

  console.log("Reward Delegators verified");
}