import { ethers, run, upgrades } from 'hardhat';
import { Contract } from 'ethers';
import * as fs from 'fs';
import { upgrade as upgradeUtil } from '../utils/Upgrade';
const config = require('./config');

export async function deploy(rewardDelegators: string): Promise<Contract> {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  const chainConfig = config[chainId];

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined) {
    addresses[chainId] = {};
  }

  const StakeManager = await ethers.getContractFactory('StakeManager');
  if(addresses[chainId]['StakeManager'] !== undefined) {
    console.log("Existing deployment:", addresses[chainId]['StakeManager']);
    return StakeManager.attach(addresses[chainId]['StakeManager']);
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const tokenIds: string[] = [];
  const tokenAddresses: string[] = [];
  const delegatable: boolean[] = [];

  for(let token in chainConfig.staking.tokens) {
    const tokenInfo = chainConfig.staking.tokens[token];
    tokenIds.push(tokenInfo.id);
    tokenAddresses.push(tokenInfo.address);
    delegatable.push(tokenInfo.delegatable);
  }

  let stakeManager = await upgrades.deployProxy(StakeManager, [
    tokenIds,
    tokenAddresses,
    delegatable,
    rewardDelegators,
    chainConfig.staking.waitTimes.redelegation,
    chainConfig.staking.waitTimes.undelegation
  ], { kind: "uups" });

  console.log("Deployed addr:", stakeManager.address);

  addresses[chainId]['StakeManager'] = stakeManager.address;

  fs.writeFileSync('address.json', JSON.stringify(addresses, null, 2), 'utf8');

  return stakeManager;
}

export async function upgrade() {
  await upgradeUtil('StakeManager', 'StakeManager', []);
}

export async function verify() {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined || addresses[chainId]['StakeManager'] === undefined) {
    throw new Error("Stake Manager not deployed");
  }

  const implAddress = await upgrades.erc1967.getImplementationAddress(addresses[chainId]['StakeManager']);

  await run("verify:verify", {
    address: implAddress,
    constructorArguments: []
  });

  console.log("Stake Manager verified");
}