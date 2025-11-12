import { ethers, run, upgrades } from 'hardhat';
import { Contract } from 'ethers';
import * as fs from 'fs';
import { upgrade as upgradeUtil } from '../utils/Upgrade';
const config = require('./config');


export async function deploy(admin?: string, startTime?: number, epochLength?: number, stakingToken?: string, noLog?: boolean): Promise<Contract> {
  let chainId = (await ethers.provider.getNetwork()).chainId;

  const chainConfig = config[chainId];

  const ReceiverStaking = await ethers.getContractFactory('ReceiverStaking');

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(!noLog) {
    console.log("Chain Id:", chainId);

    if(fs.existsSync('address.json')) {
      addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
    }

    if(addresses[chainId] === undefined) {
      addresses[chainId] = {};
    }

    if(addresses[chainId]['ReceiverStaking'] !== undefined) {
      console.log("Existing deployment:", addresses[chainId]['ReceiverStaking']);
      return ReceiverStaking.attach(addresses[chainId]['ReceiverStaking']);
    }
  }

  let signers = await ethers.getSigners();

  if(admin == undefined) admin = chainConfig.admin;
  if(startTime == undefined) startTime = chainConfig.startTime;
  if(epochLength == undefined) epochLength = chainConfig.epochLength;
  if(stakingToken == undefined) stakingToken = chainConfig.staking.receiver.token;

  let receiverStaking = await upgrades.deployProxy(ReceiverStaking, [ admin, "Receiver POND", "rPOND" ], { 
    kind: "uups",
    constructorArgs: [
      startTime,
      epochLength,
      stakingToken
    ]
  });

  if(!noLog) {
    console.log("Deployed addr:", receiverStaking.address);

    addresses[chainId]['ReceiverStaking'] = receiverStaking.address;

    fs.writeFileSync('address.json', JSON.stringify(addresses, null, 2), 'utf8');
  }

  return receiverStaking;
}

export async function upgrade(startTime?: number, epochLength?: number, stakingToken?: string) {
  let chainId = (await ethers.provider.getNetwork()).chainId
  const chainConfig = config[chainId];

  if(startTime == undefined) startTime = chainConfig.startTime;
  if(epochLength == undefined) epochLength = chainConfig.epochLength;
  if(stakingToken == undefined) stakingToken = chainConfig.staking.receiver.token;

  await upgradeUtil('ReceiverStaking', 'ReceiverStaking', [
    startTime, epochLength, stakingToken
  ]);
}

export async function verify() {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  const chainConfig = config[chainId];

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined || addresses[chainId]['ReceiverStaking'] === undefined) {
    throw new Error("Receiver Staking not deployed");
  }

  const implAddress = await upgrades.erc1967.getImplementationAddress(addresses[chainId]['ReceiverStaking']);

  await run("verify:verify", {
    address: implAddress,
    constructorArguments: [
      chainConfig.startTime,
      chainConfig.epochLength,
      chainConfig.staking.receiver.token
    ]
  });

  console.log("Receiver Staking verified");
}