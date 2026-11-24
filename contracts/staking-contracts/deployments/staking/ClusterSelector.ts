import { ethers, run, upgrades } from "hardhat";
import { Contract } from "ethers";
import * as fs from "fs";
import { upgrade as upgradeUtil } from '../utils/Upgrade';
const config = require('./config');

export async function deploy(network: string, rewardDelegators: string, arbGasInfo?: string, admin?: string, startTime?: number, epochLength?: number, gasRefund?: string, maxReward?: string, noLog?: boolean): Promise<Contract> {

  let chainId = (await ethers.provider.getNetwork()).chainId;

  const chainConfig = config[chainId];

  const ClusterSelector = await ethers.getContractFactory("ClusterSelector");

  var addresses: { [key: string]: { [key: string]: string } } = {};
  if(!noLog) {
    console.log("Chain Id:", chainId);

    if (fs.existsSync("address.json")) {
      addresses = JSON.parse(fs.readFileSync("address.json", "utf8"));
    }

    if (addresses[chainId] === undefined) {
      addresses[chainId] = {};
    }

    if (addresses[chainId]["ClusterSelector_"+network] !== undefined) {
      console.log("Existing deployment:", addresses[chainId]["ClusterSelector_"+network]);
      return ClusterSelector.attach(addresses[chainId]["ClusterSelector_"+network]);
    }
  }

  if(admin == undefined) {
    admin = chainConfig.admin;
  }

  if(startTime == undefined) startTime = chainConfig.startTime;
  if(epochLength == undefined) epochLength = chainConfig.epochLength;
  if(arbGasInfo == undefined) arbGasInfo = chainConfig.arbGasInfo;
  if(maxReward == undefined) maxReward = chainConfig.clusterSelection.maxReward;
  if(gasRefund === undefined) gasRefund = chainConfig.clusterSelection.gasRefund;

  const clusterSelector = await upgrades.deployProxy(ClusterSelector, [
    admin,
    rewardDelegators,
  ], {
    kind: "uups",
    constructorArgs: [startTime, epochLength, arbGasInfo, maxReward, gasRefund]
  });

  if(!noLog) {
    console.log("Deployed addr:", clusterSelector.address);

    addresses[chainId]["ClusterSelector_"+network] = clusterSelector.address;

    fs.writeFileSync("address.json", JSON.stringify(addresses, null, 2), "utf8");
  }

  return clusterSelector;
}

export async function upgrade(network: string, startTime?: string, epochLength?: number, arbGasInfo?: string, maxReward?: string, gasRefund?: number) {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  const chainConfig = config[chainId];

  if(startTime == undefined) startTime = chainConfig.startTime;
  if(epochLength == undefined) epochLength = chainConfig.epochLength;
  if(arbGasInfo == undefined) arbGasInfo = chainConfig.arbGasInfo;
  if(maxReward == undefined) maxReward = chainConfig.clusterSelection.maxReward;
  if(gasRefund === undefined) gasRefund = chainConfig.clusterSelection.gasRefund;

  await upgradeUtil("ClusterSelector", `ClusterSelector_${network}`, [
    startTime, epochLength, arbGasInfo, maxReward, gasRefund
  ]);
}

export async function verify(network: string) {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  const chainConfig = config[chainId];

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined || addresses[chainId]["ClusterSelector_"+network] === undefined) {
    throw new Error("Cluster Selector not deployed");
  }

  const implAddress = await upgrades.erc1967.getImplementationAddress(addresses[chainId]["ClusterSelector_"+network]);

  await run("verify:verify", {
    address: implAddress,
    constructorArguments: [
      chainConfig.startTime, 
      chainConfig.epochLength, 
      chainConfig.arbGasInfo, 
      chainConfig.clusterSelection.maxReward, 
      chainConfig.clusterSelection.gasRefund
    ]
  });

  console.log("Cluster Selector verified");
}