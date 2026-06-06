import { ethers, upgrades } from 'hardhat';
import * as fs from 'fs';

export async function upgrade(contractName: string, contractId: string, constructorArgs?: any[]) {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined ||
     addresses[chainId][contractId] === undefined
  ) {
    console.log("Missing dependencies");
    return;
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const CF = await ethers.getContractFactory(contractName);
  let c = await upgrades.upgradeProxy(addresses[chainId][contractId], CF, { 
    kind: "uups",
    constructorArgs
  });

  console.log("Deployed addr:", c.address);
}