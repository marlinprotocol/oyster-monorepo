import { ethers, upgrades, run } from 'hardhat';
import * as fs from 'fs'

async function main() {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined ||
     addresses[chainId]['Pond'] === undefined ||
     addresses[chainId]['MPond'] === undefined ||
     addresses[chainId]['StakeManager'] === undefined
  ) {
    console.log("Missing dependencies");
    return;
  }

  if(addresses[chainId]['Bridge'] !== undefined) {
    console.log("Existing deployment:", addresses[chainId]['Bridge']);
    return;
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const Bridge = await ethers.getContractFactory('Bridge');
  let bridge = await upgrades.deployProxy(Bridge, [
    addresses[chainId]['MPond'],
    addresses[chainId]['Pond'],
    addresses[chainId]['StakeManager']
  ], { kind: "uups" });

  console.log("Deployed addr:", bridge.address);

  addresses[chainId]['Bridge'] = bridge.address;

  fs.writeFileSync('address.json', JSON.stringify(addresses, null, 2), 'utf8');
}

async function verify() {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(
    addresses[chainId] === undefined ||
    addresses[chainId]['Bridge'] === undefined
  ) {
    console.log("Missing dependencies");
    return;
  }

  await run("verify:verify", {
    address: addresses[chainId]['Bridge'],
    constructorArguments: []
  });
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

