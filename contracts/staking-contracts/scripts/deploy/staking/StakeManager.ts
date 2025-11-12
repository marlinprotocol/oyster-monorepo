import { ethers, upgrades } from 'hardhat';
import { BigNumber as BN, Signer, Contract } from 'ethers';
import * as fs from 'fs';


declare module 'ethers' {
  interface BigNumber {
    e18(this: BigNumber): BigNumber;
  }
}
BN.prototype.e18 = function () {
  return this.mul(BN.from(10).pow(18))
}


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
     addresses[chainId]['RewardDelegators'] === undefined ||
     false
  ) {
    console.log("Missing dependencies");
    return;
  }

  if(addresses[chainId]['StakeManager'] !== undefined) {
    console.log("Existing deployment:", addresses[chainId]['StakeManager']);
    return;
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const StakeManager = await ethers.getContractFactory('StakeManager');
  let stakeManager = await upgrades.deployProxy(StakeManager, [
    ["0x5802add45f8ec0a524470683e7295faacc853f97cf4a8d3ffbaaf25ce0fd87c4", "0x1635815984abab0dbb9afd77984dad69c24bf3d711bc0ddb1e2d53ef2d523e5e"],
    [addresses[chainId]['Pond'], addresses[chainId]['MPond']],
    [false, true],
    addresses[chainId]['RewardDelegators'],
    120,
    300,
    "0x0000000000000000000000000000000000000000",
  ], { kind: "uups" });

  console.log("Deployed addr:", stakeManager.address);

  addresses[chainId]['StakeManager'] = stakeManager.address;

  fs.writeFileSync('address.json', JSON.stringify(addresses, null, 2), 'utf8');
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });


