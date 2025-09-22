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
     addresses[chainId]['RewardDelegators'] === undefined ||
     addresses[chainId]['StakeManager'] === undefined ||
     addresses[chainId]['ClusterRegistry'] === undefined ||
     addresses[chainId]['ClusterRewards'] === undefined ||
     addresses[chainId]['Pond'] === undefined
  ) {
    console.log("Missing dependencies");
    return;
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const RewardDelegators = await ethers.getContractFactory('RewardDelegators');
  let rewardDelegators = await RewardDelegators.attach(addresses[chainId]['RewardDelegators']);

  console.log("Deployed addr:", rewardDelegators.address);

  await rewardDelegators.initialize(
    addresses[chainId]['StakeManager'],
    addresses[chainId]['ClusterRewards'],
    addresses[chainId]['ClusterRegistry'],
    addresses[chainId]['Pond'],
    ["0x5802add45f8ec0a524470683e7295faacc853f97cf4a8d3ffbaaf25ce0fd87c4", "0x1635815984abab0dbb9afd77984dad69c24bf3d711bc0ddb1e2d53ef2d523e5e"],
    [1,1]
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });


