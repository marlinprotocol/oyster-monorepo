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
     addresses[chainId]['RewardDelegators'] === undefined
  ) {
    console.log("Missing dependencies");
    return;
  }

  if(addresses[chainId]['ClusterRewards'] !== undefined) {
    console.log("Existing deployment:", addresses[chainId]['ClusterRewards']);
    return;
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const ClusterRewards = await ethers.getContractFactory('ClusterRewards');
  let clusterRewards = await upgrades.deployProxy(ClusterRewards, [
    addrs[0],
    addresses[chainId]['RewardDelegators'],
    [ethers.utils.id("ETH"), ethers.utils.id("COSMOS"), ethers.utils.id("DOT"), ethers.utils.id("POLYGON")],
    [BN.from(6).e18(), BN.from(3).e18(), BN.from(2).e18(), BN.from(1).e18()],
    BN.from(1200).e18(),
    100000,
    300
  ], { kind: "uups" });

  console.log("Deployed addr:", clusterRewards.address);

  addresses[chainId]['ClusterRewards'] = clusterRewards.address;

  fs.writeFileSync('address.json', JSON.stringify(addresses, null, 2), 'utf8');
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });


