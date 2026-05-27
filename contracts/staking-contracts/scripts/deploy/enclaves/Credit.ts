import { ethers, upgrades, network } from 'hardhat';
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
  let name = process.env.NAME || 'MarketV1';
  console.log(name);

  let chainId = (network.config as any).tag || (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined ||
     addresses[chainId]['Pond'] === undefined
  ) {
    console.log("Missing dependencies");
    return;
  }

  if(addresses[chainId]['MarketV1'] !== undefined) {
    console.log("Existing deployment:", addresses[chainId]['MarketV1']);
    return;
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const MarketV1 = await ethers.getContractFactory('MarketV1');
  let marketv1 = await upgrades.deployProxy(MarketV1, [
    addresses[chainId]['Pond'],
    [ethers.utils.id('RATE_LOCK')],
    [300],
  ], { kind: "uups" });

  console.log("Deployed addr:", marketv1.address);

  addresses[chainId]['MarketV1'] = marketv1.address;

  fs.writeFileSync('address.json', JSON.stringify(addresses, null, 2), 'utf8');
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });


