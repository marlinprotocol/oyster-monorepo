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
  let name = process.env.NAME || 'L2Gateway';
  let tokenName = process.env.TOKENNAME || 'Token';
  let l1GName = process.env.L1GNAME || 'L1Gateway';
  console.log(name);

  let chainId = (await ethers.provider.getNetwork()).chainId;
  let ethChainId = { '421611': '4', '42161': '1' }[chainId]!;
  console.log("Chain Id:", chainId, ethChainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined ||
     addresses[ethChainId] === undefined ||
     addresses[chainId][tokenName] === undefined ||
     addresses[ethChainId][l1GName] === undefined
  ) {
    console.log("Missing dependencies");
    return;
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const L2Gateway = await ethers.getContractFactory('L2Gateway');
  let l2Gateway = L2Gateway.attach(addresses[chainId][name]);

  console.log("Deployed addr:", l2Gateway.address);

  await l2Gateway.initialize(
    addresses[chainId][tokenName],
    addresses[ethChainId][l1GName]
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

