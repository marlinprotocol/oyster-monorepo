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
  let name = process.env.NAME || 'L1Gateway';
  let tokenName = process.env.TOKENNAME || 'Token';
  let l2GName = process.env.L2GNAME || 'L2Gateway';
  console.log(name, tokenName, l2GName);

  let chainId = (await ethers.provider.getNetwork()).chainId;
  let arbChainId = { '4': '421611', '1': '42161' }[chainId]!;
  console.log("Chain Id:", chainId, arbChainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined ||
     addresses[arbChainId] === undefined ||
     addresses[chainId][tokenName] === undefined ||
     addresses[arbChainId][l2GName] === undefined
  ) {
    console.log("Missing dependencies");
    return;
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const L1Gateway = await ethers.getContractFactory('L1Gateway');
  let l1Gateway = L1Gateway.attach(addresses[chainId][name]);

  console.log("Deployed addr:", l1Gateway.address);

  await l1Gateway.initialize(
    "0x578BAde599406A8fE3d24Fd7f7211c0911F5B29e",
    addresses[chainId][tokenName],
    addresses[arbChainId][l2GName]
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

