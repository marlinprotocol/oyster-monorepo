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
  let name = process.env.NAME || 'Token';
  let address = process.env.TO;
  let wname = process.env.WNAME || 'TokenGateway';
  let amount = BN.from(process.env.AMOUNT || 1).e18();
  console.log(name, wname, amount);

  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined ||
     addresses[chainId][name] === undefined ||
     (address === undefined && addresses[chainId][wname] === undefined)
  ) {
    console.log("Missing dependencies");
    return;
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const Pond = await ethers.getContractFactory('Pond');
  let mpond = Pond.attach(addresses[chainId][name]);

  console.log("Deployed addr:", mpond.address);

  await mpond.transfer(
    address || addresses[chainId][wname],
    amount
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

