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
  let name = process.env.NAME || 'Contract';
  let cname = process.env.CNAME || name;
  let addr = process.env.ADDR || '0x00';
  let roleString = process.env.ROLE || 'SOME_ROLE';
  let role = roleString !== 'DEFAULT_ADMIN_ROLE' ? ethers.utils.id(roleString) : '0x0000000000000000000000000000000000000000000000000000000000000000';
  console.log(name, cname, addr, role);

  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined ||
     addresses[chainId][name] === undefined
  ) {
    console.log("Missing dependencies");
    return;
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const CF = await ethers.getContractFactory(cname);
  let c = CF.attach(addresses[chainId][name]);

  let res = await c.revokeRole(role, addr);
  console.log(res);

  res = await res.wait();
  console.log(res);

}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });


