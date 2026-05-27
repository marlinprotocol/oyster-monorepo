import { ethers } from 'hardhat';
import * as fs from 'fs';


async function main() {
  let name = process.env.NAME || 'MPond';
  let wname = process.env.WNAME || 'MPondGateway';
  console.log(name);

  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  var addresses: {[key: string]: {[key: string]: string}} = {};
  if(fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if(addresses[chainId] === undefined ||
     addresses[chainId][name] === undefined ||
     addresses[chainId][wname] === undefined
  ) {
    console.log("Missing dependencies");
    return;
  }

  let signers = await ethers.getSigners();
  let addrs = await Promise.all(signers.map(a => a.getAddress()));

  console.log("Signer addrs:", addrs);

  const MPond = await ethers.getContractFactory('MPond');
  let mpond = MPond.attach(addresses[chainId][name]);

  console.log("Deployed addr:", mpond.address);

  await mpond.grantRole(
    await mpond.WHITELIST_ROLE(),
    addresses[chainId][wname]
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

