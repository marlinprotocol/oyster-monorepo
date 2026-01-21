import { ethers } from "hardhat";
import fs from "fs";
import {
  run,
} from 'hardhat';


export async function getConfig() {
  const chainId = (await ethers.provider.getNetwork()).chainId.toString();
  console.log("Running script on chain id:", chainId);

  const signers = await ethers.getSigners();
  
  console.log("Signers:", signers);
  for (let i = 0; i < 5; i++) {
    if (!signers[i]) {
      break;
    }
    console.log(signers[i].address);
  }
  if (signers.length > 5) {
    console.log(`... and ${signers.length - 5} more`);
  }

  const path = `./addresses/${chainId}.json`;
  console.log("Path:", path);
  let addresses = JSON.parse(fs.readFileSync(path, "utf-8"));

  if (!Object.keys(addresses).length) {
    const addressesInit = {
      proxy: {},
      implementation: {},
    };
    fs.writeFileSync(path, JSON.stringify(addressesInit, null, 4), "utf-8");
    addresses = addressesInit;
  }

  return { chainId, signers, path, addresses };
}

export enum ContractType {
  Proxy = "proxy",
  Implementation = "implementation",
}

export const verifyContract = async (contractName: string, contractType: ContractType, constructorArguments: any[] = []) => {
  const { addresses } = await getConfig();
  const isProxy = contractType === ContractType.Proxy;
  const type = isProxy ? "proxy" : "implementation";
  
  // Verify in Explorer
  try {
    console.log(`Verifying ${contractName} ${type}...`);
    console.log("constructor args: ", constructorArguments);

    // if first character is Upper case, then convert to lower case
    let contractNameLowerCase = contractName;
    if (contractName.charAt(0) === contractName.charAt(0).toUpperCase()) {
      contractNameLowerCase = contractName.charAt(0).toLowerCase() + contractName.slice(1);
    }

    // verify
    await run("verify:verify", {
      address: addresses[type][contractNameLowerCase],
      constructorArguments: constructorArguments,
    });
    console.log(`(${type}) ${contractName} verified\n`);
  } catch (error) {
    console.log(`[${contractName}]: `, error);
  }
};