import { ethers, upgrades, run } from 'hardhat';
import { Contract } from 'ethers';
import * as fs from 'fs';

import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

import { upgrade as upgradeUtil } from './Upgrade';

import * as configI from './config.json';
const config = configI as any;

export async function deploy(): Promise<Contract> {
  const AttestationVerifier = await ethers.getContractFactory('AttestationVerifier');

  let chainId = (await ethers.provider.getNetwork()).chainId.toString();
  console.log("Chain Id:", chainId);

  const chainConfig = config[chainId];

  var addresses: { [key: string]: { [key: string]: string } } = {};
  if (fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if (addresses[chainId] === undefined) {
    addresses[chainId] = {};
  }

  if (addresses[chainId]['AttestationVerifier'] !== undefined) {
    console.log("Existing deployment:", addresses[chainId]['AttestationVerifier']);
    return AttestationVerifier.attach(addresses[chainId]['AttestationVerifier']);
  }

  // Image ids are computed off-chain by the attestation verifier enclave (they cover PCR0, PCR1, PCR2 and PCR16)
  // and cannot be derived from PCRs here, so the config carries the image id directly.
  let enclaveImages = [];
  for (let i = 0; i < chainConfig.enclaves.whitelistedImages.length; i++) {
    const imageId: string | undefined = chainConfig.enclaves.whitelistedImages[i].imageId;
    if (imageId === undefined || imageId === "") {
      throw new Error(`Image ${i}: imageId not defined for image`);
    }
    const imageIdHex = imageId.startsWith("0x") ? imageId.substring(2) : imageId;
    if (!/^[0-9a-fA-F]{64}$/.test(imageIdHex)) {
      throw new Error(`Image ${i}: imageId is not 32 bytes of hex`);
    }
    enclaveImages.push("0x" + imageIdHex);
  }

  let enclaveKeys = [];
  for (let i = 0; i < chainConfig.enclaves.whitelistedImages.length; i++) {
    if (chainConfig.enclaves.whitelistedImages[i].enclaveKey === undefined) {
      throw new Error(`Image ${i}: Enclave key not defined for image`);
    }
    enclaveKeys.push(chainConfig.enclaves.whitelistedImages[i].enclaveKey);
  }

  let admin = chainConfig.admin;

  let attestationVerifier = await upgrades.deployProxy(AttestationVerifier, [enclaveImages, enclaveKeys, admin], { kind: "uups" });

  console.log("Deployed addr:", await attestationVerifier.getAddress());

  addresses[chainId]['AttestationVerifier'] = await attestationVerifier.getAddress();

  fs.writeFileSync('address.json', JSON.stringify(addresses, null, 2), 'utf8');

  return attestationVerifier;
}

export async function upgrade() {
  await upgradeUtil('AttestationVerifier', 'AttestationVerifier', []);
}

export async function verify() {
  let chainId = (await ethers.provider.getNetwork()).chainId.toString();
  console.log("Chain Id:", chainId);

  var addresses: { [key: string]: { [key: string]: string } } = {};
  if (fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if (addresses[chainId] === undefined || addresses[chainId]['AttestationVerifier'] === undefined) {
    throw new Error("Attestation Verifier not deployed");
  }

  await run("verify:verify", {
    address: addresses[chainId]['AttestationVerifier'],
    constructorArguments: []
  });

  console.log("Attestation Verifier verified");
}

yargs(hideBin(process.argv))
  .command({
    command: 'deploy',
    describe: 'Deploy the contract',
    handler: (_argv) => deploy().then(),
  })
  .command({
    command: 'upgrade',
    describe: 'Upgrade the contract',
    handler: (_argv) => upgrade().then(),
  })
  .command({
    command: 'verify',
    describe: 'Verify the contract',
    handler: (_argv) => verify().then(),
  })
  .demandCommand(1, 'expected a command from deploy, upgrade or verify')
  .strict()
  .help()
  .argv;
