import { ethers } from 'hardhat';
import { deploy } from './AttestationVerifier';

async function deployAttestationVerifier() {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  await deploy();
}

deployAttestationVerifier()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
