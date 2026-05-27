import { ethers } from 'hardhat';
import { deploy } from './MarketV1';

async function deployMarketV1() {
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  await deploy();
}

deployMarketV1()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
