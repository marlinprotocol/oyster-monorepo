import { ethers, upgrades, network, run } from 'hardhat';
import { getImplementationAddress } from '@openzeppelin/upgrades-core';
import { BigNumber as BN, Signer, Contract } from 'ethers';
import { MarketV1__factory, UUPSUpgradeable__factory } from '../../../typechain-types';

// 2024-03-04 Arbitrum Sepolia Upgrade
const MARKET_V1_ADDRESS = '0xDcD2846DCA523Db1C8F3c842a41A58099dE26A0A';

async function deployAndUpgrade() {
  let signers = await ethers.getSigners();
  const admin = signers[0];
  const marketV1Proxy = UUPSUpgradeable__factory.connect(MARKET_V1_ADDRESS, admin);
  const newMarketV1Impl = await new MarketV1__factory(admin).deploy();
  await newMarketV1Impl.deployed();

  const tx = await marketV1Proxy.connect(admin).upgradeTo(newMarketV1Impl.address);
  await tx.wait();

  console.log("MarketV1 upgraded to:", newMarketV1Impl.address);
}

async function verify() {
  const marketV1ImplAddr = await getImplementationAddress(ethers.provider, MARKET_V1_ADDRESS);
  console.log("MarketV1 implementation address:", marketV1ImplAddr);

    // Verify on Etherscan
    let verificationResult;
    try {
      verificationResult = await run("verify:verify", {
        address: marketV1ImplAddr,
      });
      console.log({ verificationResult });  
    } catch (error) {
      console.error("Error verifying MarketV1 implementation on Etherscan:", error);
    }
  
    // Verify on Tenderly
    // try {
    //   await tenderly.verify({
    //     address: marketV1ImplAddr,
    //     name: "MarketV1",
    //   });
    // } catch (error) {
    //   console.error("Error verifying MarketV1 implementation on Tenderly:", error);
    // }
}

deployAndUpgrade()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

// verify()
//   .then(() => process.exit(0))
//   .catch((error) => {
//     console.error(error);
//     process.exit(1);
//   });
