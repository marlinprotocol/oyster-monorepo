import { ethers, upgrades, network, run } from 'hardhat';
import { getImplementationAddress } from '@openzeppelin/upgrades-core';
import { BigNumber as BN, Signer, Contract } from 'ethers';
import { Credit__factory, MarketV1__factory, UUPSUpgradeable__factory } from '../../../typechain-types';
import { ContractType, getConfig, verifyContract } from '../../helper/helper';
import * as fs from 'fs';

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

async function main() {
  await deployMarketV1();
  await deployCredit();
}

// Freshly Deploy MarketV1 
async function deployMarketV1() {
  const { addresses, path } = await getConfig();
  const signers = await ethers.getSigners();
  const admin = signers[0];
  
  // MarketV1
  const MarketV1Contract = await ethers.getContractFactory("MarketV1");
  const marketV1Proxy = await upgrades.deployProxy(MarketV1Contract, [], {
    kind: "uups",
    initializer: false,
    unsafeAllow: ["missing-initializer-call"],
  });
  await marketV1Proxy.deployed();
  const marketV1 = MarketV1__factory.connect(marketV1Proxy.address, admin);
  addresses.proxy.marketV1 = marketV1.address;
  addresses.implementation.marketV1 = await upgrades.erc1967.getImplementationAddress(marketV1.address);
  fs.writeFileSync(path, JSON.stringify(addresses, null, 4), "utf-8");
  console.log("MarketV1 deployed at:\t\t", marketV1.address);

  // TODO: set shutdown window
  // TODO: set Credit Contract

  await verifyContract("MarketV1", ContractType.Proxy);
  await verifyContract("MarketV1", ContractType.Implementation);
}

// Freshly Deploy Credit 
async function deployCredit() {
  const { addresses, path } = await getConfig();

  const signers = await ethers.getSigners();
  const admin = signers[0];

  // Credit
  const CreditContract = await ethers.getContractFactory("Credit");
  const creditProxy = await upgrades.deployProxy(CreditContract, [], {
    kind: "uups",
    initializer: false,
    unsafeAllow: ["missing-initializer-call"],
    constructorArgs: [addresses.proxy.marketV1, addresses.proxy.usdc],
  });
  await creditProxy.deployed();
  const credit = Credit__factory.connect(creditProxy.address, admin);
  console.log("Credit deployed at:\t\t", credit.address);

  // Set Admin
  await credit.connect(admin).initialize(admin.address);

  // set addresses
  addresses.proxy.credit = credit.address;
  addresses.implementation.credit = await upgrades.erc1967.getImplementationAddress(credit.address);

  fs.writeFileSync(path, JSON.stringify(addresses, null, 4), "utf-8");

  await verifyContract("Credit", ContractType.Proxy);
  await verifyContract("Credit", ContractType.Implementation);
}

main()
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
