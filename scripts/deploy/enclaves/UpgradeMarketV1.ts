import { ethers, upgrades, network, run } from 'hardhat';
import { getImplementationAddress } from '@openzeppelin/upgrades-core';
import { BigNumber as BN, Signer, Contract } from 'ethers';
import { Credit__factory, MarketV1__factory, UUPSUpgradeable__factory } from '../../../typechain-types';
import { ContractType, getConfig, verifyContract } from '../../helper/helper';
import * as fs from 'fs';

// 2024-03-20 Arbitrum Sepolia Upgrade Before Merge
// Upgrade Original MarketV1 contract
// Upgrade Credit Contract
async function main() {
  await deployAndUpgradeMarketV1(); // admin: 0xd7E109d2219b5b5b90656FB8B33F2ba679b22062
  await deployAndUpgradeCredit(); // admin: 0x7C046645E21B811780Cf420021E6701A9E66935C
}

async function deployAndUpgradeMarketV1() {
  const { addresses, path } = await getConfig();
  const signers = await ethers.getSigners();
  const admin = signers[0]; // 0xd7E109d2219b5b5b90656FB8B33F2ba679b22062
  const FIVE_MINUTES = 5 * 60;

  /*//////////////////////////////////////////////////////////////
                      UPGRADE ORIGINAL MARKETV1
  //////////////////////////////////////////////////////////////*/

  // Deploy New Marketv1 Implementation
  const marketV1Proxy = UUPSUpgradeable__factory.connect(addresses.proxy.marketV1, admin);
  const newMarketV1Impl = await new MarketV1__factory(admin).deploy();
  await newMarketV1Impl.deployed();
  
  // save new marketV1 implementation address
  addresses.implementation.marketV1 = newMarketV1Impl.address;
  fs.writeFileSync(path, JSON.stringify(addresses, null, 4), "utf-8");

  // Upgrade to new implementation
  const marketV1UpgradeTx = await marketV1Proxy.connect(admin).upgradeTo(newMarketV1Impl.address);
  await marketV1UpgradeTx.wait();
  
  // Reinitialize MarketV1 (noticePeriod, creditToken)
  const marketV1 = MarketV1__factory.connect(marketV1Proxy.address, admin);
  const reinitializeTx = await marketV1.connect(admin).reinitialize(FIVE_MINUTES, addresses.proxy.credit);
  await reinitializeTx.wait();

  /*//////////////////////////////////////////////////////////////
                          VERIFY CONTRACTS
  //////////////////////////////////////////////////////////////*/
  await verifyContract("MarketV1", ContractType.Implementation);
}

async function deployAndUpgradeCredit() {
  const { addresses, path } = await getConfig();
  const signers = await ethers.getSigners();
  const admin = signers[0]; // 0x7C046645E21B811780Cf420021E6701A9E66935C
  
  /*//////////////////////////////////////////////////////////////
                        UPGRADE CREDIT CONTRACT
  //////////////////////////////////////////////////////////////*/

  // Deploy New Credit Implementation
  const credit = Credit__factory.connect(addresses.proxy.credit, admin);
  const creditProxy = UUPSUpgradeable__factory.connect(addresses.proxy.credit, admin);
  const newCreditImpl = await new Credit__factory(admin).deploy(addresses.proxy.usdc);
  await newCreditImpl.deployed();
  
  // save new credit implementation address
  addresses.implementation.credit = newCreditImpl.address;
  fs.writeFileSync(path, JSON.stringify(addresses, null, 4), "utf-8");

  // Upgrade to new implementation
  const creditUpgradeTx = await creditProxy.connect(admin).upgradeTo(newCreditImpl.address);
  await creditUpgradeTx.wait();

  /*//////////////////////////////////////////////////////////////
                      GRANT ROLES TO MARKETV1
  //////////////////////////////////////////////////////////////*/

  // Grant `TRANSFER_ALLOWED_ROLE` to MarketV1
  await credit.connect(admin).grantRole(await credit.TRANSFER_ALLOWED_ROLE(), addresses.proxy.marketV1);
  // Grant `REDEEMER_ROLE` to MarketV1
  await credit.connect(admin).grantRole(await credit.REDEEMER_ROLE(), addresses.proxy.marketV1); 

  await verifyContract("Credit", ContractType.Implementation, [addresses.proxy.usdc]);
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
