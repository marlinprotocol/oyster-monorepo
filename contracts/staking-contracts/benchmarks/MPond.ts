import { ethers, upgrades } from 'hardhat';
import { BigNumber as BN, Signer, Contract } from 'ethers';
import { benchmark as benchmarkDeployment } from './helpers/deployment';


declare module 'ethers' {
  interface BigNumber {
    e18(this: BigNumber): BigNumber;
  }
}
BN.prototype.e18 = function () {
  return this.mul(BN.from(10).pow(18))
}


describe('MPond', function () {
  let signers: Signer[];
  let addrs: string[];

  beforeEach(async function () {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map(a => a.getAddress()));
  });

  benchmarkDeployment('MPond', [], []);

  it('grant first whitelist', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });

    let tx = await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('grant second whitelist', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);

    let tx = await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[1]);
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('revoke first whitelist', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);

    let tx = await mpond.revokeRole(await mpond.WHITELIST_ROLE(), addrs[0]);
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('revoke second whitelist', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[1]);

    let tx = await mpond.revokeRole(await mpond.WHITELIST_ROLE(), addrs[1]);
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer all to new address, first whitelisted', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);

    let tx = await mpond.transfer(addrs[1], BN.from(10000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer all to new address, second whitelisted', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[1]);

    let tx = await mpond.transfer(addrs[1], BN.from(10000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer all to new address, both whitelisted', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[1]);

    let tx = await mpond.transfer(addrs[1], BN.from(10000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer all to old address, first whitelisted', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);
    await mpond.transfer(addrs[1], BN.from(1000).e18());

    let tx = await mpond.transfer(addrs[1], BN.from(9000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer all to old address, second whitelisted', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[1]);
    await mpond.transfer(addrs[1], BN.from(1000).e18());

    let tx = await mpond.transfer(addrs[1], BN.from(9000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer all to old address, both whitelisted', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[1]);
    await mpond.transfer(addrs[1], BN.from(1000).e18());

    let tx = await mpond.transfer(addrs[1], BN.from(9000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer some to old address, first whitelisted', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);
    await mpond.transfer(addrs[1], BN.from(1000).e18());

    let tx = await mpond.transfer(addrs[1], BN.from(8000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer some to old address, second whitelisted', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[1]);
    await mpond.transfer(addrs[1], BN.from(1000).e18());

    let tx = await mpond.transfer(addrs[1], BN.from(8000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer some to old address, both whitelisted', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[1]);
    await mpond.transfer(addrs[1], BN.from(1000).e18());

    let tx = await mpond.transfer(addrs[1], BN.from(8000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer some to new address, first whitelisted', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);

    let tx = await mpond.transfer(addrs[1], BN.from(8000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer some to new address, second whitelisted', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[1]);

    let tx = await mpond.transfer(addrs[1], BN.from(8000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer some to new address, both whitelisted', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[1]);

    let tx = await mpond.transfer(addrs[1], BN.from(8000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('approve new', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });

    let tx = await mpond.approve(addrs[1], BN.from(8000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('approve old', async function () {
    const MPond = await ethers.getContractFactory('MPond');
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.approve(addrs[1], BN.from(1000).e18());

    let tx = await mpond.approve(addrs[1], BN.from(8000).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });
});

