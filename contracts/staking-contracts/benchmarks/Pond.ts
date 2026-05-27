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


describe('Pond', function () {
  let signers: Signer[];
  let addrs: string[];

  beforeEach(async function () {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map(a => a.getAddress()));
  });

  benchmarkDeployment('Pond', [], ["Marlin POND", "POND"]);

  it('transfer all to new address', async function () {
    const Pond = await ethers.getContractFactory('Pond');
    let pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });

    let tx = await pond.transfer(addrs[1], BN.from(10e9).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer all to old address', async function () {
    const Pond = await ethers.getContractFactory('Pond');
    let pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
    await pond.transfer(addrs[1], BN.from(1e9).e18());

    let tx = await pond.transfer(addrs[1], BN.from(9e9).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer some to old address', async function () {
    const Pond = await ethers.getContractFactory('Pond');
    let pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
    await pond.transfer(addrs[1], BN.from(1e9).e18());

    let tx = await pond.transfer(addrs[1], BN.from(8e9).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('transfer some to new address', async function () {
    const Pond = await ethers.getContractFactory('Pond');
    let pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });

    let tx = await pond.transfer(addrs[1], BN.from(8e9).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('approve new', async function () {
    const Pond = await ethers.getContractFactory('Pond');
    let pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });

    let tx = await pond.approve(addrs[1], BN.from(8e9).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });

  it('approve old', async function () {
    const Pond = await ethers.getContractFactory('Pond');
    let pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
    await pond.approve(addrs[1], BN.from(1e9).e18());

    let tx = await pond.approve(addrs[1], BN.from(8e9).e18());
    let receipt = await tx.wait();

    console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
  });
});

