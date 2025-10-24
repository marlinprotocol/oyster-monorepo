import { ethers, upgrades } from "hardhat";
import { expect, util } from "chai";
import { BigNumber as BN, Signer } from "ethers";
import { sign } from "crypto";
import { getTimelock } from "../../utils/typechainConvertor";

declare module "ethers" {
  interface BigNumber {
    e18(this: BigNumber): BigNumber;
  }
}

BN.prototype.e18 = function () {
  return this.mul(BN.from(10).pow(18));
};

describe("Timelock", function () {
  let signers: Signer[];
  let addrs: string[];
  beforeEach(async function () {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
  });

  it("deploys with initialization disabled", async function () {
    const Timelock = await ethers.getContractFactory("Timelock");
    let timelockContract = await Timelock.deploy();
    let timelock = getTimelock(timelockContract.address, signers[0]);
    await expect(timelock.initialize(2 * 24 * 60 * 60)).to.be.reverted;
  });

  it("deploys as proxy and initializes", async function () {
    const Timelock = await ethers.getContractFactory("Timelock");
    let timelockContract = await upgrades.deployProxy(Timelock, [2 * 24 * 60 * 60], { kind: "uups" });
    let timelock = getTimelock(timelockContract.address, signers[0]);

    expect(await timelock.delay()).to.equal(2 * 24 * 60 * 60);
    expect(await timelock.hasRole(await timelock.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
  });

  it("upgrades", async function () {
    const Timelock = await ethers.getContractFactory("Timelock");
    let timelockContract = await upgrades.deployProxy(Timelock, [2 * 24 * 60 * 60], { kind: "uups" });
    let timelock = getTimelock(timelockContract.address, signers[0]);

    await upgrades.upgradeProxy(timelock.address, Timelock, { kind: "uups" });

    expect(await timelock.delay()).to.equal(2 * 24 * 60 * 60);
    expect(await timelock.hasRole(await timelock.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
  });

  it("does not upgrade without admin", async function () {
    const Timelock = await ethers.getContractFactory("Timelock");
    let timelockContract = await upgrades.deployProxy(Timelock, [2 * 24 * 60 * 60], { kind: "uups" });
    let timelock = getTimelock(timelockContract.address, signers[0]);

    await expect(upgrades.upgradeProxy(timelock.address, Timelock.connect(signers[1]), { kind: "uups" })).to.be.reverted;
  });
});
