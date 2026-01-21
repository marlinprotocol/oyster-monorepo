import { ethers, upgrades } from "hardhat";
import { expect, util } from "chai";
import { BigNumber as BN, Signer } from "ethers";
import { MPond, Timelock } from "../../typechain-types";
import { getGovernorAlpha, getMpond, getTimelock } from "../../utils/typechainConvertor";

declare module "ethers" {
  interface BigNumber {
    e18(this: BigNumber): BigNumber;
  }
}

BN.prototype.e18 = function () {
  return this.mul(BN.from(10).pow(18));
};

describe("GovernorAlpha", function () {
  let signers: Signer[];
  let addrs: string[];
  let mpond: MPond;
  let timelock: Timelock;

  beforeEach(async function () {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    const Timelock = await ethers.getContractFactory("Timelock");
    let timelockContract = await upgrades.deployProxy(Timelock, [2 * 24 * 60 * 60], { kind: "uups" });
    timelock = getTimelock(timelockContract.address, signers[0]);
  });

  it("deploys with initialization disabled", async function () {
    const GovernorAlpha = await ethers.getContractFactory("GovernorAlpha");
    let governorAlphaContract = await GovernorAlpha.deploy();
    let governorAlpha = getGovernorAlpha(governorAlphaContract.address, signers[0]);
    await expect(governorAlpha.initialize(timelock.address, mpond.address, addrs[1])).to.be.reverted;
  });

  it("deploys as proxy and initializes", async function () {
    const GovernorAlpha = await ethers.getContractFactory("GovernorAlpha");
    let governorAlphaContract = await upgrades.deployProxy(GovernorAlpha, [timelock.address, mpond.address, addrs[1]], { kind: "uups" });
    let governorAlpha = getGovernorAlpha(governorAlphaContract.address, signers[0]);

    expect(await governorAlpha.timelock()).to.equal(timelock.address);
    expect(await governorAlpha.MPond()).to.equal(mpond.address);
    expect(await governorAlpha.hasRole(await governorAlpha.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await governorAlpha.guardian()).to.equal(addrs[1]);
  });

  it("upgrades", async function () {
    const GovernorAlpha = await ethers.getContractFactory("GovernorAlpha");
    let governorAlphaContract = await upgrades.deployProxy(GovernorAlpha, [timelock.address, mpond.address, addrs[1]], { kind: "uups" });
    let governorAlpha = getGovernorAlpha(governorAlphaContract.address, signers[0]);
    await upgrades.upgradeProxy(governorAlpha.address, GovernorAlpha, { kind: "uups" });

    expect(await governorAlpha.timelock()).to.equal(timelock.address);
    expect(await governorAlpha.MPond()).to.equal(mpond.address);
    expect(await governorAlpha.hasRole(await governorAlpha.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await governorAlpha.guardian()).to.equal(addrs[1]);
  });

  it("does not upgrade without admin", async function () {
    const GovernorAlpha = await ethers.getContractFactory("GovernorAlpha");
    let governorAlphaContract = await upgrades.deployProxy(GovernorAlpha, [timelock.address, mpond.address, addrs[1]], { kind: "uups" });
    let governorAlpha = getGovernorAlpha(governorAlphaContract.address, signers[0]);

    await expect(upgrades.upgradeProxy(governorAlpha.address, GovernorAlpha.connect(signers[1]), { kind: "uups" })).to.be.reverted;
  });
});
