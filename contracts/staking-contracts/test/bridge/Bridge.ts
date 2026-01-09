import { ethers, upgrades } from "hardhat";
import { expect } from "chai";
import { BigNumber as BN, Signer } from "ethers";
import { Bridge, MPond, Pond } from "../../typechain-types";
import { getBridge, getMpond, getPond } from "../../utils/typechainConvertor";

declare module "ethers" {
  interface BigNumber {
    e18(this: BigNumber): BigNumber;
  }
}

BN.prototype.e18 = function () {
  return this.mul(BN.from(10).pow(18));
};

describe.skip("Bridge", function () {
  let signers: Signer[];
  let addrs: string[];
  let mpond: MPond;
  let pond: Pond;

  beforeEach(async function () {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);
  });

  it("deploys with initialization disabled", async function () {
    const Bridge = await ethers.getContractFactory("Bridge");
    let bridgeContract = await Bridge.deploy();
    let bridge = getBridge(bridgeContract.address, signers[0]);
    await expect(bridge.initialize(mpond.address, pond.address, addrs[1])).to.be.reverted;
  });

  it("deploys as proxy and initializes", async function () {
    const Bridge = await ethers.getContractFactory("Bridge");
    let bridgeContract = await upgrades.deployProxy(Bridge, [mpond.address, pond.address, addrs[1]], { kind: "uups" });
    let bridge = getBridge(bridgeContract.address, signers[0]);

    expect(await bridge.mpond()).to.equal(mpond.address);
    expect(await bridge.pond()).to.equal(pond.address);
    expect(await bridge.hasRole(await bridge.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await bridge.hasRole(await bridge.GOVERNANCE_ROLE(), addrs[1])).to.be.true;
    let currentBlockTimestamp = (await ethers.provider.getBlock(await ethers.provider.getBlockNumber())).timestamp;
    expect(await bridge.startTime()).to.equal(currentBlockTimestamp);
    expect(await bridge.liquidityStartTime()).to.equal(currentBlockTimestamp);
    expect(await bridge.liquidityBp()).to.equal(1000);
    expect(await bridge.lockTimeEpochs()).to.equal(180);
    expect(await bridge.liquidityEpochLength()).to.equal(180 * 24 * 60 * 60);
  });

  it("upgrades", async function () {
    const Bridge = await ethers.getContractFactory("Bridge");
    let bridgeContract = await upgrades.deployProxy(Bridge, [mpond.address, pond.address, addrs[1]], { kind: "uups" });
    let bridge = getBridge(bridgeContract.address, signers[0]);
    await upgrades.upgradeProxy(bridge.address, Bridge, { kind: "uups" });

    expect(await bridge.mpond()).to.equal(mpond.address);
    expect(await bridge.pond()).to.equal(pond.address);
    expect(await bridge.hasRole(await bridge.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await bridge.hasRole(await bridge.GOVERNANCE_ROLE(), addrs[1])).to.be.true;
    let currentBlockTimestamp = (await ethers.provider.getBlock(await ethers.provider.getBlockNumber())).timestamp;
    expect(await bridge.startTime()).to.equal(currentBlockTimestamp - 1);
    expect(await bridge.liquidityStartTime()).to.equal(currentBlockTimestamp - 1);
    expect(await bridge.liquidityBp()).to.equal(1000);
    expect(await bridge.lockTimeEpochs()).to.equal(180);
    expect(await bridge.liquidityEpochLength()).to.equal(180 * 24 * 60 * 60);
  });

  it("does not upgrade without admin", async function () {
    const Bridge = await ethers.getContractFactory("Bridge");
    let bridgeContract = await upgrades.deployProxy(Bridge, [mpond.address, pond.address, addrs[1]], { kind: "uups" });
    let bridge = getBridge(bridgeContract.address, signers[0]);
    await expect(upgrades.upgradeProxy(bridge.address, Bridge.connect(signers[1]), { kind: "uups" })).to.be.reverted;
  });
});

describe.skip("Bridge", function () {
  let signers: Signer[];
  let addrs: string[];
  let bridge: Bridge;

  beforeEach(async function () {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const MPond = await ethers.getContractFactory("MPond");
    const mpond = await upgrades.deployProxy(MPond, { kind: "uups" });

    const Pond = await ethers.getContractFactory("Pond");
    const pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });

    const Bridge = await ethers.getContractFactory("Bridge");
    let bridgeContract = await upgrades.deployProxy(Bridge, [mpond.address, pond.address, addrs[1]], { kind: "uups" });
    bridge = getBridge(bridgeContract.address, signers[0]);
  });

  it("admin can change staking contract", async () => {
    await bridge.changeStakingContract(addrs[2]);
    expect(await bridge.stakingContract()).to.equal(addrs[2]);
  });

  it("governance can change staking contract", async () => {
    await bridge.connect(signers[1]).changeStakingContract(addrs[2]);
    expect(await bridge.stakingContract()).to.equal(addrs[2]);
  });

  it("non admin and non governance cannot change staking contract", async () => {
    await expect(bridge.connect(signers[3]).changeStakingContract(addrs[2])).to.be.reverted;
    expect(await bridge.stakingContract()).to.equal("0x0000000000000000000000000000000000000000");
  });

  it("admin can change liquidityBp", async () => {
    await bridge.changeLiquidityBp(10);
    expect(await bridge.liquidityBp()).to.equal(10);
  });

  it("governance can change liquidityBp", async () => {
    await bridge.connect(signers[1]).changeLiquidityBp(10);
    expect(await bridge.liquidityBp()).to.equal(10);
  });

  it("non admin and non governance cannot change liquidityBp", async () => {
    await expect(bridge.connect(signers[2]).changeLiquidityBp(10)).to.be.reverted;
    expect(await bridge.liquidityBp()).to.equal(1000);
  });

  it("admin can change lock time epochs", async () => {
    await bridge.changeLockTimeEpochs(10);
    expect(await bridge.lockTimeEpochs()).to.equal(10);
  });

  it("governance can change lock time epochs", async () => {
    await bridge.connect(signers[1]).changeLockTimeEpochs(10);
    expect(await bridge.lockTimeEpochs()).to.equal(10);
  });

  it("non admin and non governance cannot change lock time epochs", async () => {
    await expect(bridge.connect(signers[2]).changeLockTimeEpochs(10)).to.be.reverted;
    expect(await bridge.lockTimeEpochs()).to.equal(180);
  });

  it("admin can change liquidity epoch length", async () => {
    await bridge.changeLiquidityEpochLength(10);
    expect(await bridge.liquidityEpochLength()).to.equal(10 * 24 * 60 * 60);
  });

  it("governance can change liquidity epoch length", async () => {
    await bridge.connect(signers[1]).changeLiquidityEpochLength(10);
    expect(await bridge.liquidityEpochLength()).to.equal(10 * 24 * 60 * 60);
  });

  it("non admin and non governance cannot change liquidity epoch length", async () => {
    await expect(bridge.connect(signers[2]).changeLiquidityEpochLength(10)).to.be.reverted;
    expect(await bridge.liquidityEpochLength()).to.equal(180 * 24 * 60 * 60);
  });

  it("admin can be changed by admin", async () => {
    await bridge.transferOwner(addrs[2]);
    expect(await bridge.hasRole(await bridge.DEFAULT_ADMIN_ROLE(), addrs[2])).to.be.true;
  });

  it("cannot change admin to zero address", async () => {
    await expect(bridge.connect(signers[1]).transferOwner("0x0000000000000000000000000000000000000000")).to.be.reverted;
    expect(await bridge.hasRole(await bridge.DEFAULT_ADMIN_ROLE(), addrs[2])).to.be.false;
    expect(await bridge.hasRole(await bridge.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
  });

  it("non admin cannot change admin", async () => {
    await expect(bridge.connect(signers[1]).transferOwner(addrs[2])).to.be.reverted;
    expect(await bridge.hasRole(await bridge.DEFAULT_ADMIN_ROLE(), addrs[2])).to.be.false;
    expect(await bridge.hasRole(await bridge.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
  });

  it("governance can be changed by governance", async () => {
    await bridge.connect(signers[1]).transferGovernance(addrs[2]);
    expect(await bridge.hasRole(await bridge.GOVERNANCE_ROLE(), addrs[2])).to.be.true;
  });

  it("non governance cannot change governance", async () => {
    await expect(bridge.transferGovernance(addrs[2])).to.be.reverted;
    expect(await bridge.hasRole(await bridge.GOVERNANCE_ROLE(), addrs[2])).to.be.false;
    expect(await bridge.hasRole(await bridge.GOVERNANCE_ROLE(), addrs[1])).to.be.true;
  });

  it("non admin cannot renounce ownership", async () => {
    await expect(bridge.connect(signers[1]).renounceOwnership()).to.be.reverted;
  });

  it("admin can renounce ownership", async () => {
    await bridge.renounceOwnership();
    expect(await bridge.hasRole(await bridge.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.false;
  });
});

describe.skip("Bridge", function () {
  let signers: Signer[];
  let addrs: string[];
  let bridge: Bridge;
  let mpond: MPond;
  let pond: Pond;

  beforeEach(async function () {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, [], { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    let WHITELIST_ROLE = await mpond.WHITELIST_ROLE();
    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.transfer(addrs[2], BN.from(1000).e18());

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const Bridge = await ethers.getContractFactory("Bridge");
    let bridgeContract = await upgrades.deployProxy(Bridge, [mpond.address, pond.address, addrs[1]], { kind: "uups" });
    bridge = getBridge(bridgeContract.address, signers[0]);

    await pond.transfer(bridge.address, BN.from(1000000000).e18());
    await mpond.grantRole(WHITELIST_ROLE, bridge.address);
    await mpond.connect(signers[2]).approve(bridge.address, BN.from(1000).e18());
  });

  it("cannot place request for zero amount", async () => {
    await expect(bridge.connect(signers[2]).placeRequest(0)).to.be.reverted;
  });

  it("cannot place request for amount greater than balance/delegation", async () => {
    await expect(bridge.connect(signers[2]).placeRequest(BN.from(1001).e18())).to.be.reverted;
  });

  it("can place request", async () => {
    let req = await bridge.connect(signers[2]).callStatic.placeRequest(BN.from(900).e18());
    expect(req[0]).to.equal(BN.from(0));
    expect(req[1]).to.equal(BN.from(180));
  });

  it("cannot place multiple requests in same epoch", async () => {
    await bridge.connect(signers[2]).placeRequest(BN.from(900).e18());
    await expect(bridge.connect(signers[2]).placeRequest(BN.from(10).e18())).to.be.reverted;
  });

  it("can place another request in different epoch", async () => {
    await bridge.connect(signers[2]).placeRequest(BN.from(900).e18());
    await skipTime(1 * 86400); // 1 day
    let req = await bridge.connect(signers[2]).callStatic.placeRequest(BN.from(10).e18());
    expect(req[0]).to.equal(BN.from(1));
    expect(req[1]).to.equal(BN.from(181));
  });

  it("cannot convert more amount than convertable", async () => {
    await bridge.connect(signers[2]).placeRequest(BN.from(900).e18());
    await skipTime(180 * 86400); // 180 days
    let convertableAmount = await bridge.getConvertableAmount(addrs[2], 0);
    await expect(bridge.convert(0, convertableAmount + 1)).to.be.reverted;
  });

  it("cannot convert before release epoch", async () => {
    await bridge.connect(signers[2]).placeRequest(BN.from(900).e18());
    await skipTime(179 * 86400);
    let convertableAmount = await bridge.getConvertableAmount(addrs[2], 0);
    await expect(bridge.convert(0, convertableAmount)).to.be.reverted;
  });

  it("can convert amount equal to convertable", async () => {
    await bridge.connect(signers[2]).placeRequest(BN.from(900).e18());
    await skipTime(180 * 86400); // 180 days
    let convertableAmount = await bridge.getConvertableAmount(addrs[2], 0);
    await bridge.connect(signers[2]).convert(0, convertableAmount);
    expect(await mpond.balanceOf(addrs[2])).to.equal(BN.from(1000).e18().sub(convertableAmount));
    expect(await mpond.balanceOf(bridge.address)).to.equal(convertableAmount);
    expect(await pond.balanceOf(addrs[2])).to.equal(convertableAmount.mul(1000000));
    expect(await pond.balanceOf(bridge.address)).to.equal(BN.from(1000000000).e18().sub(convertableAmount.mul(1000000)));
  });

  it("can convert partial amount", async () => {
    await bridge.connect(signers[2]).placeRequest(BN.from(900).e18());
    await skipTime(180 * 86400); // 180 days
    let convertableAmount = await bridge.getConvertableAmount(addrs[2], 0);
    await bridge.connect(signers[2]).convert(0, 10000);
    expect(await bridge.claimedAmounts(addrs[2], 0)).to.equal(10000);
    await bridge.connect(signers[2]).convert(0, convertableAmount.sub(10000));
    expect(await mpond.balanceOf(addrs[2])).to.equal(BN.from(1000).e18().sub(convertableAmount));
    expect(await mpond.balanceOf(bridge.address)).to.equal(convertableAmount);
    expect(await pond.balanceOf(addrs[2])).to.equal(convertableAmount.mul(1000000));
    expect(await pond.balanceOf(bridge.address)).to.equal(BN.from(1000000000).e18().sub(convertableAmount.mul(1000000)));
  });

  it("admin can add liquidity", async () => {
    let prevMpondBal = await mpond.balanceOf(bridge.address);
    let prevPondBal = await pond.balanceOf(bridge.address);
    await mpond.approve(bridge.address, 1000);
    await pond.approve(bridge.address, 1000);

    await bridge.addLiquidity(1000, 1000);

    expect(await mpond.balanceOf(bridge.address)).to.equal(prevMpondBal.add(1000));
    expect(await pond.balanceOf(bridge.address)).to.equal(prevPondBal.add(1000));
  });

  it("non admin cannot add liquidity", async () => {
    await pond.transfer(addrs[1], 1000);
    await pond.connect(signers[1]).approve(bridge.address, 1000);
    await mpond.transfer(addrs[1], 1000);
    await mpond.connect(signers[1]).approve(bridge.address, 1000);

    await expect(bridge.connect(signers[1]).addLiquidity(1000, 1000)).to.be.reverted;
  });

  it("admin can remove liquidity", async () => {
    await mpond.approve(bridge.address, 1000);
    await pond.approve(bridge.address, 1000);
    await bridge.addLiquidity(1000, 1000);

    await bridge.removeLiquidity(500, 500, addrs[3]);
    expect(await mpond.balanceOf(addrs[3])).to.equal(500);
    expect(await pond.balanceOf(addrs[3])).to.equal(500);
  });

  it("non admin cannot remove liquidity", async () => {
    await mpond.approve(bridge.address, 1000);
    await pond.approve(bridge.address, 1000);
    await bridge.addLiquidity(1000, 1000);

    await expect(bridge.connect(signers[1]).removeLiquidity(500, 500, addrs[3])).to.be.reverted;
  });

  it("can get mpond from pond", async () => {
    await mpond.approve(bridge.address, 100);
    await bridge.addLiquidity(100, 0);

    await pond.transfer(addrs[3], (await bridge.pondPerMpond()).mul(100));
    await pond.connect(signers[3]).approve(bridge.address, (await bridge.pondPerMpond()).mul(100));
    await bridge.connect(signers[3]).getMpond(100);
    expect(await mpond.balanceOf(addrs[3])).to.equal(100);
  });
});

async function skipTime(t: number) {
  await ethers.provider.send("evm_increaseTime", [t]);
  await skipBlocks(1);
}

async function skipBlocks(n: number) {
  await Promise.all([...Array(n)].map(async (x) => await ethers.provider.send("evm_mine", [])));
}
