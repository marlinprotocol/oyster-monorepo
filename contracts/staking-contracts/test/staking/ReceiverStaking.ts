import { ethers, upgrades, network } from "hardhat";
import { expect } from "chai";
import { BigNumber as BN, Signer, Contract } from "ethers";
import { time } from "@nomicfoundation/hardhat-network-helpers";

import { testERC165 } from "../helpers/erc165";
import { testAdminRole } from "../helpers/rbac";


declare module "ethers" {
  interface BigNumber {
    e18(this: BigNumber): BigNumber;
  }
}
BN.prototype.e18 = function() {
  return this.mul(BN.from(10).pow(18));
};


let startTime = Math.floor(Date.now() / 1000) + 100000;

describe("ReceiverStaking", function() {
  let signers: Signer[];
  let addrs: string[];

  let snapshot: any;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
  });

  beforeEach(async function() {
    snapshot = await network.provider.request({
      method: "evm_snapshot",
      params: [],
    });
  });

  afterEach(async function() {
    await network.provider.request({
      method: "evm_revert",
      params: [snapshot],
    });
  });

  it("deploys with initialization disabled", async function() {
    const ReceiverStaking = await ethers.getContractFactory("ReceiverStaking");
    let receiverStaking = await ReceiverStaking.deploy(startTime, 3600, addrs[11]);

    await expect(
      receiverStaking.initialize(addrs[0], "Receiver POND", "rPOND")
    ).to.be.reverted;
  });

  it("deploys as proxy and initializes", async function() {
    const ReceiverStaking = await ethers.getContractFactory("ReceiverStaking");
    let receiverStaking = await upgrades.deployProxy(
      ReceiverStaking,
      [addrs[0], "Receiver POND", "rPOND"],
      {
        kind: "uups",
        constructorArgs: [startTime, 3600, addrs[11]],
      }
    );

    expect(await receiverStaking.name()).to.equal("Receiver POND");
    expect(await receiverStaking.symbol()).to.equal("rPOND");
    expect(await receiverStaking.totalSupply()).to.equal(0);
    expect(await receiverStaking.hasRole(await receiverStaking.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await receiverStaking.START_TIME()).to.equal(startTime);
    expect(await receiverStaking.EPOCH_LENGTH()).to.equal(3600);
    expect(await receiverStaking.STAKING_TOKEN()).to.equal(addrs[11]);
  });

  it("upgrades", async function() {
    const ReceiverStaking = await ethers.getContractFactory("ReceiverStaking");
    let receiverStaking = await upgrades.deployProxy(
      ReceiverStaking,
      [addrs[0], "Receiver POND", "rPOND"],
      {
        kind: "uups",
        constructorArgs: [startTime, 3600, addrs[11]],
      }
    );

    await upgrades.upgradeProxy(receiverStaking.address, ReceiverStaking, {
      kind: "uups",
      constructorArgs: [startTime, 3600, addrs[11]],
    });

    expect(await receiverStaking.name()).to.equal("Receiver POND");
    expect(await receiverStaking.symbol()).to.equal("rPOND");
    expect(await receiverStaking.totalSupply()).to.equal(0);
    expect(await receiverStaking.hasRole(await receiverStaking.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await receiverStaking.START_TIME()).to.equal(startTime);
    expect(await receiverStaking.EPOCH_LENGTH()).to.equal(3600);
    expect(await receiverStaking.STAKING_TOKEN()).to.equal(addrs[11]);
  });

  it("does not upgrade without admin", async () => {
    const ReceiverStaking = await ethers.getContractFactory("ReceiverStaking");
    let receiverStaking = await upgrades.deployProxy(
      ReceiverStaking,
      [addrs[0], "Receiver POND", "rPOND"],
      {
        kind: "uups",
        constructorArgs: [startTime, 3600, addrs[11]],
      }
    );

    await expect(upgrades.upgradeProxy(receiverStaking.address, ReceiverStaking.connect(signers[1]), {
      kind: "uups",
      constructorArgs: [startTime, 3600, addrs[11]],
    })).to.be.reverted;
  });
});

testERC165("ReceiverStaking", async function(_signers: Signer[], addrs: string[]) {
  const ReceiverStaking = await ethers.getContractFactory("ReceiverStaking");
  let receiverStaking = await upgrades.deployProxy(
    ReceiverStaking,
    [addrs[0], "Receiver POND", "rPOND"],
    {
      kind: "uups",
      constructorArgs: [startTime, 3600, addrs[11]],
    }
  );
  return receiverStaking;
}, {
  "IAccessControl": [
    "hasRole(bytes32,address)",
    "getRoleAdmin(bytes32)",
    "grantRole(bytes32,address)",
    "revokeRole(bytes32,address)",
    "renounceRole(bytes32,address)",
  ],
  "IAccessControlEnumerable": [
    "getRoleMember(bytes32,uint256)",
    "getRoleMemberCount(bytes32)"
  ],
});

testAdminRole("ReceiverStaking", async function(_signers: Signer[], addrs: string[]) {
  const ReceiverStaking = await ethers.getContractFactory("ReceiverStaking");
  let receiverStaking = await upgrades.deployProxy(
    ReceiverStaking,
    [addrs[0], "Receiver POND", "rPOND"],
    {
      kind: "uups",
      constructorArgs: [startTime, 3600, addrs[11]],
    }
  );
  return receiverStaking;
});

describe("ReceiverStaking", function() {
  let signers: Signer[];
  let addrs: string[];
  let pond: Contract;
  let receiverStaking: Contract;

  let snapshot: any;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });

    const ReceiverStaking = await ethers.getContractFactory("ReceiverStaking");
    receiverStaking = await upgrades.deployProxy(
      ReceiverStaking,
      [addrs[0], "Receiver POND", "rPOND"],
      {
        kind: "uups",
        constructorArgs: [startTime, 3600, pond.address],
      }
    );

    expect(await receiverStaking.name()).to.equal("Receiver POND");
    expect(await receiverStaking.symbol()).to.equal("rPOND");
    expect(await receiverStaking.totalSupply()).to.equal(0);
    expect(await receiverStaking.hasRole(await receiverStaking.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await receiverStaking.START_TIME()).to.equal(startTime);
    expect(await receiverStaking.EPOCH_LENGTH()).to.equal(3600);
    expect(await receiverStaking.STAKING_TOKEN()).to.equal(pond.address);
  });

  beforeEach(async function() {
    snapshot = await network.provider.request({
      method: "evm_snapshot",
      params: [],
    });
  });

  afterEach(async function() {
    await network.provider.request({
      method: "evm_revert",
      params: [snapshot],
    });
  });

  it("name is Receiver POND", async function() {
    expect(await receiverStaking.name()).to.equal("Receiver POND");
  });

  it("symbol is rPOND", async function() {
    expect(await receiverStaking.symbol()).to.equal("rPOND");
  });

  it("decimals is 18", async function() {
    expect(await receiverStaking.decimals()).to.equal(18);
  });

  it("total supply is 0", async function() {
    expect(await receiverStaking.totalSupply()).to.equal(0);
  });
});

describe("Receiver Staking signer functions", function() {
  let signers: Signer[];
  let addrs: string[];
  let pond: Contract;
  let receiverStaking: Contract;

  let snapshot: any;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });

    const ReceiverStaking = await ethers.getContractFactory("ReceiverStaking");
    receiverStaking = await upgrades.deployProxy(
      ReceiverStaking,
      [addrs[0], "Receiver POND", "rPOND"],
      {
        kind: "uups",
        constructorArgs: [startTime, 3600, pond.address],
      }
    );
  });

  beforeEach(async function() {
    snapshot = await network.provider.request({
      method: "evm_snapshot",
      params: [],
    });
  });

  afterEach(async function() {
    await network.provider.request({
      method: "evm_revert",
      params: [snapshot],
    });
  });

  it("user can set signer", async () => {
    const user1 = signers[1];
    const user1Addr = await user1.getAddress();
    const signerAddr1 = addrs[2];
    const user2 = signers[3];
    const user2Addr = await user2.getAddress();
    const signerAddr2 = addrs[4];

    await receiverStaking.connect(user1).setSigner(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(ethers.constants.AddressZero);
    await receiverStaking.connect(user1).setSigner(signerAddr1);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(signerAddr1);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(user1Addr);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(ethers.constants.AddressZero);
    await receiverStaking.connect(user2).setSigner(signerAddr2);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(signerAddr1);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(signerAddr2);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(user1Addr);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(user2Addr);
    await expect(receiverStaking.connect(user1).setSigner(signerAddr2)).to.be.revertedWith("signer has a staker");

    await receiverStaking.connect(user1).setSigner(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(signerAddr2);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(user2Addr);
    await receiverStaking.connect(user2).setSigner(signerAddr1);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(signerAddr1);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(user2Addr);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(ethers.constants.AddressZero);
    await receiverStaking.connect(user1).setSigner(signerAddr2);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(signerAddr2);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(signerAddr1);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(user2Addr);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(user1Addr);
  })

  it("user can deposit and set signer", async () => {
    const user1 = signers[10];
    const user1Addr = await user1.getAddress();
    const signerAddr1 = addrs[12];
    await pond.transfer(user1Addr, 100000);
    await pond.connect(user1).approve(receiverStaking.address, 100000);
    const user2 = signers[13];
    const user2Addr = await user2.getAddress();
    const signerAddr2 = addrs[14];
    await pond.transfer(user2Addr, 100000);
    await pond.connect(user2).approve(receiverStaking.address, 100000);

    await expect(() => receiverStaking.connect(user1).depositAndSetSigner(100, ethers.constants.AddressZero))
      .to.changeTokenBalances(pond, [user1, user2, receiverStaking], [-100, 0, 100]);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(ethers.constants.AddressZero);
    await expect(() => receiverStaking.connect(user1).depositAndSetSigner(100, signerAddr1))
      .to.changeTokenBalances(pond, [user1, user2, receiverStaking], [-100, 0, 100]);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(signerAddr1);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(user1Addr);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(ethers.constants.AddressZero);
    await expect(() => receiverStaking.connect(user2).depositAndSetSigner(200, signerAddr2))
      .to.changeTokenBalances(pond, [user1, user2, receiverStaking], [0, -200, 200]);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(signerAddr1);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(signerAddr2);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(user1Addr);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(user2Addr);
    await expect(receiverStaking.connect(user1).depositAndSetSigner(100, signerAddr2)).to.be.revertedWith("signer has a staker");

    await expect(() => receiverStaking.connect(user1).depositAndSetSigner(300, ethers.constants.AddressZero))
      .to.changeTokenBalances(pond, [user1, user2, receiverStaking], [-300, 0, 300]);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(signerAddr2);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(user2Addr);
    await expect(() => receiverStaking.connect(user2).depositAndSetSigner(500, signerAddr1))
      .to.changeTokenBalances(pond, [user1, user2, receiverStaking], [0, -500, 500]);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(signerAddr1);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(user2Addr);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(ethers.constants.AddressZero);
    await expect(() => receiverStaking.connect(user1).depositAndSetSigner(600, signerAddr2))
      .to.changeTokenBalances(pond, [user1, user2, receiverStaking], [-600, 0, 600]);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(signerAddr2);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(signerAddr1);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(user2Addr);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(user1Addr);
  })

  it("user can set signer without deposit", async () => {
    const user1 = signers[10];
    const user1Addr = await user1.getAddress();
    const signerAddr1 = addrs[12];
    await pond.transfer(user1Addr, 100000);
    await pond.connect(user1).approve(receiverStaking.address, 100000);
    const user2 = signers[13];
    const user2Addr = await user2.getAddress();
    const signerAddr2 = addrs[14];
    await pond.transfer(user2Addr, 100000);
    await pond.connect(user2).approve(receiverStaking.address, 100000);

    await expect(() => receiverStaking.connect(user1).depositAndSetSigner(0, ethers.constants.AddressZero))
      .to.changeTokenBalances(pond, [user1, user2, receiverStaking], [0, 0, 0]);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(ethers.constants.AddressZero);
    await expect(() => receiverStaking.connect(user1).depositAndSetSigner(0, signerAddr1))
      .to.changeTokenBalances(pond, [user1, user2, receiverStaking], [0, 0, 0]);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(signerAddr1);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(user1Addr);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(ethers.constants.AddressZero);
    await expect(() => receiverStaking.connect(user2).depositAndSetSigner(0, signerAddr2))
      .to.changeTokenBalances(pond, [user1, user2, receiverStaking], [0, 0, 0]);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(signerAddr1);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(signerAddr2);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(user1Addr);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(user2Addr);
    await expect(receiverStaking.connect(user1).depositAndSetSigner(0, signerAddr2)).to.be.revertedWith("signer has a staker");

    await expect(() => receiverStaking.connect(user1).depositAndSetSigner(0, ethers.constants.AddressZero))
      .to.changeTokenBalances(pond, [user1, user2, receiverStaking], [0, 0, 0]);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(signerAddr2);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(user2Addr);
    await expect(() => receiverStaking.connect(user2).depositAndSetSigner(0, signerAddr1))
      .to.changeTokenBalances(pond, [user1, user2, receiverStaking], [0, 0, 0]);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(signerAddr1);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(user2Addr);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(ethers.constants.AddressZero);
    await expect(() => receiverStaking.connect(user1).depositAndSetSigner(0, signerAddr2))
      .to.changeTokenBalances(pond, [user1, user2, receiverStaking], [0, 0, 0]);
    expect(await receiverStaking.signerToStaker(ethers.constants.AddressZero)).to.equal(ethers.constants.AddressZero);
    expect(await receiverStaking.stakerToSigner(user1Addr)).to.equal(signerAddr2);
    expect(await receiverStaking.stakerToSigner(user2Addr)).to.equal(signerAddr1);
    expect(await receiverStaking.signerToStaker(signerAddr1)).to.equal(user2Addr);
    expect(await receiverStaking.signerToStaker(signerAddr2)).to.equal(user1Addr);
  })
});

describe("ReceiverStaking", function() {
  let signers: Signer[];
  let addrs: string[];
  let pond: Contract;
  let receiverStaking: Contract;

  let snapshot: any;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });

    const ReceiverStaking = await ethers.getContractFactory("ReceiverStaking");
    receiverStaking = await upgrades.deployProxy(
      ReceiverStaking,
      [addrs[0], "Receiver POND", "rPOND"],
      {
        kind: "uups",
        constructorArgs: [startTime, 3600, pond.address],
      }
    );

    expect(await receiverStaking.name()).to.equal("Receiver POND");
    expect(await receiverStaking.symbol()).to.equal("rPOND");
    expect(await receiverStaking.totalSupply()).to.equal(0);
    expect(await receiverStaking.hasRole(await receiverStaking.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await receiverStaking.START_TIME()).to.equal(startTime);
    expect(await receiverStaking.EPOCH_LENGTH()).to.equal(3600);
    expect(await receiverStaking.STAKING_TOKEN()).to.equal(pond.address);
  });

  beforeEach(async function() {
    snapshot = await network.provider.request({
      method: "evm_snapshot",
      params: [],
    });
  });

  afterEach(async function() {
    await network.provider.request({
      method: "evm_revert",
      params: [snapshot],
    });
  });

  it("can deposit before start time", async function() {
    await pond.approve(receiverStaking.address, 1000);

    await receiverStaking.depositAndSetSigner(1000, addrs[6]);

    expect(await receiverStaking.balanceOf(addrs[0])).to.equal(1000);
    expect(await receiverStaking.totalSupply()).to.equal(1000);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(1000);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(10e9).e18().sub(1000));

    await pond.transfer(addrs[1], 2000);
    await pond.connect(signers[1]).approve(receiverStaking.address, 1500);

    await receiverStaking.connect(signers[1]).depositAndSetSigner(1500, addrs[7]);

    expect(await receiverStaking.balanceOf(addrs[1])).to.equal(1500);
    expect(await receiverStaking.totalSupply()).to.equal(2500);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(2500);
    expect(await pond.balanceOf(addrs[1])).to.equal(500);

    await time.increaseTo(startTime + 10);
    let stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    let epochInfo = await receiverStaking.getEpochInfo(1);
    let balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(1);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(1);
  });

  it("can deposit for others", async function() {
    const depositor = signers[0];
    const depositorAddr = await depositor.getAddress();
    const stakerAddr = addrs[2];
    await pond.connect(depositor).approve(receiverStaking.address, 1000);

    expect(await receiverStaking.balanceOf(depositorAddr)).to.equal(0);
    expect(await receiverStaking.balanceOf(stakerAddr)).to.equal(0);
    await receiverStaking.connect(depositor).depositFor(1000, stakerAddr);
    expect(await receiverStaking.balanceOf(depositorAddr)).to.equal(0);
    expect(await receiverStaking.balanceOf(stakerAddr)).to.equal(1000);
    expect(await receiverStaking.totalSupply()).to.equal(1000);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(1000);
    expect(await pond.balanceOf(depositorAddr)).to.equal(BN.from(10e9).e18().sub(1000));
  });

  it("can deposit after start time", async function() {
    await pond.approve(receiverStaking.address, 1000);

    await receiverStaking.depositAndSetSigner(1000, addrs[6]);

    expect(await receiverStaking.balanceOf(addrs[0])).to.equal(1000);
    expect(await receiverStaking.totalSupply()).to.equal(1000);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(1000);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(10e9).e18().sub(1000));

    await pond.transfer(addrs[1], 2000);
    await pond.connect(signers[1]).approve(receiverStaking.address, 2000);

    await time.increaseTo(startTime + 10);
    let stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    let epochInfo = await receiverStaking.getEpochInfo(1);
    let balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(1000);
    expect(stakeInfo._currentEpoch).to.equal(1);

    await receiverStaking.connect(signers[1]).depositAndSetSigner(1500, addrs[7]);

    expect(await receiverStaking.balanceOf(addrs[1])).to.equal(1500);
    expect(await receiverStaking.totalSupply()).to.equal(2500);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(2500);
    expect(await pond.balanceOf(addrs[1])).to.equal(500);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(0);
    expect(stakeInfo._totalStake).to.equal(1000);
    expect(stakeInfo._currentEpoch).to.equal(1);

    await time.increase(3600);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(2);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(2);

    await receiverStaking.connect(signers[1]).deposit(500);

    expect(await receiverStaking.balanceOf(addrs[1])).to.equal(2000);
    expect(await receiverStaking.totalSupply()).to.equal(3000);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(3000);
    expect(await pond.balanceOf(addrs[1])).to.equal(0);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(2);

    await time.increase(3600);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(3000);
    expect(stakeInfo._currentEpoch).to.equal(3);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(2000);
    expect(stakeInfo._totalStake).to.equal(3000);
    expect(stakeInfo._currentEpoch).to.equal(3);
  });

  it("cannot deposit more than approved amount", async function() {
    await pond.approve(receiverStaking.address, 1000);

    await expect(receiverStaking.deposit(1001)).to.be.reverted;
  });

  it("can withdraw before start time", async function() {
    await pond.approve(receiverStaking.address, 1000);
    await receiverStaking.depositAndSetSigner(1000, addrs[6]);

    expect(await receiverStaking.balanceOf(addrs[0])).to.equal(1000);
    expect(await receiverStaking.totalSupply()).to.equal(1000);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(1000);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(10e9).e18().sub(1000));

    await pond.transfer(addrs[1], 2000);
    await pond.connect(signers[1]).approve(receiverStaking.address, 1500);
    await receiverStaking.connect(signers[1]).depositAndSetSigner(1500, addrs[7]);

    expect(await receiverStaking.balanceOf(addrs[1])).to.equal(1500);
    expect(await receiverStaking.totalSupply()).to.equal(2500);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(2500);
    expect(await pond.balanceOf(addrs[1])).to.equal(500);

    await receiverStaking.withdraw(100);

    expect(await receiverStaking.balanceOf(addrs[0])).to.equal(900);
    expect(await receiverStaking.totalSupply()).to.equal(2400);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(2400);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(10e9).e18().sub(2900));

    await receiverStaking.connect(signers[1]).withdraw(200);

    expect(await receiverStaking.balanceOf(addrs[1])).to.equal(1300);
    expect(await receiverStaking.totalSupply()).to.equal(2200);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(2200);
    expect(await pond.balanceOf(addrs[1])).to.equal(700);

    await time.increaseTo(startTime + 10);
    let stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    let epochInfo = await receiverStaking.getEpochInfo(1);
    let balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(900);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(1);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1300);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(1);
  });

  it("can withdraw after start time", async function() {
    await pond.approve(receiverStaking.address, 1000);
    await receiverStaking.depositAndSetSigner(1000, addrs[6]);

    expect(await receiverStaking.balanceOf(addrs[0])).to.equal(1000);
    expect(await receiverStaking.totalSupply()).to.equal(1000);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(1000);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(10e9).e18().sub(1000));

    await pond.transfer(addrs[1], 2000);
    await pond.connect(signers[1]).approve(receiverStaking.address, 1500);
    await receiverStaking.connect(signers[1]).depositAndSetSigner(1500, addrs[7]);

    expect(await receiverStaking.balanceOf(addrs[1])).to.equal(1500);
    expect(await receiverStaking.totalSupply()).to.equal(2500);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(2500);
    expect(await pond.balanceOf(addrs[1])).to.equal(500);

    await time.increaseTo(startTime + 10);
    let stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    let epochInfo = await receiverStaking.getEpochInfo(1);
    let balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(1);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(1);

    await time.increase(3600);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(2);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(2);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(2);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(2);

    await receiverStaking.withdraw(100);

    expect(await receiverStaking.balanceOf(addrs[0])).to.equal(900);
    expect(await receiverStaking.totalSupply()).to.equal(2400);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(2400);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(10e9).e18().sub(2900));

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(2);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(2);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(900);
    expect(stakeInfo._totalStake).to.equal(2400);
    expect(stakeInfo._currentEpoch).to.equal(2);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2400);
    expect(stakeInfo._currentEpoch).to.equal(2);

    await receiverStaking.connect(signers[1]).withdraw(200);

    expect(await receiverStaking.balanceOf(addrs[1])).to.equal(1300);
    expect(await receiverStaking.totalSupply()).to.equal(2200);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(2200);
    expect(await pond.balanceOf(addrs[1])).to.equal(700);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(2);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(2);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(900);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(2);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1300);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(2);

    await time.increase(3600);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(3);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(3);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(900);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(3);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1300);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(3);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(900);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(3);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1300);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(3);

    await receiverStaking.withdraw(100);

    expect(await receiverStaking.balanceOf(addrs[0])).to.equal(800);
    expect(await receiverStaking.totalSupply()).to.equal(2100);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(2100);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(10e9).e18().sub(2800));

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(3);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(3);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(900);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(3);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1300);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(3);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(800);
    expect(stakeInfo._totalStake).to.equal(2100);
    expect(stakeInfo._currentEpoch).to.equal(3);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1300);
    expect(stakeInfo._totalStake).to.equal(2100);
    expect(stakeInfo._currentEpoch).to.equal(3);

    await receiverStaking.connect(signers[1]).withdraw(200);

    expect(await receiverStaking.balanceOf(addrs[1])).to.equal(1100);
    expect(await receiverStaking.totalSupply()).to.equal(1900);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(1900);
    expect(await pond.balanceOf(addrs[1])).to.equal(900);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(3);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(3);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(900);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(3);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1300);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(3);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(800);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(3);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1100);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(3);

    await time.increase(3600);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(4);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(4);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(900);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(4);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1300);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(4);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(800);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(4);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1100);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(4);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 4);
    epochInfo = await receiverStaking.getEpochInfo(4);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 4);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(800);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(4);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 4);
    epochInfo = await receiverStaking.getEpochInfo(4);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 4);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1100);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(4);

    await time.increase(3600);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(5);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(900);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1300);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(5);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(800);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1100);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 4);
    epochInfo = await receiverStaking.getEpochInfo(4);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 4);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(800);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 4);
    epochInfo = await receiverStaking.getEpochInfo(4);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 4);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1100);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 5);
    epochInfo = await receiverStaking.getEpochInfo(5);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 5);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(800);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 5);
    epochInfo = await receiverStaking.getEpochInfo(5);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 5);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1100);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);

    await receiverStaking.withdraw(100);

    expect(await receiverStaking.balanceOf(addrs[0])).to.equal(700);
    expect(await receiverStaking.totalSupply()).to.equal(1800);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(1800);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(10e9).e18().sub(2700));

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(5);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(900);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1300);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(5);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(800);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1100);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 4);
    epochInfo = await receiverStaking.getEpochInfo(4);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 4);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(800);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 4);
    epochInfo = await receiverStaking.getEpochInfo(4);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 4);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1100);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 5);
    epochInfo = await receiverStaking.getEpochInfo(5);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 5);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(700);
    expect(stakeInfo._totalStake).to.equal(1800);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 5);
    epochInfo = await receiverStaking.getEpochInfo(5);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 5);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1100);
    expect(stakeInfo._totalStake).to.equal(1800);
    expect(stakeInfo._currentEpoch).to.equal(5);

    await receiverStaking.connect(signers[1]).withdraw(200);

    expect(await receiverStaking.balanceOf(addrs[1])).to.equal(900);
    expect(await receiverStaking.totalSupply()).to.equal(1600);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(1600);
    expect(await pond.balanceOf(addrs[1])).to.equal(1100);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(1000);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 1);
    epochInfo = await receiverStaking.getEpochInfo(1);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 1);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1500);
    expect(stakeInfo._totalStake).to.equal(2500);
    expect(stakeInfo._currentEpoch).to.equal(5);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(900);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 2);
    epochInfo = await receiverStaking.getEpochInfo(2);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 2);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1300);
    expect(stakeInfo._totalStake).to.equal(2200);
    expect(stakeInfo._currentEpoch).to.equal(5);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(800);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 3);
    epochInfo = await receiverStaking.getEpochInfo(3);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 3);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1100);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 4);
    epochInfo = await receiverStaking.getEpochInfo(4);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 4);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(800);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 4);
    epochInfo = await receiverStaking.getEpochInfo(4);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 4);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(1100);
    expect(stakeInfo._totalStake).to.equal(1900);
    expect(stakeInfo._currentEpoch).to.equal(5);

    stakeInfo = await receiverStaking.getStakeInfo(addrs[0], 5);
    epochInfo = await receiverStaking.getEpochInfo(5);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[6], 5);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[0]);
    expect(stakeInfo._userStake).to.equal(700);
    expect(stakeInfo._totalStake).to.equal(1600);
    expect(stakeInfo._currentEpoch).to.equal(5);
    stakeInfo = await receiverStaking.getStakeInfo(addrs[1], 5);
    epochInfo = await receiverStaking.getEpochInfo(5);
    balanceOfSigner = await receiverStaking.balanceOfSignerAt(addrs[7], 5);
    expect(stakeInfo._totalStake).to.equal(epochInfo.totalStake);
    expect(stakeInfo._currentEpoch).to.equal(epochInfo.currentEpoch);
    expect(stakeInfo._userStake).to.equal(balanceOfSigner.balance);
    expect(balanceOfSigner.account).to.equal(addrs[1]);
    expect(stakeInfo._userStake).to.equal(900);
    expect(stakeInfo._totalStake).to.equal(1600);
    expect(stakeInfo._currentEpoch).to.equal(5);
  });

  it("cannot withdraw more than deposited amount", async function() {
    await pond.approve(receiverStaking.address, 1000);
    await receiverStaking.deposit(1000);

    expect(await receiverStaking.balanceOf(addrs[0])).to.equal(1000);
    expect(await receiverStaking.totalSupply()).to.equal(1000);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(1000);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(10e9).e18().sub(1000));

    await expect(receiverStaking.withdraw(1001)).to.be.reverted;
  });

  it("cannot transfer staking tokens", async function() {
    await pond.approve(receiverStaking.address, 1000);
    await receiverStaking.deposit(1000);

    expect(await receiverStaking.balanceOf(addrs[0])).to.equal(1000);
    expect(await receiverStaking.totalSupply()).to.equal(1000);
    expect(await pond.balanceOf(receiverStaking.address)).to.equal(1000);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(10e9).e18().sub(1000));

    await expect(receiverStaking.transfer(addrs[1], 100)).to.be.reverted;
  });
});

