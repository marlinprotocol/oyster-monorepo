import { ethers, upgrades, network } from "hardhat";
import { deployMockContract, MockContract } from "@ethereum-waffle/mock-contract";
import { expect } from "chai";
import { BigNumber as BN, Signer, Contract } from "ethers";
import { time } from "@nomicfoundation/hardhat-network-helpers";

import { testERC165 } from "../helpers/erc165";
import { testAdminRole, testRole } from "../helpers/rbac";
import { increaseBalance } from "../helpers/common";
import { Invoke__factory } from "../../typechain-types";


declare module "ethers" {
  interface BigNumber {
    e18(this: BigNumber): BigNumber;
  }
}
BN.prototype.e18 = function() {
  return this.mul(BN.from(10).pow(18));
};


let startTime = Math.floor(Date.now() / 1000) + 100000;

describe("ClusterSelector", function() {
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
    const ClusterSelector = await ethers.getContractFactory("ClusterSelector");
    let clusterSelector = await ClusterSelector.deploy(startTime, 900, addrs[2], 1000, 100);

    await expect(
      clusterSelector.initialize(
        addrs[0],
        addrs[11],
      )
    ).to.be.reverted;
  });

  it("deploys as proxy and initializes", async function() {
    const ClusterSelector = await ethers.getContractFactory("ClusterSelector");
    let clusterSelector = await upgrades.deployProxy(
      ClusterSelector,
      [
        addrs[0],
        addrs[11],
      ],
      {
        kind: "uups",
        constructorArgs: [startTime, 900, addrs[2], 1000, 100],
      },
    );

    expect(await clusterSelector.hasRole(await clusterSelector.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await clusterSelector.hasRole(await clusterSelector.REWARD_CONTROLLER_ROLE(), addrs[0])).to.be.true;
    expect(await clusterSelector.hasRole(await clusterSelector.UPDATER_ROLE(), addrs[11])).to.be.true;
    expect(await clusterSelector.REFUND_GAS_FOR_CLUSTER_SELECTION()).to.equal(100);
    expect(await clusterSelector.START_TIME()).to.equal(startTime);
    expect(await clusterSelector.EPOCH_LENGTH()).to.equal(900);
  });

  it("upgrades", async function() {
    const ClusterSelector = await ethers.getContractFactory("ClusterSelector");
    let clusterSelector = await upgrades.deployProxy(
      ClusterSelector,
      [
        addrs[0],
        addrs[11],
      ],
      {
        kind: "uups",
        constructorArgs: [startTime, 900, addrs[2], 1000, 100],
      },
    );
    await upgrades.upgradeProxy(clusterSelector.address, ClusterSelector, { kind: "uups", constructorArgs: [startTime, 900, addrs[2], 1000, 100] });

    expect(await clusterSelector.hasRole(await clusterSelector.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await clusterSelector.hasRole(await clusterSelector.REWARD_CONTROLLER_ROLE(), addrs[0])).to.be.true;
    expect(await clusterSelector.hasRole(await clusterSelector.UPDATER_ROLE(), addrs[11])).to.be.true;
    expect(await clusterSelector.REFUND_GAS_FOR_CLUSTER_SELECTION()).to.equal(100);
    expect(await clusterSelector.START_TIME()).to.equal(startTime);
    expect(await clusterSelector.EPOCH_LENGTH()).to.equal(900);
  });

  it("does not upgrade without admin", async () => {
    const ClusterSelector = await ethers.getContractFactory("ClusterSelector");
    let clusterSelector = await upgrades.deployProxy(
      ClusterSelector,
      [
        addrs[0],
        addrs[11],
      ],
      {
        kind: "uups",
        constructorArgs: [startTime, 900, addrs[2], 1000, 100],
      },
    );

    await expect(upgrades.upgradeProxy(clusterSelector.address, ClusterSelector.connect(signers[1]), { kind: "uups", constructorArgs: [startTime, 900, addrs[2], 1000, 100] })).to.be.reverted;
  });
});

testERC165("ClusterSelector", async function(_: Signer[], addrs: string[]) {
  const ClusterSelector = await ethers.getContractFactory("ClusterSelector");
  let clusterSelector = await upgrades.deployProxy(
    ClusterSelector,
    [
      addrs[0],
      addrs[11],
    ],
    {
      kind: "uups",
      constructorArgs: [startTime, 900, addrs[2], 1000, 100],
    },
  );
  return clusterSelector;
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

testAdminRole("ClusterSelector", async function(_: Signer[], addrs: string[]) {
  const ClusterSelector = await ethers.getContractFactory("ClusterSelector");
  let clusterSelector = await upgrades.deployProxy(
    ClusterSelector,
    [
      addrs[0],
      addrs[11],
    ],
    {
      kind: "uups",
      constructorArgs: [startTime, 900, addrs[2], 1000, 100],
    },
  );
  return clusterSelector;
});

testRole("ClusterSelector", async function(_: Signer[], addrs: string[]) {
  const ClusterSelector = await ethers.getContractFactory("ClusterSelector");
  let clusterSelector = await upgrades.deployProxy(
    ClusterSelector,
    [
      addrs[0],
      addrs[11],
    ],
    {
      kind: "uups",
      constructorArgs: [startTime, 900, addrs[2], 1000, 100],
    },
  );
  return clusterSelector;
}, "UPDATER_ROLE");

testRole("ClusterSelector", async function(_: Signer[], addrs: string[]) {
  const ClusterSelector = await ethers.getContractFactory("ClusterSelector");
  let clusterSelector = await upgrades.deployProxy(
    ClusterSelector,
    [
      addrs[0],
      addrs[11],
    ],
    {
      kind: "uups",
      constructorArgs: [startTime, 900, addrs[2], 1000, 100],
    },
  );
  return clusterSelector;
}, "REWARD_CONTROLLER_ROLE");

describe("ClusterSelector", function() {
  let signers: Signer[];
  let addrs: string[];
  let clusterSelector: Contract;
  let arbGasInfoMock: MockContract;

  let snapshot: any;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const ClusterSelector = await ethers.getContractFactory("ClusterSelector");
    arbGasInfoMock = await deployMockContract(signers[0], ["function getPricesInArbGas() view returns (uint, uint, uint)"]);
    await arbGasInfoMock.mock.getPricesInArbGas.returns(223148, 1593, 21000);
    clusterSelector = await upgrades.deployProxy(
      ClusterSelector,
      [
        addrs[1],
        addrs[11],
      ],
      {
        kind: "uups",
        constructorArgs: [startTime, 900, arbGasInfoMock.address, ethers.utils.parseEther("1"), 100],
      },
    );

    expect(await clusterSelector.hasRole(await clusterSelector.DEFAULT_ADMIN_ROLE(), addrs[1])).to.be.true;
    expect(await clusterSelector.hasRole(await clusterSelector.REWARD_CONTROLLER_ROLE(), addrs[1])).to.be.true;
    expect(await clusterSelector.hasRole(await clusterSelector.UPDATER_ROLE(), addrs[11])).to.be.true;
    expect(await clusterSelector.REFUND_GAS_FOR_CLUSTER_SELECTION()).to.equal(100);
    expect(await clusterSelector.START_TIME()).to.equal(startTime);
    expect(await clusterSelector.EPOCH_LENGTH()).to.equal(900);
    expect(await clusterSelector.nodesInTree()).to.equal(0);
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

  it("non updater cannot insert nodes", async () => {
    await expect(clusterSelector.insert_unchecked(addrs[31], 31)).to.be.reverted;
  });

  it("updater can insert nodes", async () => {
    await clusterSelector.connect(signers[11]).insert_unchecked(addrs[31], 31);

    expect(await clusterSelector.addressToIndexMap(addrs[31])).to.equal(1);
    expect(await clusterSelector.indexToAddressMap(1)).to.equal(addrs[31]);
    let nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(2)).to.be.reverted;

    await clusterSelector.connect(signers[11]).insert_unchecked(addrs[32], 32);

    expect(await clusterSelector.addressToIndexMap(addrs[32])).to.equal(2);
    expect(await clusterSelector.indexToAddressMap(2)).to.equal(addrs[32]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(32);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(3)).to.be.reverted;

    await clusterSelector.connect(signers[11]).insert_unchecked(addrs[33], 33);

    expect(await clusterSelector.addressToIndexMap(addrs[33])).to.equal(3);
    expect(await clusterSelector.indexToAddressMap(3)).to.equal(addrs[33]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(32);
    expect(await nodeData.rightSum).to.equal(33);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(4)).to.be.reverted;

    await clusterSelector.connect(signers[11]).insertMultiple_unchecked([addrs[34], addrs[35], addrs[36]], [34, 35, 36]);

    expect(await clusterSelector.addressToIndexMap(addrs[34])).to.equal(4);
    expect(await clusterSelector.indexToAddressMap(4)).to.equal(addrs[34]);
    expect(await clusterSelector.addressToIndexMap(addrs[35])).to.equal(5);
    expect(await clusterSelector.indexToAddressMap(5)).to.equal(addrs[35]);
    expect(await clusterSelector.addressToIndexMap(addrs[36])).to.equal(6);
    expect(await clusterSelector.indexToAddressMap(6)).to.equal(addrs[36]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(101);
    expect(await nodeData.rightSum).to.equal(69);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(7)).to.be.reverted;

    await clusterSelector.connect(signers[11]).insert_unchecked(addrs[37], 37);

    expect(await clusterSelector.addressToIndexMap(addrs[37])).to.equal(7);
    expect(await clusterSelector.indexToAddressMap(7)).to.equal(addrs[37]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(101);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;
  });

  it("non updater cannot update nodes", async () => {
    await clusterSelector.connect(signers[11]).insert_unchecked(addrs[31], 31);
    await expect(clusterSelector.update_unchecked(addrs[31], 41)).to.be.reverted;
  });

  it("updater can update nodes", async () => {
    await clusterSelector.connect(signers[11]).insert_unchecked(addrs[31], 31);

    expect(await clusterSelector.addressToIndexMap(addrs[31])).to.equal(1);
    expect(await clusterSelector.indexToAddressMap(1)).to.equal(addrs[31]);
    let nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(2)).to.be.reverted;

    await clusterSelector.connect(signers[11]).insert_unchecked(addrs[32], 32);

    expect(await clusterSelector.addressToIndexMap(addrs[32])).to.equal(2);
    expect(await clusterSelector.indexToAddressMap(2)).to.equal(addrs[32]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(32);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(3)).to.be.reverted;

    await clusterSelector.connect(signers[11]).insert_unchecked(addrs[33], 33);

    expect(await clusterSelector.addressToIndexMap(addrs[33])).to.equal(3);
    expect(await clusterSelector.indexToAddressMap(3)).to.equal(addrs[33]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(32);
    expect(await nodeData.rightSum).to.equal(33);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(4)).to.be.reverted;

    await clusterSelector.connect(signers[11]).insertMultiple_unchecked([addrs[34], addrs[35], addrs[36]], [34, 35, 36]);

    expect(await clusterSelector.addressToIndexMap(addrs[34])).to.equal(4);
    expect(await clusterSelector.indexToAddressMap(4)).to.equal(addrs[34]);
    expect(await clusterSelector.addressToIndexMap(addrs[35])).to.equal(5);
    expect(await clusterSelector.indexToAddressMap(5)).to.equal(addrs[35]);
    expect(await clusterSelector.addressToIndexMap(addrs[36])).to.equal(6);
    expect(await clusterSelector.indexToAddressMap(6)).to.equal(addrs[36]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(101);
    expect(await nodeData.rightSum).to.equal(69);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(7)).to.be.reverted;

    await clusterSelector.connect(signers[11]).insert_unchecked(addrs[37], 37);

    expect(await clusterSelector.addressToIndexMap(addrs[37])).to.equal(7);
    expect(await clusterSelector.indexToAddressMap(7)).to.equal(addrs[37]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(101);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).update_unchecked(addrs[31], 41);

    expect(await clusterSelector.addressToIndexMap(addrs[31])).to.equal(1);
    expect(await clusterSelector.indexToAddressMap(1)).to.equal(addrs[31]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(101);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).update_unchecked(addrs[32], 22);

    expect(await clusterSelector.addressToIndexMap(addrs[32])).to.equal(2);
    expect(await clusterSelector.indexToAddressMap(2)).to.equal(addrs[32]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).update_unchecked(addrs[33], 43);

    expect(await clusterSelector.addressToIndexMap(addrs[33])).to.equal(3);
    expect(await clusterSelector.indexToAddressMap(3)).to.equal(addrs[33]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(116);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(43);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsertMultiple([addrs[34], addrs[35], addrs[36]], [24, 45, 26]);

    expect(await clusterSelector.addressToIndexMap(addrs[34])).to.equal(4);
    expect(await clusterSelector.indexToAddressMap(4)).to.equal(addrs[34]);
    expect(await clusterSelector.addressToIndexMap(addrs[35])).to.equal(5);
    expect(await clusterSelector.indexToAddressMap(5)).to.equal(addrs[35]);
    expect(await clusterSelector.addressToIndexMap(addrs[36])).to.equal(6);
    expect(await clusterSelector.indexToAddressMap(6)).to.equal(addrs[36]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(24);
    expect(await nodeData.rightSum).to.equal(45);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(43);
    expect(await nodeData.leftSum).to.equal(26);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(24);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(45);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(26);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).update_unchecked(addrs[37], 47);

    expect(await clusterSelector.addressToIndexMap(addrs[37])).to.equal(7);
    expect(await clusterSelector.indexToAddressMap(7)).to.equal(addrs[37]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(116);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(24);
    expect(await nodeData.rightSum).to.equal(45);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(43);
    expect(await nodeData.leftSum).to.equal(26);
    expect(await nodeData.rightSum).to.equal(47);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(24);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(45);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(26);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(47);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;
  });

  it("non updater cannot upsert nodes", async () => {
    await expect(clusterSelector.upsert(addrs[31], 31)).to.be.reverted;
  });

  it("updater can upsert nodes", async () => {
    await clusterSelector.connect(signers[11]).upsert(addrs[31], 31);

    expect(await clusterSelector.addressToIndexMap(addrs[31])).to.equal(1);
    expect(await clusterSelector.indexToAddressMap(1)).to.equal(addrs[31]);
    let nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(2)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[32], 32);

    expect(await clusterSelector.addressToIndexMap(addrs[32])).to.equal(2);
    expect(await clusterSelector.indexToAddressMap(2)).to.equal(addrs[32]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(32);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(3)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[33], 33);

    expect(await clusterSelector.addressToIndexMap(addrs[33])).to.equal(3);
    expect(await clusterSelector.indexToAddressMap(3)).to.equal(addrs[33]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(32);
    expect(await nodeData.rightSum).to.equal(33);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(4)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsertMultiple([addrs[34], addrs[35], addrs[36]], [34, 35, 36]);

    expect(await clusterSelector.addressToIndexMap(addrs[34])).to.equal(4);
    expect(await clusterSelector.indexToAddressMap(4)).to.equal(addrs[34]);
    expect(await clusterSelector.addressToIndexMap(addrs[35])).to.equal(5);
    expect(await clusterSelector.indexToAddressMap(5)).to.equal(addrs[35]);
    expect(await clusterSelector.addressToIndexMap(addrs[36])).to.equal(6);
    expect(await clusterSelector.indexToAddressMap(6)).to.equal(addrs[36]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(101);
    expect(await nodeData.rightSum).to.equal(69);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(7)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[37], 37);

    expect(await clusterSelector.addressToIndexMap(addrs[37])).to.equal(7);
    expect(await clusterSelector.indexToAddressMap(7)).to.equal(addrs[37]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(101);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[31], 41);

    expect(await clusterSelector.addressToIndexMap(addrs[31])).to.equal(1);
    expect(await clusterSelector.indexToAddressMap(1)).to.equal(addrs[31]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(101);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[32], 22);

    expect(await clusterSelector.addressToIndexMap(addrs[32])).to.equal(2);
    expect(await clusterSelector.indexToAddressMap(2)).to.equal(addrs[32]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[33], 43);

    expect(await clusterSelector.addressToIndexMap(addrs[33])).to.equal(3);
    expect(await clusterSelector.indexToAddressMap(3)).to.equal(addrs[33]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(116);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(43);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsertMultiple([addrs[34], addrs[35], addrs[36]], [24, 45, 26]);

    expect(await clusterSelector.addressToIndexMap(addrs[34])).to.equal(4);
    expect(await clusterSelector.indexToAddressMap(4)).to.equal(addrs[34]);
    expect(await clusterSelector.addressToIndexMap(addrs[35])).to.equal(5);
    expect(await clusterSelector.indexToAddressMap(5)).to.equal(addrs[35]);
    expect(await clusterSelector.addressToIndexMap(addrs[36])).to.equal(6);
    expect(await clusterSelector.indexToAddressMap(6)).to.equal(addrs[36]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(24);
    expect(await nodeData.rightSum).to.equal(45);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(43);
    expect(await nodeData.leftSum).to.equal(26);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(24);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(45);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(26);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[37], 47);

    expect(await clusterSelector.addressToIndexMap(addrs[37])).to.equal(7);
    expect(await clusterSelector.indexToAddressMap(7)).to.equal(addrs[37]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(116);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(24);
    expect(await nodeData.rightSum).to.equal(45);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(43);
    expect(await nodeData.leftSum).to.equal(26);
    expect(await nodeData.rightSum).to.equal(47);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(24);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(45);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(26);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(47);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;
  });

  it("non updater cannot delete nodes", async () => {
    await clusterSelector.connect(signers[11]).upsert(addrs[31], 31);
    await expect(clusterSelector.delete_unchecked(addrs[31])).to.be.reverted;
  });

  it("updater can delete nodes", async () => {
    await clusterSelector.connect(signers[11]).upsert(addrs[31], 31);

    expect(await clusterSelector.addressToIndexMap(addrs[31])).to.equal(1);
    expect(await clusterSelector.indexToAddressMap(1)).to.equal(addrs[31]);
    let nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(2)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[32], 32);

    expect(await clusterSelector.addressToIndexMap(addrs[32])).to.equal(2);
    expect(await clusterSelector.indexToAddressMap(2)).to.equal(addrs[32]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(32);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(3)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[33], 33);

    expect(await clusterSelector.addressToIndexMap(addrs[33])).to.equal(3);
    expect(await clusterSelector.indexToAddressMap(3)).to.equal(addrs[33]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(32);
    expect(await nodeData.rightSum).to.equal(33);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(4)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsertMultiple([addrs[34], addrs[35], addrs[36]], [34, 35, 36]);

    expect(await clusterSelector.addressToIndexMap(addrs[34])).to.equal(4);
    expect(await clusterSelector.indexToAddressMap(4)).to.equal(addrs[34]);
    expect(await clusterSelector.addressToIndexMap(addrs[35])).to.equal(5);
    expect(await clusterSelector.indexToAddressMap(5)).to.equal(addrs[35]);
    expect(await clusterSelector.addressToIndexMap(addrs[36])).to.equal(6);
    expect(await clusterSelector.indexToAddressMap(6)).to.equal(addrs[36]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(101);
    expect(await nodeData.rightSum).to.equal(69);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(7)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[37], 37);

    expect(await clusterSelector.addressToIndexMap(addrs[37])).to.equal(7);
    expect(await clusterSelector.indexToAddressMap(7)).to.equal(addrs[37]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(31);
    expect(await nodeData.leftSum).to.equal(101);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[31], 41);

    expect(await clusterSelector.addressToIndexMap(addrs[31])).to.equal(1);
    expect(await clusterSelector.indexToAddressMap(1)).to.equal(addrs[31]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(101);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(32);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[32], 22);

    expect(await clusterSelector.addressToIndexMap(addrs[32])).to.equal(2);
    expect(await clusterSelector.indexToAddressMap(2)).to.equal(addrs[32]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(33);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[33], 43);

    expect(await clusterSelector.addressToIndexMap(addrs[33])).to.equal(3);
    expect(await clusterSelector.indexToAddressMap(3)).to.equal(addrs[33]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(116);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(34);
    expect(await nodeData.rightSum).to.equal(35);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(43);
    expect(await nodeData.leftSum).to.equal(36);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(34);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(35);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(36);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsertMultiple([addrs[34], addrs[35], addrs[36]], [24, 45, 26]);

    expect(await clusterSelector.addressToIndexMap(addrs[34])).to.equal(4);
    expect(await clusterSelector.indexToAddressMap(4)).to.equal(addrs[34]);
    expect(await clusterSelector.addressToIndexMap(addrs[35])).to.equal(5);
    expect(await clusterSelector.indexToAddressMap(5)).to.equal(addrs[35]);
    expect(await clusterSelector.addressToIndexMap(addrs[36])).to.equal(6);
    expect(await clusterSelector.indexToAddressMap(6)).to.equal(addrs[36]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(106);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(24);
    expect(await nodeData.rightSum).to.equal(45);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(43);
    expect(await nodeData.leftSum).to.equal(26);
    expect(await nodeData.rightSum).to.equal(37);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(24);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(45);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(26);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(37);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).upsert(addrs[37], 47);

    expect(await clusterSelector.addressToIndexMap(addrs[37])).to.equal(7);
    expect(await clusterSelector.indexToAddressMap(7)).to.equal(addrs[37]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(41);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(116);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(24);
    expect(await nodeData.rightSum).to.equal(45);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(43);
    expect(await nodeData.leftSum).to.equal(26);
    expect(await nodeData.rightSum).to.equal(47);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(24);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(45);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(26);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(7);
    expect(await nodeData.value).to.equal(47);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(8)).to.be.reverted;

    await clusterSelector.connect(signers[11]).deleteIfPresent(addrs[38]);
    await clusterSelector.connect(signers[11]).deleteIfPresent(addrs[31]);

    expect(await clusterSelector.addressToIndexMap(addrs[31])).to.equal(0);
    expect(await clusterSelector.indexToAddressMap(7)).to.equal(ethers.constants.AddressZero);
    expect(await clusterSelector.addressToIndexMap(addrs[37])).to.equal(1);
    expect(await clusterSelector.indexToAddressMap(1)).to.equal(addrs[37]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(47);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(69);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(24);
    expect(await nodeData.rightSum).to.equal(45);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(43);
    expect(await nodeData.leftSum).to.equal(26);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(24);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(45);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(6);
    expect(await nodeData.value).to.equal(26);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(7)).to.be.reverted;

    await clusterSelector.connect(signers[11]).delete_unchecked(addrs[33]);

    expect(await clusterSelector.addressToIndexMap(addrs[33])).to.equal(0);
    expect(await clusterSelector.indexToAddressMap(6)).to.equal(ethers.constants.AddressZero);
    expect(await clusterSelector.addressToIndexMap(addrs[36])).to.equal(3);
    expect(await clusterSelector.indexToAddressMap(3)).to.equal(addrs[36]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(47);
    expect(await nodeData.leftSum).to.equal(91);
    expect(await nodeData.rightSum).to.equal(26);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(22);
    expect(await nodeData.leftSum).to.equal(24);
    expect(await nodeData.rightSum).to.equal(45);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(26);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(24);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(5);
    expect(await nodeData.value).to.equal(45);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(6)).to.be.reverted;

    await clusterSelector.connect(signers[11]).delete_unchecked(addrs[32]);

    expect(await clusterSelector.addressToIndexMap(addrs[32])).to.equal(0);
    expect(await clusterSelector.indexToAddressMap(5)).to.equal(ethers.constants.AddressZero);
    expect(await clusterSelector.addressToIndexMap(addrs[35])).to.equal(2);
    expect(await clusterSelector.indexToAddressMap(2)).to.equal(addrs[35]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(47);
    expect(await nodeData.leftSum).to.equal(69);
    expect(await nodeData.rightSum).to.equal(26);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(45);
    expect(await nodeData.leftSum).to.equal(24);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(26);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(4);
    expect(await nodeData.value).to.equal(24);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(5)).to.be.reverted;

    await clusterSelector.connect(signers[11]).delete_unchecked(addrs[37]);

    expect(await clusterSelector.addressToIndexMap(addrs[37])).to.equal(0);
    expect(await clusterSelector.indexToAddressMap(4)).to.equal(ethers.constants.AddressZero);
    expect(await clusterSelector.addressToIndexMap(addrs[34])).to.equal(1);
    expect(await clusterSelector.indexToAddressMap(1)).to.equal(addrs[34]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(24);
    expect(await nodeData.leftSum).to.equal(45);
    expect(await nodeData.rightSum).to.equal(26);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(45);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(3);
    expect(await nodeData.value).to.equal(26);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(4)).to.be.reverted;

    await clusterSelector.connect(signers[11]).delete_unchecked(addrs[35]);

    expect(await clusterSelector.addressToIndexMap(addrs[35])).to.equal(0);
    expect(await clusterSelector.indexToAddressMap(3)).to.equal(ethers.constants.AddressZero);
    expect(await clusterSelector.addressToIndexMap(addrs[36])).to.equal(2);
    expect(await clusterSelector.indexToAddressMap(2)).to.equal(addrs[36]);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(24);
    expect(await nodeData.leftSum).to.equal(26);
    expect(await nodeData.rightSum).to.equal(0);
    nodeData = await clusterSelector.nodes(2);
    expect(await nodeData.value).to.equal(26);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(3)).to.be.reverted;

    await clusterSelector.connect(signers[11]).delete_unchecked(addrs[36]);

    expect(await clusterSelector.addressToIndexMap(addrs[36])).to.equal(0);
    expect(await clusterSelector.indexToAddressMap(2)).to.equal(ethers.constants.AddressZero);
    nodeData = await clusterSelector.nodes(1);
    expect(await nodeData.value).to.equal(24);
    expect(await nodeData.leftSum).to.equal(0);
    expect(await nodeData.rightSum).to.equal(0);
    await expect(clusterSelector.nodes(2)).to.be.reverted;

    await clusterSelector.connect(signers[11]).delete_unchecked(addrs[34]);

    expect(await clusterSelector.addressToIndexMap(addrs[34])).to.equal(0);
    expect(await clusterSelector.indexToAddressMap(1)).to.equal(ethers.constants.AddressZero);
    await expect(clusterSelector.nodes(1)).to.be.reverted;
  });

  it("current epoch", async () => {
    const epochLength = parseInt((await clusterSelector.EPOCH_LENGTH()).toString());
    // 0x11 mean Arithmetic underflow or overflow
    await expect(clusterSelector.getCurrentEpoch()).to.be.revertedWithPanic(0x11);
    await time.increaseTo(startTime);
    expect(await clusterSelector.getCurrentEpoch()).to.equal(1);
    await time.increase(epochLength - 1);
    expect(await clusterSelector.getCurrentEpoch()).to.equal(1);
    await time.increase(1);
    expect(await clusterSelector.getCurrentEpoch()).to.equal(2);
    await time.increase(1);
    expect(await clusterSelector.getCurrentEpoch()).to.equal(2);
    await time.increase(epochLength - 1 + epochLength * 5);
    expect(await clusterSelector.getCurrentEpoch()).to.equal(8);
    await time.increase(epochLength * 6 + epochLength / 2);
    expect(await clusterSelector.getCurrentEpoch()).to.equal(14);
    await time.increase(epochLength - epochLength / 2 - 2);
    expect(await clusterSelector.getCurrentEpoch()).to.equal(14);
  });

  it("Proxy admin can update refund gas to select clusters by upgrading", async () => {
    const ClusterSelector = await ethers.getContractFactory("ClusterSelector");
    await upgrades.upgradeProxy(clusterSelector.address, ClusterSelector.connect(signers[1]), { kind: "uups", constructorArgs: [startTime, 900, addrs[2], 1000, 6] });
    expect(await clusterSelector.REFUND_GAS_FOR_CLUSTER_SELECTION()).to.be.equal(6);
    await upgrades.upgradeProxy(clusterSelector.address, ClusterSelector.connect(signers[1]), { kind: "uups", constructorArgs: [startTime, 900, addrs[2], 1000, 0] });
    expect(await clusterSelector.REFUND_GAS_FOR_CLUSTER_SELECTION()).to.be.equal(0);
    await upgrades.upgradeProxy(clusterSelector.address, ClusterSelector.connect(signers[1]), { kind: "uups", constructorArgs: [startTime, 900, addrs[2], 1000, 5] });
    expect(await clusterSelector.REFUND_GAS_FOR_CLUSTER_SELECTION()).to.be.equal(5);
  });

  it("reward controller can flush any erc20 token", async () => {
    await expect(() => clusterSelector.connect(signers[1]).flushReward(addrs[7]))
      .to.changeEtherBalances([clusterSelector, signers[7]], [0, 0]);
    await increaseBalance(ethers, clusterSelector.address, BN.from(145));
    await expect(clusterSelector.connect(signers[11]).flushReward(addrs[7])).to.be.reverted;
    await expect(clusterSelector.connect(signers[0]).flushReward(addrs[7])).to.be.reverted;
    await expect(() => clusterSelector.connect(signers[1]).flushReward(addrs[7]))
      .to.changeEtherBalances([clusterSelector, signers[7]], [-145, 145]);
    await expect(() => clusterSelector.connect(signers[1]).flushReward(addrs[7]))
      .to.changeEtherBalances([clusterSelector, signers[7]], [0, 0]);

    await increaseBalance(ethers, clusterSelector.address, BN.from(245));
    await expect(() => clusterSelector.connect(signers[1]).flushReward(addrs[7]))
      .to.changeEtherBalances([clusterSelector, signers[7]], [-245, 245]);
    await increaseBalance(ethers, clusterSelector.address, BN.from(345));
    await expect(() => clusterSelector.connect(signers[1]).flushReward(addrs[7]))
      .to.changeEtherBalances([clusterSelector, signers[7]], [-345, 345]);
    await expect(() => clusterSelector.connect(signers[1]).flushReward(addrs[7]))
      .to.changeEtherBalances([clusterSelector, signers[7]], [0, 0]);
    await increaseBalance(ethers, clusterSelector.address, BN.from(445));
    await expect(() => clusterSelector.connect(signers[1]).flushReward(addrs[7]))
      .to.changeEtherBalances([clusterSelector, signers[7]], [-445, 445]);

    await increaseBalance(ethers, clusterSelector.address, BN.from(545));
    await increaseBalance(ethers, clusterSelector.address, BN.from(645));
    await clusterSelector.connect(signers[1]).grantRole(await clusterSelector.REWARD_CONTROLLER_ROLE(), addrs[3]);
    await expect(() => clusterSelector.connect(signers[3]).flushReward(addrs[7]))
      .to.changeEtherBalances([clusterSelector, signers[7]], [-1190, 1190]);

    await increaseBalance(ethers, clusterSelector.address, BN.from(745));
    await clusterSelector.connect(signers[1]).renounceRole(await clusterSelector.REWARD_CONTROLLER_ROLE(), addrs[1]);
    await expect(clusterSelector.connect(signers[1]).flushReward(addrs[7])).to.be.reverted;
    await expect(clusterSelector.connect(signers[11]).flushReward(addrs[7])).to.be.reverted;
    await expect(() => clusterSelector.connect(signers[3]).flushReward(addrs[7]))
      .to.changeEtherBalances([clusterSelector, signers[7]], [-745, 745]);

    await increaseBalance(ethers, clusterSelector.address, BN.from(845));
    await expect(() => clusterSelector.connect(signers[3]).flushReward(clusterSelector.address))
      .to.changeEtherBalances([clusterSelector, signers[7]], [0, 0]);
    // deployed pond which doesn't have receive as mock for receive ether is not yet implemented
    const Pond = await ethers.getContractFactory("Pond");
    const pond = await upgrades.deployProxy(Pond, ["POND", "Marlin POND"], { kind: "uups" });
    await expect(clusterSelector.connect(signers[3]).flushReward(pond.address)).to.be.revertedWith("CS:FR-Flushing reward failed");
  });

  it("select clusters", async () => {
    const BASE_L1_GAS = 223148;
    const GAS_PER_BYTE = 1593;
    const gasForSelection = await clusterSelector.REFUND_GAS_FOR_CLUSTER_SELECTION();
    const gasPrice = BN.from(1e10);
    const rewardForSelection = (gasForSelection.add(BASE_L1_GAS + GAS_PER_BYTE * 4)).mul(gasPrice);
    await increaseBalance(ethers, clusterSelector.address, rewardForSelection.mul(10000000));

    let selectedClusters: string[][] = [];
    let epochLength = (await clusterSelector.EPOCH_LENGTH()).toNumber();
    let clusters: string[] = [];

    await expect(clusterSelector.selectClusters({ gasPrice })).to.be.reverted;
    await time.increaseTo(startTime - 2);
    await expect(clusterSelector.selectClusters({ gasPrice })).to.be.reverted;
    await time.increaseTo(startTime);
    const epochPlusOne = (await clusterSelector.getCurrentEpoch()).add(1);
    expect(epochPlusOne).equals(2);
    await expect(clusterSelector.selectClusters({ gasPrice })).to.be.revertedWith("CS:SC-No cluster selected");
    await expect(clusterSelector.getClusters(epochPlusOne)).to.be.revertedWith("6");
    await expect(clusterSelector.getClusters(epochPlusOne.add(1))).to.be.revertedWith("6");

    await expect(clusterSelector.updateMissingClusters(2)).to.be.revertedWith("cannot update future epochs");
    await clusterSelector.updateMissingClusters(1);
    // 0x11 mean Arithmetic underflow or overflow
    await expect(clusterSelector.getClusters(1)).to.be.revertedWithPanic(0x11);

    await clusterSelector.connect(signers[11]).upsert(addrs[31], 1);
    expect(await clusterSelector.nodesInTree()).to.equal(1);
    clusters.push(addrs[31]);
    await expect(() => clusterSelector.selectClusters({ gasPrice }))
      .to.changeEtherBalances([clusterSelector, signers[0]], [-rewardForSelection, rewardForSelection]);
    selectedClusters[2] = await clusterSelector.getClusters(epochPlusOne);
    expect(selectedClusters[2][0]).equals(addrs[31]);
    await expect(clusterSelector.selectClusters({ gasPrice })).to.be.revertedWith("CS:SC-Already selected");
    await time.increaseTo(epochLength + startTime - 2);
    await expect(clusterSelector.selectClusters({ gasPrice })).to.be.revertedWith("CS:SC-Already selected");
    await time.increaseTo(epochLength + startTime);

    expect(await clusterSelector.getCurrentEpoch()).equals(2);

    await clusterSelector.connect(signers[11]).upsert(addrs[32], 2);
    expect(await clusterSelector.nodesInTree()).to.equal(2);
    clusters.push(addrs[32]);
    await expect(() => clusterSelector.selectClusters({ gasPrice }))
      .to.changeEtherBalances([clusterSelector, signers[0]], [-rewardForSelection, rewardForSelection]);
    selectedClusters[3] = await clusterSelector.getClusters(3);
    expect(selectedClusters[3].length).to.equal(2);
    expect(selectedClusters[3].every((cluster) => clusters.includes(cluster))).to.be.true;

    await expect(clusterSelector.selectClusters({ gasPrice })).to.be.reverted;

    await time.increaseTo(epochLength * 2 + startTime);
    expect(await clusterSelector.getCurrentEpoch()).equals(3);
    await expect(() => clusterSelector.selectClusters({ gasPrice }))
      .to.changeEtherBalances([clusterSelector, signers[0]], [-rewardForSelection, rewardForSelection]);
    selectedClusters[4] = await clusterSelector.getClusters(4);
    expect(selectedClusters[4].length).to.equal(2);
    expect(selectedClusters[3].every((cluster) => clusters.includes(cluster))).to.be.true;

    await clusterSelector.connect(signers[11]).delete_unchecked(addrs[31]);
    expect(await clusterSelector.nodesInTree()).to.equal(1);
    await expect(clusterSelector.selectClusters({ gasPrice })).to.be.revertedWith("CS:SC-Already selected");

    await time.increaseTo(epochLength * 3 + startTime + epochLength * 2 / 3);
    expect(await clusterSelector.getCurrentEpoch()).equals(4);
    await expect(() => clusterSelector.selectClusters({ gasPrice }))
      .to.changeEtherBalances([clusterSelector, signers[0]], [-rewardForSelection, rewardForSelection]);
    selectedClusters[5] = await clusterSelector.getClusters(5);
    expect(selectedClusters[5].length).to.equal(1);
    expect(selectedClusters[5][0].toLowerCase()).to.equal(addrs[32].toLowerCase());

    await clusterSelector.connect(signers[11]).delete_unchecked(addrs[32]);
    expect(await clusterSelector.nodesInTree()).to.equal(0);
    await time.increaseTo(epochLength * 4 + startTime + epochLength * 2 / 3);
    expect(await clusterSelector.getCurrentEpoch()).equals(5);
    await expect(clusterSelector.selectClusters({ gasPrice })).to.be.revertedWith("CS:SC-No cluster selected");
    await expect(clusterSelector.getClusters(6)).to.be.revertedWith("6");

    let addresses: string[] = [], balances = [];
    for (let i = 0; i < 50; i++) {
      addresses.push(addrs[33 + i]);
      balances.push((Math.random() * 10000).toFixed(0));
    }
    await clusterSelector.connect(signers[11]).upsertMultiple(addresses, balances);
    expect(await clusterSelector.nodesInTree()).to.equal(50);

    await time.increaseTo(epochLength * 8 + startTime + epochLength * 1 / 3);
    expect(await clusterSelector.getCurrentEpoch()).equals(9);

    selectedClusters[8] = await clusterSelector.getClusters(8);
    const epoch8GetCostInit = (await clusterSelector.estimateGas.getClusters(8)).toNumber();
    expect(selectedClusters[8]).to.eql(selectedClusters[5]);
    selectedClusters[7] = await clusterSelector.getClusters(7);
    const epoch7GetCostInit = (await clusterSelector.estimateGas.getClusters(7)).toNumber();
    expect(selectedClusters[7]).to.eql(selectedClusters[5]);
    selectedClusters[6] = await clusterSelector.getClusters(6);
    const epoch6GetCostInit = (await clusterSelector.estimateGas.getClusters(6)).toNumber();
    expect(selectedClusters[6]).to.eql(selectedClusters[5]);

    expect(epoch8GetCostInit).greaterThan(epoch7GetCostInit);
    expect(epoch7GetCostInit).greaterThan(epoch6GetCostInit);

    await expect(() => clusterSelector.selectClusters({ gasPrice }))
      .to.changeEtherBalances([clusterSelector, signers[0]], [-rewardForSelection, rewardForSelection]);
    selectedClusters[10] = await clusterSelector.getClusters(10);
    expect(selectedClusters[10].length).to.equal(5);
    expect(selectedClusters[10].every((cluster) => addresses.includes(cluster))).to.be.true;

    await clusterSelector.updateMissingClusters(7);
    expect(await clusterSelector.getClusters(7)).to.eql(selectedClusters[7]);
    const epoch7GetCost = (await clusterSelector.estimateGas.getClusters(7)).toNumber();
    expect(epoch7GetCost).to.be.lessThan(epoch7GetCostInit);
    const epoch8GetCost = (await clusterSelector.estimateGas.getClusters(8)).toNumber();
    expect(epoch8GetCost).to.be.lessThan(epoch8GetCostInit);
    expect((await clusterSelector.estimateGas.getClusters(6)).toNumber()).to.equal(epoch6GetCostInit);

    await expect(clusterSelector.updateMissingClusters(10)).to.be.revertedWith("cannot update future epochs");

    await time.increaseTo(epochLength * 9 + startTime + epochLength * 1 / 3);
    expect(await clusterSelector.getCurrentEpoch()).equals(10);
    await clusterSelector.updateMissingClusters(10);
    await expect(clusterSelector.updateMissingClusters(11)).to.be.revertedWith("cannot update future epochs");

    await time.increaseTo(epochLength * 10 + startTime + epochLength * 1 / 3);
    expect(await clusterSelector.getCurrentEpoch()).equals(11);
    const epoch11GetCostInit = (await clusterSelector.estimateGas.getClusters(11)).toNumber();
    await clusterSelector.updateMissingClusters(11);
    const epoch11GetCost = (await clusterSelector.estimateGas.getClusters(11)).toNumber();
    expect(epoch11GetCost).lessThan(epoch11GetCostInit);
    expect(await clusterSelector.getClusters(11)).to.eql(selectedClusters[10]);

    await time.increaseTo(epochLength * 11 + startTime + epochLength * 1 / 2);
    expect(await clusterSelector.getCurrentEpoch()).equals(12);
    await clusterSelector.connect(signers[1]).flushReward(addrs[7]);
    await increaseBalance(ethers, clusterSelector.address, rewardForSelection.div(2));

    await expect(() => clusterSelector.selectClusters({ gasPrice }))
      .to.changeEtherBalances([clusterSelector, signers[0]], [0, 0]);
    expect(await ethers.provider.getBalance(clusterSelector.address)).to.equal(rewardForSelection.div(2));

    await time.increaseTo(epochLength * 12 + startTime + epochLength * 1 / 2);
    expect(await clusterSelector.getCurrentEpoch()).equals(13);
    await increaseBalance(ethers, clusterSelector.address, rewardForSelection.mul(10000000));
    const ClusterSelector = await ethers.getContractFactory("ClusterSelector");
    await upgrades.upgradeProxy(clusterSelector.address, ClusterSelector.connect(signers[1]), { kind: "uups", constructorArgs: [startTime, 900, arbGasInfoMock.address, ethers.utils.parseEther("1"), 0] });
    const baseReward = (gasForSelection.add(BASE_L1_GAS + GAS_PER_BYTE * 4).sub(gasForSelection)).mul(gasPrice);
    await expect(() => clusterSelector.selectClusters({ gasPrice }))
      .to.changeEtherBalances([clusterSelector, signers[0]], [-baseReward, baseReward]);

    // Testing _dispense failure
    await time.increaseTo(epochLength * 13 + startTime + epochLength * 1 / 2);
    expect(await clusterSelector.getCurrentEpoch()).equals(14);
    await upgrades.upgradeProxy(clusterSelector.address, ClusterSelector.connect(signers[1]), { kind: "uups", constructorArgs: [startTime, 900, arbGasInfoMock.address, 10000, 10000] });
    const invoke = await new Invoke__factory(signers[0]).deploy()

    const balanceBefore = await signers[0].provider?.getBalance(invoke.address)
    await expect(invoke.selectClusters(clusterSelector.address)).to.emit(clusterSelector, "ClusterSelected")
    const balanceAfter = await signers[0].provider?.getBalance(invoke.address)
    expect(balanceAfter).eq(balanceBefore);
  });
  
});
