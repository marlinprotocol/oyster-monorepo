import { ethers, upgrades } from "hardhat";
import { expect } from "chai";
import { BigNumber as BN, Signer, Contract } from "ethers";

import { testERC165 } from "../helpers/erc165";
import { testAdminRole, testRole } from "../helpers/rbac";

declare module "ethers" {
  interface BigNumber {
    e18(this: BigNumber): BigNumber;
  }
}
BN.prototype.e18 = function() {
  return this.mul(BN.from(10).pow(18));
};

describe("Pond", function() {
  let signers: Signer[];
  let addrs: string[];

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
  });

  it("deploys with initialization disabled", async function() {
    const Pond = await ethers.getContractFactory("Pond");
    let pond = await Pond.deploy();
    await expect(pond.initialize("Marlin POND", "POND")).to.be.reverted;
  });

  it("deploys as proxy and initializes", async function() {
    const Pond = await ethers.getContractFactory("Pond");
    const pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });

    expect(await pond.name()).to.equal("Marlin POND");
    expect(await pond.symbol()).to.equal("POND");
    expect(await pond.cap()).to.equal(BN.from(10000000000).e18());
    expect(await pond.hasRole(await pond.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
  });

  it("upgrades", async function() {
    const Pond = await ethers.getContractFactory("Pond");
    const pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
    await upgrades.upgradeProxy(pond.address, Pond);

    expect(await pond.name()).to.equal("Marlin POND");
    expect(await pond.symbol()).to.equal("POND");
    expect(await pond.cap()).to.equal(BN.from(10000000000).e18());
    expect(await pond.hasRole(await pond.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
  });

  it("does not upgrade without admin", async function() {
    const Pond = await ethers.getContractFactory("Pond");
    const pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
    await expect(upgrades.upgradeProxy(pond.address, Pond.connect(signers[1]), { kind: "uups" })).to.be.reverted;
  });
});

testERC165(
  "Pond",
  async function() {
    const Pond = await ethers.getContractFactory("Pond");
    let pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
    return pond;
  },
  {
    IAccessControl: [
      "hasRole(bytes32,address)",
      "getRoleAdmin(bytes32)",
      "grantRole(bytes32,address)",
      "revokeRole(bytes32,address)",
      "renounceRole(bytes32,address)",
    ],
    IAccessControlEnumerable: ["getRoleMember(bytes32,uint256)", "getRoleMemberCount(bytes32)"],
    IArbToken: ["bridgeMint(address,uint256)", "bridgeBurn(address,uint256)", "l1Address()"],
  }
);

testAdminRole("Pond", async function(_signers: Signer[], _addrs: string[]) {
  const Pond = await ethers.getContractFactory("Pond");
  let pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
  return pond;
});

describe("Pond", function() {
  let signers: Signer[];
  let addrs: string[];
  let pond: Contract;

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const Pond = await ethers.getContractFactory("Pond");
    pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
  });

  it("name is Marlin POND", async function() {
    expect(await pond.name()).to.equal("Marlin POND");
  });

  it("symbol is POND", async function() {
    expect(await pond.symbol()).to.equal("POND");
  });

  it("decimals is 18", async function() {
    expect(await pond.decimals()).to.equal(18);
  });

  it("total supply is 10e9", async function() {
    expect(await pond.totalSupply()).to.equal(BN.from(10e9).e18());
  });
});

describe("Pond", function() {
  let signers: Signer[];
  let addrs: string[];
  let pond: Contract;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const Pond = await ethers.getContractFactory("Pond");
    pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
  });

  it("approve", async function() {
    await pond.approve(addrs[1], 400);
    expect(await pond.allowance(addrs[0], addrs[1])).to.equal(400);
  });

  it("decrease allowance", async function() {
    await pond.decreaseAllowance(addrs[1], 100);
    expect(await pond.allowance(addrs[0], addrs[1])).to.equal(300);
  });

  it("increase allowance", async function() {
    await pond.increaseAllowance(addrs[1], 100);
    expect(await pond.allowance(addrs[0], addrs[1])).to.equal(400);
  });
});

describe("Pond", function() {
  let signers: Signer[];
  let addrs: string[];
  let pond: Contract;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const Pond = await ethers.getContractFactory("Pond");
    pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
  });

  it("transfer", async function() {
    await pond.transfer(addrs[1], 400);
    expect(await pond.balanceOf(addrs[1])).to.equal(400);
  });

  it("transferFrom (no allowance)", async function() {
    await expect(pond.connect(signers[1]).transferFrom(addrs[0], addrs[2], 100)).to.be.reverted;
  });

  it("transferFrom (with allowance)", async function() {
    await pond.increaseAllowance(addrs[1], 100);
    await pond.connect(signers[1]).transferFrom(addrs[0], addrs[2], 100);
    expect(await pond.balanceOf(addrs[2])).to.equal(100);
  });
});

testRole(
  "Pond",
  async function(_signers: Signer[], _addrs: string[]) {
    const Pond = await ethers.getContractFactory("Pond");
    let pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
    return pond;
  },
  "BRIDGE_ROLE"
);

describe("Pond", function() {
  let signers: Signer[];
  let addrs: string[];
  let pond: Contract;

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const Pond = await ethers.getContractFactory("Pond");
    pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
  });

  it("admin can set l1 address", async function() {
    await pond.setL1Address(addrs[1]);
    expect(await pond.l1Address()).to.equal(addrs[1]);
  });

  it("non admin cannot set l1 address", async function() {
    await expect(pond.connect(signers[1]).setL1Address(addrs[1])).to.be.reverted;
  });

  it("admin can withdraw", async function() {
    let balance = await pond.balanceOf(addrs[0]);
    await pond.transfer(pond.address, 1000);
    expect(await pond.balanceOf(pond.address)).to.equal(1000);
    expect(await pond.balanceOf(addrs[0])).to.equal(balance.sub(1000));

    await pond.withdraw(200);
    expect(await pond.balanceOf(pond.address)).to.equal(800);
    expect(await pond.balanceOf(addrs[0])).to.equal(balance.sub(800));
  });

  it("non admin cannot withdraw", async function() {
    await pond.transfer(pond.address, 1000);
    await expect(pond.connect(signers[1]).withdraw(200)).to.be.reverted;
  });
});

describe("Pond", function() {
  let signers: Signer[];
  let addrs: string[];
  let pond: Contract;

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const Pond = await ethers.getContractFactory("Pond");
    pond = await upgrades.deployProxy(Pond, ["Marlin POND", "POND"], { kind: "uups" });
    await pond.grantRole(await pond.BRIDGE_ROLE(), addrs[1]);
    await pond.transfer(pond.address, 1000);
  });

  it("non bridge cannot mint", async function() {
    await expect(pond.connect(signers[2]).bridgeMint(addrs[2], 100)).to.be.reverted;
  });

  it("bridge can mint up to its balance", async function() {
    expect(await pond.balanceOf(addrs[2])).to.equal(0);
    expect(await pond.balanceOf(addrs[3])).to.equal(0);
    expect(await pond.balanceOf(pond.address)).to.equal(1000);

    await pond.connect(signers[1]).bridgeMint(addrs[2], 100);

    expect(await pond.balanceOf(addrs[2])).to.equal(100);
    expect(await pond.balanceOf(addrs[3])).to.equal(0);
    expect(await pond.balanceOf(pond.address)).to.equal(900);

    await pond.connect(signers[1]).bridgeMint(addrs[3], 900);

    expect(await pond.balanceOf(addrs[2])).to.equal(100);
    expect(await pond.balanceOf(addrs[3])).to.equal(900);
    expect(await pond.balanceOf(pond.address)).to.equal(0);
  });

  it("bridge cannot mint beyond its balance", async function() {
    await expect(pond.connect(signers[1]).bridgeMint(addrs[2], 1001)).to.be.reverted;

    await pond.connect(signers[1]).bridgeMint(addrs[2], 100);

    await expect(pond.connect(signers[1]).bridgeMint(addrs[2], 901)).to.be.reverted;
  });

  it("non bridge cannot burn", async function() {
    await pond.transfer(addrs[2], 1000);
    await pond.transfer(addrs[3], 1000);
    await expect(pond.connect(signers[2]).bridgeBurn(addrs[2], 100)).to.be.reverted;
  });

  it("bridge can burn up to users balance", async function() {
    await pond.transfer(addrs[2], 1000);
    await pond.transfer(addrs[3], 1000);
    expect(await pond.balanceOf(addrs[2])).to.equal(1000);
    expect(await pond.balanceOf(addrs[3])).to.equal(1000);
    expect(await pond.balanceOf(pond.address)).to.equal(1000);

    await pond.connect(signers[1]).bridgeBurn(addrs[2], 100);
    await pond.connect(signers[1]).bridgeBurn(addrs[3], 600);

    expect(await pond.balanceOf(addrs[2])).to.equal(900);
    expect(await pond.balanceOf(addrs[3])).to.equal(400);
    expect(await pond.balanceOf(pond.address)).to.equal(1700);

    await pond.connect(signers[1]).bridgeBurn(addrs[2], 900);
    await pond.connect(signers[1]).bridgeBurn(addrs[3], 400);

    expect(await pond.balanceOf(addrs[2])).to.equal(0);
    expect(await pond.balanceOf(addrs[3])).to.equal(0);
    expect(await pond.balanceOf(pond.address)).to.equal(3000);
  });

  it("bridge cannot burn beyond users balance", async function() {
    await pond.transfer(addrs[2], 1000);
    await expect(pond.connect(signers[1]).bridgeBurn(addrs[2], 1001)).to.be.reverted;

    await pond.connect(signers[1]).bridgeBurn(addrs[2], 100);

    await expect(pond.connect(signers[1]).bridgeBurn(addrs[2], 901)).to.be.reverted;
  });
});
