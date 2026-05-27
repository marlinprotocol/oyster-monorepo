import { ethers, upgrades, network } from "hardhat";
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

describe("MPond", function() {
  let signers: Signer[];
  let addrs: string[];

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
  });

  it("deploys with initialization disabled", async function() {
    const MPond = await ethers.getContractFactory("MPond");
    let mpond = await MPond.deploy();

    await expect(mpond.initialize()).to.be.reverted;
  });

  it("deploys as proxy and initializes", async function() {
    const MPond = await ethers.getContractFactory("MPond");
    const mpond = await upgrades.deployProxy(MPond, { kind: "uups" });

    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.hasRole(await mpond.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
  });

  it("upgrades", async function() {
    const MPond = await ethers.getContractFactory("MPond");
    const mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await upgrades.upgradeProxy(mpond.address, MPond, { kind: "uups" });

    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.hasRole(await mpond.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
  });

  it("does not upgrade without admin", async function() {
    const MPond = await ethers.getContractFactory("MPond");
    const mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await expect(upgrades.upgradeProxy(mpond.address, MPond.connect(signers[1]), { kind: "uups" })).to.be.reverted;
  });
});

testERC165(
  "MPond",
  async function() {
    const MPond = await ethers.getContractFactory("MPond");
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    return mpond;
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

testAdminRole("MPond", async function(_signers: Signer[], _addrs: string[]) {
  const MPond = await ethers.getContractFactory("MPond");
  let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
  return mpond;
});

testRole(
  "MPond",
  async function(_signers: Signer[], _addrs: string[]) {
    const MPond = await ethers.getContractFactory("MPond");
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    return mpond;
  },
  "WHITELIST_ROLE"
);

describe("MPond", function() {
  let signers: Signer[];
  let addrs: string[];
  let mpond: Contract;
  let WHITELIST_ROLE: string;

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const MPond = await ethers.getContractFactory("MPond");
    mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    WHITELIST_ROLE = await mpond.WHITELIST_ROLE();
  });

  it("transfer should be whitelisted if addr1 is whitelisted", async function() {
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    expect(await mpond.hasRole(WHITELIST_ROLE, addrs[1])).to.be.true;

    expect(await mpond.isWhitelistedTransfer(addrs[1], addrs[2])).to.be.true;
  });

  it("transfer should be whitelisted if addr2 is whitelisted", async function() {
    await mpond.grantRole(WHITELIST_ROLE, addrs[2]);
    expect(await mpond.hasRole(WHITELIST_ROLE, addrs[2])).to.be.true;

    expect(await mpond.isWhitelistedTransfer(addrs[1], addrs[2])).to.be.true;
  });

  it("transfer should be whitelisted if both addr1 and addr2 are whitelisted", async function() {
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.grantRole(WHITELIST_ROLE, addrs[2]);
    expect(await mpond.hasRole(WHITELIST_ROLE, addrs[1])).to.be.true;
    expect(await mpond.hasRole(WHITELIST_ROLE, addrs[2])).to.be.true;

    expect(await mpond.isWhitelistedTransfer(addrs[1], addrs[2])).to.be.true;
  });

  it("transfer should not be whitelisted if neither addr1 nor addr2 are whitelisted", async function() {
    expect(await mpond.isWhitelistedTransfer(addrs[1], addrs[2])).to.be.false;
  });
});

describe("MPond", function() {
  let signers: Signer[];
  let addrs: string[];
  let mpond: Contract;

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const MPond = await ethers.getContractFactory("MPond");
    mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
  });

  it("name is Marlin MPond", async function() {
    expect(await mpond.name()).to.equal("Marlin MPond");
  });

  it("symbol is MPond", async function() {
    expect(await mpond.symbol()).to.equal("MPond");
  });

  it("decimals is 18", async function() {
    expect(await mpond.decimals()).to.equal(18);
  });

  it("total supply is 10000", async function() {
    expect(await mpond.totalSupply()).to.equal(BN.from(10000).e18());
  });
});

describe("MPond", function() {
  let signers: Signer[];
  let addrs: string[];
  let mpond: Contract;

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const MPond = await ethers.getContractFactory("MPond");
    mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
  });

  it("can grant small finite transfer allowance", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await mpond.connect(signers[1]).approve(addrs[2], 1234);

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(1234);
  });

  it("can grant large finite transfer allowance up to 2^96 - 1", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await mpond.connect(signers[1]).approve(addrs[2], BN.from(2).pow(96).sub(1));

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(BN.from(2).pow(96).sub(1));
  });

  it("can grant infinite transfer allowance", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await mpond.connect(signers[1]).approve(addrs[2], BN.from(2).pow(256).sub(1));

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(BN.from(2).pow(96).sub(1));
  });

  it("cannot grant finite transfer allowance over 2^96 - 1", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await expect(mpond.connect(signers[1]).approve(addrs[2], BN.from(2).pow(96).sub(0))).to.be.reverted;
    await expect(mpond.connect(signers[1]).approve(addrs[2], BN.from(2).pow(256).sub(2))).to.be.reverted;
  });

  it("can increase by small finite transfer allowance", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await mpond.connect(signers[1]).approve(addrs[2], 1234);

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(1234);
    await mpond.connect(signers[1]).increaseAllowance(addrs[2], 5678);

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(6912);
  });

  it("can increase by large finite transfer allowance up to 2^96 - 1", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await mpond.connect(signers[1]).approve(addrs[2], 1234);

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(1234);
    await mpond.connect(signers[1]).increaseAllowance(addrs[2], BN.from(2).pow(96).sub(1).sub(1234));

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(BN.from(2).pow(96).sub(1));
  });

  it("can increase by infinite transfer allowance from zero", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await mpond.connect(signers[1]).increaseAllowance(addrs[2], BN.from(2).pow(256).sub(1));

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(BN.from(2).pow(96).sub(1));
  });

  it("cannot increase by infinite transfer allowance from non-zero", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await mpond.connect(signers[1]).increaseAllowance(addrs[2], 1);

    await expect(mpond.connect(signers[1]).increaseAllowance(addrs[2], BN.from(2).pow(256).sub(1))).to.be.reverted;
  });

  it("cannot increase finite transfer allowance over 2^96 - 1", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await expect(mpond.connect(signers[1]).increaseAllowance(addrs[2], BN.from(2).pow(96).sub(0))).to.be.reverted;
    await expect(mpond.connect(signers[1]).increaseAllowance(addrs[2], BN.from(2).pow(256).sub(2))).to.be.reverted;
  });

  it("can decrease by small finite transfer allowance", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await mpond.connect(signers[1]).approve(addrs[2], 5678);

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(5678);
    await mpond.connect(signers[1]).decreaseAllowance(addrs[2], 1234);

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(4444);
  });

  it("can decrease by large finite transfer allowance up to 2^96 - 1", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await mpond.connect(signers[1]).approve(addrs[2], BN.from(2).pow(96).sub(1));

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(BN.from(2).pow(96).sub(1));
    await mpond.connect(signers[1]).decreaseAllowance(addrs[2], BN.from(2).pow(96).sub(1).sub(1234));

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(1234);
  });

  it("can decrease by infinite transfer allowance from infinite", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await mpond.connect(signers[1]).approve(addrs[2], BN.from(2).pow(96).sub(1));

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(BN.from(2).pow(96).sub(1));
    await mpond.connect(signers[1]).decreaseAllowance(addrs[2], BN.from(2).pow(256).sub(1));

    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
  });

  it("cannot decrease by infinite transfer allowance from finite", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await mpond.connect(signers[1]).approve(addrs[2], BN.from(2).pow(96).sub(2));

    await expect(mpond.connect(signers[1]).decreaseAllowance(addrs[2], BN.from(2).pow(256).sub(1))).to.be.reverted;
  });

  it("cannot decrease finite transfer allowance over 2^96 - 1", async function() {
    expect(await mpond.allowance(addrs[1], addrs[2])).to.equal(0);
    await mpond.connect(signers[1]).approve(addrs[2], BN.from(2).pow(96).sub(1));

    await expect(mpond.connect(signers[1]).decreaseAllowance(addrs[2], BN.from(2).pow(96).sub(0))).to.be.reverted;
    await expect(mpond.connect(signers[1]).decreaseAllowance(addrs[2], BN.from(2).pow(256).sub(2))).to.be.reverted;
  });
});

describe("MPond", function() {
  let signers: Signer[];
  let addrs: string[];
  let mpond: Contract;
  let WHITELIST_ROLE: string;

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const MPond = await ethers.getContractFactory("MPond");
    mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    WHITELIST_ROLE = await mpond.WHITELIST_ROLE();
  });

  it("transfer should happen if addr0 is whitelisted", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.transfer(addrs[1], 1234);

    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.balanceOf(addrs[1])).to.equal(1234);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(1234);
  });

  it("transfer should happen if addr1 is whitelisted", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.transfer(addrs[1], 1234);

    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.balanceOf(addrs[1])).to.equal(1234);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(1234);
  });

  it("transfer should happen if addr0 and addr1 are whitelisted", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.transfer(addrs[1], 1234);

    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.balanceOf(addrs[1])).to.equal(1234);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(1234);
  });

  it("transfer should fail if neither addr0 nor addr1 are whitelisted", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await expect(mpond.transfer(addrs[1], 1234)).to.be.reverted;
  });

  it("transfer should fail when not enough token balance", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await expect(mpond.connect(signers[1]).transfer(addrs[0], 1234)).to.be.reverted;
  });

  it("transfer should fail when not enough undelegated balance", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.delegate(addrs[1], BN.from(10000).e18().sub(1233));
    await expect(mpond.transfer(addrs[1], 1234)).to.be.reverted;
  });

  it("transfer should happen if amount is balance", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.transfer(addrs[1], BN.from(10000).e18());

    expect(await mpond.balanceOf(addrs[0])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(0);
    expect(await mpond.balanceOf(addrs[1])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(BN.from(10000).e18());
  });

  it("transfer to zero address should fail", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await expect(mpond.transfer(ethers.constants.AddressZero, BN.from(10000).e18())).to.be.reverted;
  });

  it("transferFrom should happen if addr0 is whitelisted", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.approve(addrs[2], 1234);
    await mpond.connect(signers[2]).transferFrom(addrs[0], addrs[1], 1234);

    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.balanceOf(addrs[1])).to.equal(1234);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(1234);
  });

  it("transferFrom should happen if addr1 is whitelisted", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.approve(addrs[2], 1234);
    await mpond.connect(signers[2]).transferFrom(addrs[0], addrs[1], 1234);

    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.balanceOf(addrs[1])).to.equal(1234);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(1234);
  });

  it("transferFrom should happen if addr0 and addr1 are whitelisted", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.approve(addrs[2], 1234);
    await mpond.connect(signers[2]).transferFrom(addrs[0], addrs[1], 1234);

    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.balanceOf(addrs[1])).to.equal(1234);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(1234);
  });

  it("transferFrom should fail if neither addr0 nor addr1 are whitelisted", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.approve(addrs[2], 1234);
    await expect(mpond.connect(signers[2]).transferFrom(addrs[0], addrs[1], 1234)).to.be.reverted;
  });

  it("transferFrom should fail when not enough allowance", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.approve(addrs[2], 1233);
    await expect(mpond.connect(signers[2]).transferFrom(addrs[0], addrs[1], 1234)).to.be.reverted;
  });

  it("transferFrom should fail when not enough token balance", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.transfer(addrs[1], BN.from(10000).e18().sub(1233));
    await mpond.approve(addrs[2], 1234);
    await expect(mpond.connect(signers[2]).transferFrom(addrs[0], addrs[1], 1234)).to.be.reverted;
  });

  it("transferFrom should fail when not enough undelegated balance", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.delegate(addrs[1], BN.from(10000).e18().sub(1233));
    await mpond.approve(addrs[2], 1234);
    await expect(mpond.connect(signers[2]).transferFrom(addrs[0], addrs[1], 1234)).to.be.reverted;
  });

  it("transferFrom should happen if amount is balance", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.approve(addrs[2], BN.from(10000).e18());
    await mpond.connect(signers[2]).transferFrom(addrs[0], addrs[1], BN.from(10000).e18());

    expect(await mpond.balanceOf(addrs[0])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(0);
    expect(await mpond.balanceOf(addrs[1])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(BN.from(10000).e18());
  });

  it("transferFrom should reduce unmaxed allowance", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.approve(addrs[2], BN.from(1000).e18());

    expect(await mpond.allowance(addrs[0], addrs[2])).to.equal(BN.from(1000).e18());

    await mpond.connect(signers[2]).transferFrom(addrs[0], addrs[1], BN.from(100).e18());

    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(9900).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(9900).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(BN.from(100).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(BN.from(100).e18());
    expect(await mpond.allowance(addrs[0], addrs[2])).to.equal(BN.from(900).e18());
  });

  it("transferFrom should not reduce maxed allowance", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(0);
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(0);

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, addrs[1]);
    await mpond.approve(addrs[2], BN.from(2).pow(96).sub(1));

    expect(await mpond.allowance(addrs[0], addrs[2])).to.equal(BN.from(2).pow(96).sub(1));

    await mpond.connect(signers[2]).transferFrom(addrs[0], addrs[1], BN.from(100).e18());

    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(9900).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(9900).e18());
    expect(await mpond.balanceOf(addrs[1])).to.equal(BN.from(100).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[1])).to.equal(BN.from(100).e18());
    expect(await mpond.allowance(addrs[0], addrs[2])).to.equal(BN.from(2).pow(96).sub(1));
  });

  it("transferFrom to zero address should fail", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, ethers.constants.AddressZero);
    await mpond.approve(addrs[2], BN.from(10000).e18());
    await expect(mpond.connect(signers[2]).transferFrom(addrs[0], ethers.constants.AddressZero, 0)).to.be.reverted;
  });

  it("transferFrom from zero address should fail", async function() {
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(10000).e18());
    expect(await mpond.undelegatedBalanceOf(addrs[0])).to.equal(BN.from(10000).e18());

    await mpond.grantRole(WHITELIST_ROLE, addrs[0]);
    await mpond.grantRole(WHITELIST_ROLE, ethers.constants.AddressZero);
    await mpond.approve(addrs[2], BN.from(10000).e18());
    await expect(mpond.connect(signers[2]).transferFrom(ethers.constants.AddressZero, addrs[0], 0)).to.be.reverted;
  });
});

describe("MPond", function() {
  let signers: Signer[];
  let addrs: string[];
  let mpond: Contract;

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const MPond = await ethers.getContractFactory("MPond");
    mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
  });

  it("can get delegation for zero address", async function() {
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
  });

  it("can get delegation for non zero address", async function() {
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
  });

  it("can delegate less than undelegated balance", async function() {
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(0);
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
  });

  it("can delegate equal to undelegated balance", async function() {
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(0);
    await mpond.delegate(addrs[1], BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(0);
  });

  it("cannot delegate more than undelegated balance", async function() {
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(0);
    await mpond.delegate(addrs[1], 1);
    await expect(mpond.delegate(addrs[2], BN.from(10000).e18())).to.be.reverted;
  });

  it("cannot delegate to zero address", async function() {
    await expect(mpond.delegate(ethers.constants.AddressZero, 1234)).to.be.reverted;
  });

  it("can delegate multiple times in same block", async function() {
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(0);
    await network.provider.send("evm_setAutomine", [false]);
    await mpond.delegate(addrs[1], 1000);
    await mpond.delegate(addrs[1], 234);
    await network.provider.send("evm_mine", []);
    await network.provider.send("evm_setAutomine", [true]);
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
  });

  it("cannot delegate if block number is too high", async function() {
    let snapshot = await network.provider.send("evm_snapshot", []);
    await network.provider.send("hardhat_mine", ["0x100000000"]); // 2^32
    await expect(mpond.delegate(addrs[1], 1234)).to.be.reverted;
    await network.provider.send("evm_revert", [snapshot]);
  });

  it("can undelegate less than delegated balance", async function() {
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    await mpond.undelegate(addrs[1], 1000);
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(234));
  });

  it("can undelegate equal to delegated balance", async function() {
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    await mpond.undelegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(0);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
  });

  it("cannot undelegate more than delegated balance", async function() {
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    await mpond.undelegate(addrs[1], 1);
    await expect(mpond.undelegate(addrs[1], 1234)).to.be.reverted;
  });

  it("cannot undelegate from zero address", async function() {
    await expect(mpond.undelegate(ethers.constants.AddressZero, 1234)).to.be.reverted;
  });

  it("can delegate by sig less than undelegated balance", async function() {
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(0);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Delegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: addrs[1],
          nonce: 0,
          expiry: ts + 1,
          amount: 1234,
        }
      )
    );
    await mpond.delegateBySig(addrs[1], 0, ts + 1, sig.v, sig.r, sig.s, 1234);
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
  });

  it("can delegate by sig equal to undelegated balance", async function() {
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(0);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Delegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: addrs[1],
          nonce: 0,
          expiry: ts + 1,
          amount: BN.from(10000).e18(),
        }
      )
    );
    await mpond.delegateBySig(addrs[1], 0, ts + 1, sig.v, sig.r, sig.s, BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(0);
  });

  it("cannot delegate by sig more than undelegated balance", async function() {
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(0);
    await mpond.delegate(addrs[1], 1);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Delegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: addrs[2],
          nonce: 0,
          expiry: ts + 1,
          amount: BN.from(10000).e18(),
        }
      )
    );
    await expect(mpond.delegateBySig(addrs[2], 0, ts + 1, sig.v, sig.r, sig.s, BN.from(10000).e18())).to.be.reverted;
  });

  it("cannot delegate by sig to zero address", async function() {
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Delegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: ethers.constants.AddressZero,
          nonce: 0,
          expiry: ts + 1,
          amount: BN.from(10000).e18(),
        }
      )
    );
    await expect(mpond.delegateBySig(ethers.constants.AddressZero, 0, ts + 1, sig.v, sig.r, sig.s, BN.from(10000).e18())).to.be.reverted;
  });

  it("cannot delegate by sig with incorrect signature", async function() {
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(0);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Delegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: addrs[1],
          nonce: 0,
          expiry: ts + 1,
          amount: 1234,
        }
      )
    );
    await expect(mpond.delegateBySig(addrs[1], 0, ts + 1, sig.v + 5, sig.r, sig.s, 1234)).to.be.reverted;
  });

  it("cannot delegate by sig with incorrect nonce", async function() {
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(0);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Delegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: addrs[1],
          nonce: 1,
          expiry: ts + 1,
          amount: 1234,
        }
      )
    );
    await expect(mpond.delegateBySig(addrs[1], 1, ts + 1, sig.v, sig.r, sig.s, 1234)).to.be.reverted;
  });

  it("cannot delegate by sig with expired", async function() {
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(0);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Delegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: addrs[1],
          nonce: 0,
          expiry: ts - 1,
          amount: 1234,
        }
      )
    );
    await expect(mpond.delegateBySig(addrs[1], 0, ts, sig.v, sig.r, sig.s, 1234)).to.be.reverted;
  });

  it("can undelegate by sig less than delegated balance", async function() {
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Undelegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: addrs[1],
          nonce: 0,
          expiry: ts + 1,
          amount: 1000,
        }
      )
    );
    await mpond.undelegateBySig(addrs[1], 0, ts + 1, sig.v, sig.r, sig.s, 1000);
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(234));
  });

  it("can undelegate by sig equal to delegated balance", async function() {
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Undelegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: addrs[1],
          nonce: 0,
          expiry: ts + 1,
          amount: 1234,
        }
      )
    );
    await mpond.undelegateBySig(addrs[1], 0, ts + 1, sig.v, sig.r, sig.s, 1234);
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(0);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18());
  });

  it("cannot undelegate by sig more than delegated balance", async function() {
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    await mpond.undelegate(addrs[1], 1);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Undelegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: addrs[1],
          nonce: 0,
          expiry: ts + 1,
          amount: 1234,
        }
      )
    );
    await expect(mpond.undelegateBySig(addrs[1], 0, ts + 1, sig.v, sig.r, sig.s, 1234)).to.be.reverted;
  });

  it("cannot undelegate by sig from zero address", async function() {
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Undelegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: ethers.constants.AddressZero,
          nonce: 0,
          expiry: ts + 1,
          amount: 1000,
        }
      )
    );
    await expect(mpond.undelegateBySig(ethers.constants.AddressZero, 0, ts + 1, sig.v, sig.r, sig.s, 1000)).to.be.reverted;
  });

  it("cannot undelegate by sig with incorrect signature", async function() {
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Undelegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: addrs[1],
          nonce: 0,
          expiry: ts + 1,
          amount: 1234,
        }
      )
    );
    await expect(mpond.undelegateBySig(addrs[1], 0, ts + 1, sig.v + 5, sig.r, sig.s, 1234)).to.be.reverted;
  });

  it("cannot undelegate by sig with incorrect nonce", async function() {
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Undelegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: addrs[1],
          nonce: 1,
          expiry: ts + 1,
          amount: 1234,
        }
      )
    );
    await expect(mpond.undelegateBySig(addrs[1], 1, ts + 1, sig.v, sig.r, sig.s, 1234)).to.be.reverted;
  });

  it("cannot undelegate by sig with expired", async function() {
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getDelegates(addrs[0], ethers.constants.AddressZero)).to.equal(BN.from(10000).e18().sub(1234));
    expect(await mpond.getDelegates(addrs[0], addrs[1])).to.equal(1234);
    let ts = (await ethers.provider.getBlock("latest")).timestamp;
    let sig = ethers.utils.splitSignature(
      await (signers[0] as any)._signTypedData(
        {
          name: await mpond.name(),
          chainId: network.config.chainId,
          verifyingContract: mpond.address,
        },
        {
          Undelegation: [
            { name: "delegatee", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "expiry", type: "uint256" },
            { name: "amount", type: "uint96" },
          ],
        },
        {
          delegatee: addrs[1],
          nonce: 0,
          expiry: ts - 1,
          amount: 1234,
        }
      )
    );
    await expect(mpond.undelegateBySig(addrs[1], 0, ts, sig.v, sig.r, sig.s, 1234)).to.be.reverted;
  });
});

describe("MPond", function() {
  let signers: Signer[];
  let addrs: string[];
  let mpond: Contract;

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const MPond = await ethers.getContractFactory("MPond");
    mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
  });

  it("can get current votes", async function() {
    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234);

    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 2);

    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 3);

    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 4);

    await mpond.delegate(addrs[1], 1234);
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 5);

    await mpond.undelegate(addrs[1], 1234);
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 4);

    await mpond.undelegate(addrs[1], 1234);
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 3);

    await mpond.undelegate(addrs[1], 1234);
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 2);

    await mpond.undelegate(addrs[1], 1234);
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234);
  });

  it("can get prior votes", async function() {
    let b0 = (await ethers.provider.getBlock("latest")).number;
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 0);
    expect(await mpond.getPriorVotes(addrs[1], b0 - 1)).to.equal(1234 * 0);
    await expect(mpond.getPriorVotes(addrs[1], b0)).to.be.reverted;

    await mpond.delegate(addrs[1], 1234);
    let b1 = (await ethers.provider.getBlock("latest")).number;
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 1);
    expect(await mpond.getPriorVotes(addrs[1], b0)).to.equal(1234 * 0);
    await expect(mpond.getPriorVotes(addrs[1], b1)).to.be.reverted;

    await mpond.delegate(addrs[1], 1234);
    let b2 = (await ethers.provider.getBlock("latest")).number;
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 2);
    expect(await mpond.getPriorVotes(addrs[1], b0)).to.equal(1234 * 0);
    expect(await mpond.getPriorVotes(addrs[1], b1)).to.equal(1234 * 1);
    await expect(mpond.getPriorVotes(addrs[1], b2)).to.be.reverted;

    await mpond.delegate(addrs[1], 1234);
    let b3 = (await ethers.provider.getBlock("latest")).number;
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 3);
    expect(await mpond.getPriorVotes(addrs[1], b0)).to.equal(1234 * 0);
    expect(await mpond.getPriorVotes(addrs[1], b1)).to.equal(1234 * 1);
    expect(await mpond.getPriorVotes(addrs[1], b2)).to.equal(1234 * 2);
    await expect(mpond.getPriorVotes(addrs[1], b3)).to.be.reverted;

    await mpond.delegate(addrs[1], 1234);
    let b4 = (await ethers.provider.getBlock("latest")).number;
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 4);
    expect(await mpond.getPriorVotes(addrs[1], b0)).to.equal(1234 * 0);
    expect(await mpond.getPriorVotes(addrs[1], b1)).to.equal(1234 * 1);
    expect(await mpond.getPriorVotes(addrs[1], b2)).to.equal(1234 * 2);
    expect(await mpond.getPriorVotes(addrs[1], b3)).to.equal(1234 * 3);
    await expect(mpond.getPriorVotes(addrs[1], b4)).to.be.reverted;

    await mpond.delegate(addrs[1], 1234);
    let b5 = (await ethers.provider.getBlock("latest")).number;
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 5);
    expect(await mpond.getPriorVotes(addrs[1], b0)).to.equal(1234 * 0);
    expect(await mpond.getPriorVotes(addrs[1], b1)).to.equal(1234 * 1);
    expect(await mpond.getPriorVotes(addrs[1], b2)).to.equal(1234 * 2);
    expect(await mpond.getPriorVotes(addrs[1], b3)).to.equal(1234 * 3);
    expect(await mpond.getPriorVotes(addrs[1], b4)).to.equal(1234 * 4);
    await expect(mpond.getPriorVotes(addrs[1], b5)).to.be.reverted;

    await mpond.undelegate(addrs[1], 1234);
    let b6 = (await ethers.provider.getBlock("latest")).number;
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 4);
    expect(await mpond.getPriorVotes(addrs[1], b0)).to.equal(1234 * 0);
    expect(await mpond.getPriorVotes(addrs[1], b1)).to.equal(1234 * 1);
    expect(await mpond.getPriorVotes(addrs[1], b2)).to.equal(1234 * 2);
    expect(await mpond.getPriorVotes(addrs[1], b3)).to.equal(1234 * 3);
    expect(await mpond.getPriorVotes(addrs[1], b4)).to.equal(1234 * 4);
    expect(await mpond.getPriorVotes(addrs[1], b5)).to.equal(1234 * 5);
    await expect(mpond.getPriorVotes(addrs[1], b6)).to.be.reverted;

    await mpond.undelegate(addrs[1], 1234);
    let b7 = (await ethers.provider.getBlock("latest")).number;
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 3);
    expect(await mpond.getPriorVotes(addrs[1], b0)).to.equal(1234 * 0);
    expect(await mpond.getPriorVotes(addrs[1], b1)).to.equal(1234 * 1);
    expect(await mpond.getPriorVotes(addrs[1], b2)).to.equal(1234 * 2);
    expect(await mpond.getPriorVotes(addrs[1], b3)).to.equal(1234 * 3);
    expect(await mpond.getPriorVotes(addrs[1], b4)).to.equal(1234 * 4);
    expect(await mpond.getPriorVotes(addrs[1], b5)).to.equal(1234 * 5);
    expect(await mpond.getPriorVotes(addrs[1], b6)).to.equal(1234 * 4);
    await expect(mpond.getPriorVotes(addrs[1], b7)).to.be.reverted;

    await mpond.undelegate(addrs[1], 1234);
    let b8 = (await ethers.provider.getBlock("latest")).number;
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 2);
    expect(await mpond.getPriorVotes(addrs[1], b0)).to.equal(1234 * 0);
    expect(await mpond.getPriorVotes(addrs[1], b1)).to.equal(1234 * 1);
    expect(await mpond.getPriorVotes(addrs[1], b2)).to.equal(1234 * 2);
    expect(await mpond.getPriorVotes(addrs[1], b3)).to.equal(1234 * 3);
    expect(await mpond.getPriorVotes(addrs[1], b4)).to.equal(1234 * 4);
    expect(await mpond.getPriorVotes(addrs[1], b5)).to.equal(1234 * 5);
    expect(await mpond.getPriorVotes(addrs[1], b6)).to.equal(1234 * 4);
    expect(await mpond.getPriorVotes(addrs[1], b7)).to.equal(1234 * 3);
    await expect(mpond.getPriorVotes(addrs[1], b8)).to.be.reverted;

    await mpond.undelegate(addrs[1], 1234);
    let b9 = (await ethers.provider.getBlock("latest")).number;
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 1);
    expect(await mpond.getPriorVotes(addrs[1], b0)).to.equal(1234 * 0);
    expect(await mpond.getPriorVotes(addrs[1], b1)).to.equal(1234 * 1);
    expect(await mpond.getPriorVotes(addrs[1], b2)).to.equal(1234 * 2);
    expect(await mpond.getPriorVotes(addrs[1], b3)).to.equal(1234 * 3);
    expect(await mpond.getPriorVotes(addrs[1], b4)).to.equal(1234 * 4);
    expect(await mpond.getPriorVotes(addrs[1], b5)).to.equal(1234 * 5);
    expect(await mpond.getPriorVotes(addrs[1], b6)).to.equal(1234 * 4);
    expect(await mpond.getPriorVotes(addrs[1], b7)).to.equal(1234 * 3);
    expect(await mpond.getPriorVotes(addrs[1], b8)).to.equal(1234 * 2);
    await expect(mpond.getPriorVotes(addrs[1], b9)).to.be.reverted;

    await network.provider.request({
      method: "evm_mine",
      params: [],
    });
    let b10 = (await ethers.provider.getBlock("latest")).number;
    expect(await mpond.getCurrentVotes(addrs[1])).to.equal(1234 * 1);
    expect(await mpond.getPriorVotes(addrs[1], b0)).to.equal(1234 * 0);
    expect(await mpond.getPriorVotes(addrs[1], b1)).to.equal(1234 * 1);
    expect(await mpond.getPriorVotes(addrs[1], b2)).to.equal(1234 * 2);
    expect(await mpond.getPriorVotes(addrs[1], b3)).to.equal(1234 * 3);
    expect(await mpond.getPriorVotes(addrs[1], b4)).to.equal(1234 * 4);
    expect(await mpond.getPriorVotes(addrs[1], b5)).to.equal(1234 * 5);
    expect(await mpond.getPriorVotes(addrs[1], b6)).to.equal(1234 * 4);
    expect(await mpond.getPriorVotes(addrs[1], b7)).to.equal(1234 * 3);
    expect(await mpond.getPriorVotes(addrs[1], b8)).to.equal(1234 * 2);
    expect(await mpond.getPriorVotes(addrs[1], b9)).to.equal(1234 * 1);
    await expect(mpond.getPriorVotes(addrs[1], b10)).to.be.reverted;
  });
});

testRole(
  "MPond",
  async function(_signers: Signer[], _addrs: string[]) {
    const MPond = await ethers.getContractFactory("MPond");
    let mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    return mpond;
  },
  "BRIDGE_ROLE"
);

describe("MPond", function() {
  let signers: Signer[];
  let addrs: string[];
  let mpond: Contract;

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const MPond = await ethers.getContractFactory("MPond");
    mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);
  });

  it("admin can set l1 address", async function() {
    await mpond.setL1Address(addrs[1]);
    expect(await mpond.l1Address()).to.equal(addrs[1]);
  });

  it("non admin cannot set l1 address", async function() {
    await expect(mpond.connect(signers[1]).setL1Address(addrs[1])).to.be.reverted;
  });

  it("admin can withdraw", async function() {
    let balance = await mpond.balanceOf(addrs[0]);
    await mpond.transfer(mpond.address, 1000);
    expect(await mpond.balanceOf(mpond.address)).to.equal(1000);
    expect(await mpond.balanceOf(addrs[0])).to.equal(balance.sub(1000));

    await mpond.withdraw(200);
    expect(await mpond.balanceOf(mpond.address)).to.equal(800);
    expect(await mpond.balanceOf(addrs[0])).to.equal(balance.sub(800));
  });

  it("non admin cannot withdraw", async function() {
    await mpond.transfer(mpond.address, 1000);
    await expect(mpond.connect(signers[1]).withdraw(200)).to.be.reverted;
  });
});

describe("MPond", function() {
  let signers: Signer[];
  let addrs: string[];
  let mpond: Contract;

  beforeEach(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const MPond = await ethers.getContractFactory("MPond");
    mpond = await upgrades.deployProxy(MPond, { kind: "uups" });
    await mpond.grantRole(await mpond.BRIDGE_ROLE(), addrs[1]);
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), addrs[0]);
    await mpond.transfer(mpond.address, 1000);
  });

  it("non bridge cannot mint", async function() {
    await expect(mpond.connect(signers[2]).bridgeMint(addrs[2], 100)).to.be.reverted;
  });

  it("bridge can mint up to its balance", async function() {
    expect(await mpond.balanceOf(addrs[2])).to.equal(0);
    expect(await mpond.balanceOf(addrs[3])).to.equal(0);
    expect(await mpond.balanceOf(mpond.address)).to.equal(1000);

    await mpond.connect(signers[1]).bridgeMint(addrs[2], 100);

    expect(await mpond.balanceOf(addrs[2])).to.equal(100);
    expect(await mpond.balanceOf(addrs[3])).to.equal(0);
    expect(await mpond.balanceOf(mpond.address)).to.equal(900);

    await mpond.connect(signers[1]).bridgeMint(addrs[3], 900);

    expect(await mpond.balanceOf(addrs[2])).to.equal(100);
    expect(await mpond.balanceOf(addrs[3])).to.equal(900);
    expect(await mpond.balanceOf(mpond.address)).to.equal(0);
  });

  it("bridge cannot mint beyond its balance", async function() {
    await expect(mpond.connect(signers[1]).bridgeMint(addrs[2], 1001)).to.be.reverted;

    await mpond.connect(signers[1]).bridgeMint(addrs[2], 100);

    await expect(mpond.connect(signers[1]).bridgeMint(addrs[2], 901)).to.be.reverted;
  });

  it("non bridge cannot burn", async function() {
    await mpond.transfer(addrs[2], 1000);
    await mpond.transfer(addrs[3], 1000);
    await expect(mpond.connect(signers[2]).bridgeBurn(addrs[2], 100)).to.be.reverted;
  });

  it("bridge can burn up to users balance", async function() {
    await mpond.transfer(addrs[2], 1000);
    await mpond.transfer(addrs[3], 1000);
    expect(await mpond.balanceOf(addrs[2])).to.equal(1000);
    expect(await mpond.balanceOf(addrs[3])).to.equal(1000);
    expect(await mpond.balanceOf(mpond.address)).to.equal(1000);

    await mpond.connect(signers[1]).bridgeBurn(addrs[2], 100);
    await mpond.connect(signers[1]).bridgeBurn(addrs[3], 600);

    expect(await mpond.balanceOf(addrs[2])).to.equal(900);
    expect(await mpond.balanceOf(addrs[3])).to.equal(400);
    expect(await mpond.balanceOf(mpond.address)).to.equal(1700);

    await mpond.connect(signers[1]).bridgeBurn(addrs[2], 900);
    await mpond.connect(signers[1]).bridgeBurn(addrs[3], 400);

    expect(await mpond.balanceOf(addrs[2])).to.equal(0);
    expect(await mpond.balanceOf(addrs[3])).to.equal(0);
    expect(await mpond.balanceOf(mpond.address)).to.equal(3000);
  });

  it("bridge cannot burn beyond users balance", async function() {
    await mpond.transfer(addrs[2], 1000);
    await expect(mpond.connect(signers[1]).bridgeBurn(addrs[2], 1001)).to.be.reverted;

    await mpond.connect(signers[1]).bridgeBurn(addrs[2], 100);

    await expect(mpond.connect(signers[1]).bridgeBurn(addrs[2], 901)).to.be.reverted;
  });
});
