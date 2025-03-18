import { expect } from "chai";
import {
  BigNumber as BN,
  Contract,
  Signer,
} from "ethers";
import {
  ethers,
  upgrades,
} from "hardhat";

import { time } from "@nomicfoundation/hardhat-network-helpers";

import {
  Credit,
  MarketV1,
} from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import {
  getCredit,
  getMarketV1,
} from "../../utils/typechainConvertor";
import { testERC165 } from "../helpers/erc165";
import { testAdminRole } from "../helpers/rbac";

declare module "ethers" {
	interface BigNumber {
    e6(this: BigNumber): BigNumber;
    e12(this: BigNumber): BigNumber;
    e15(this: BigNumber): BigNumber;
    e16(this: BigNumber): BigNumber;
    e18(this: BigNumber): BigNumber;
	}
}

BN.prototype.e6 = function () {  
  return this.mul(BN.from(10).pow(6));
};
BN.prototype.e12 = function() {
  return this.mul(BN.from(10).pow(12));
};
BN.prototype.e15 = function() {
  return this.mul(BN.from(10).pow(15));
};
BN.prototype.e16 = function() {
  return this.mul(BN.from(10).pow(16));
};
BN.prototype.e18 = function() {
  return this.mul(BN.from(10).pow(18));
};

const RATE_LOCK = ethers.utils.id("RATE_LOCK");
const SELECTORS = [RATE_LOCK];
const WAIT_TIMES: number[] = [600];

const ONE_MINUTE = 60;
const TWO_MINUTES = 60 * 2;
const FIVE_MINUTES = 60 * 5;
const NOTICE_PERIOD = FIVE_MINUTES;
const SIGNER1_INITIAL_FUND = BN.from(1000).e6(); // 1000 USDC
const SIGNER2_INITIAL_FUND = BN.from(1000).e6(); // 1000 USDC
const JOB_RATE_1 = BN.from(1).e16();

const calcNoticePeriodCost = (rate: BN) => {
	return calcAmountToPay(rate, NOTICE_PERIOD);
};

const calcAmountToPay = (rate: BN, duration: number) => {
  return rate.mul(BN.from(duration)).add(10 ** 12 - 1).div(10 ** 12);
}

const incrementJobId = (jobId: string, increment: number) => {
  // Convert the jobId from bytes32 (hex string) to a BigNumber
  const jobIdBN = ethers.BigNumber.from(jobId);
  
  // Add the increment
  const incrementedJobIdBN = jobIdBN.add(increment);
  
  // Convert back to bytes32 (hex string) and return
  return ethers.utils.hexZeroPad(incrementedJobIdBN.toHexString(), 32);
};

const usdc = (number: number) => {
  return BN.from(number).e6();
};

testERC165(
	"MarketV1 ERC165",
	async function(_signers: Signer[], addrs: string[]) {
		const MarketV1 = await ethers.getContractFactory("MarketV1");
		const marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], addrs[11], SELECTORS, WAIT_TIMES],
			{ kind: "uups", unsafeAllow: ["missing-initializer-call"] },
		);
		return marketv1;
	},
	{
		IAccessControl: [
			"hasRole(bytes32,address)",
			"getRoleAdmin(bytes32)",
			"grantRole(bytes32,address)",
			"revokeRole(bytes32,address)",
			"renounceRole(bytes32,address)",
		],
		IAccessControlEnumerable: [
			"getRoleMember(bytes32,uint256)",
			"getRoleMemberCount(bytes32)",
		],
	},
);

testAdminRole("MarketV1 Admin Role", async function(_signers: Signer[], addrs: string[]) {
	const MarketV1 = await ethers.getContractFactory("MarketV1");
	const marketv1 = await upgrades.deployProxy(
		MarketV1,
		[addrs[0], addrs[11], SELECTORS, WAIT_TIMES],
		{ kind: "uups", unsafeAllow: ["missing-initializer-call"] },
	);
	return marketv1;
});

describe("Initialization", function () {
  let signers: Signer[];
  let addrs: string[];
  let marketv1: MarketV1;
  let creditToken: Credit;
  let token: Contract;

  let user: Signer;
  let user2: Signer;
  let provider: Signer;
  let admin: Signer;
  
  beforeEach(async function () {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map(async (a) => await a.getAddress()));

    admin = signers[0];
    user = signers[1];
    provider = signers[2];
    user2 = signers[3];

    // Deploy USDC
    const Token = await ethers.getContractFactory("Pond");
    token = await upgrades.deployProxy(Token, ["USDC", "USDC"], {
      kind: "uups",
      unsafeAllow: ["missing-initializer-call"],
    });
    await token.transfer(await user.getAddress(), SIGNER1_INITIAL_FUND);
    await token.transfer(await user2.getAddress(), SIGNER1_INITIAL_FUND);
    // Deploy MarketV1
    const MarketV1 = await ethers.getContractFactory("MarketV1");
    const marketv1Contract = await upgrades.deployProxy(
      MarketV1,
      [addrs[0], token.address, SELECTORS, WAIT_TIMES],
      { kind: "uups", unsafeAllow: ["missing-initializer-call"] },
    );
    marketv1 = getMarketV1(marketv1Contract.address, signers[0]);
    await token.connect(user).approve(marketv1.address, usdc(100));

    // Deploy Credit
    const Credit = await ethers.getContractFactory("Credit");
    const creditTokenContract = await upgrades.deployProxy(Credit, [], {
      kind: "uups",
      unsafeAllow: ["missing-initializer-call"],
      constructorArgs: [marketv1.address, token.address],
      initializer: false
    });
    creditToken = getCredit(creditTokenContract.address, signers[0]);

    // Initialize Credit
    await creditToken.initialize(addrs[0]);
  });

  describe("Initialize", function () {
    takeSnapshotBeforeAndAfterEveryTest(async () => { });
  
    it("should deploy with initialization disabled", async function () {
      const MarketV1 = await ethers.getContractFactory("MarketV1");
      const marketv1 = await MarketV1.deploy();

      await expect(
        marketv1.initialize(addrs[0], addrs[11], SELECTORS, WAIT_TIMES),
      ).to.be.revertedWith("Initializable: contract is already initialized");
    });
  
    it("should deploy as proxy and initializes", async function () {
      const MarketV1 = await ethers.getContractFactory("MarketV1");
      const marketv1 = await upgrades.deployProxy(
        MarketV1,
        [addrs[0], addrs[11], SELECTORS, WAIT_TIMES],
        { kind: "uups", unsafeAllow: ["missing-initializer-call"] },
      );
  
      await Promise.all(
        SELECTORS.map(async (s, idx) => {
          expect(await marketv1.lockWaitTime(s)).to.equal(WAIT_TIMES[idx]);
        }),
      );
      expect(
        await marketv1.hasRole(await marketv1.DEFAULT_ADMIN_ROLE(), addrs[0]),
      ).to.be.true;
      expect(await marketv1.token()).to.equal(addrs[11]);
    });
  
    it("should revert when initializing with mismatched lengths", async function () {
      const MarketV1 = await ethers.getContractFactory("MarketV1");
      await expect(
        upgrades.deployProxy(
          MarketV1,
          [addrs[0], addrs[11], SELECTORS, [...WAIT_TIMES, 0]],
          { kind: "uups", unsafeAllow: ["missing-initializer-call"] },
        ),
      ).to.be.reverted;
    });
  
    it("should upgrade", async function () {
      const MarketV1 = await ethers.getContractFactory("MarketV1");
      const marketv1 = await upgrades.deployProxy(
        MarketV1,
        [addrs[0], addrs[11], SELECTORS, WAIT_TIMES],
        { kind: "uups", unsafeAllow: ["missing-initializer-call"] },
      );
      await upgrades.upgradeProxy(marketv1.address, MarketV1, { kind: "uups", unsafeAllow: ["missing-initializer-call"] });
  
      await Promise.all(
        SELECTORS.map(async (s, idx) => {
          expect(await marketv1.lockWaitTime(s)).to.equal(WAIT_TIMES[idx]);
        }),
      );
      expect(
        await marketv1.hasRole(await marketv1.DEFAULT_ADMIN_ROLE(), addrs[0]),
      ).to.be.true;
      expect(await marketv1.token()).to.equal(addrs[11]);
    });
  
    it("should revert when upgrading without admin", async function () {
      const MarketV1 = await ethers.getContractFactory("MarketV1");
      const marketv1 = await upgrades.deployProxy(
        MarketV1,
        [addrs[0], addrs[11], SELECTORS, WAIT_TIMES],
        { kind: "uups", unsafeAllow: ["missing-initializer-call"] },
      );
  
      await expect(
        upgrades.upgradeProxy(marketv1.address, MarketV1.connect(signers[1]), {
          kind: "uups",
          unsafeAllow: ["missing-initializer-call"],
        }),
      ).to.be.revertedWith("only admin");
    });
  });

  describe("Reinitialize", function () {
    it("should revert when not admin", async () => {
      await expect(marketv1.connect(user).reinitialize(FIVE_MINUTES, creditToken.address)).to.be.revertedWith("only admin");
    });

    it("should revert when reinitialized twice", async () => {
      await marketv1.connect(admin).reinitialize(FIVE_MINUTES, creditToken.address);
      await expect(marketv1.connect(admin).reinitialize(FIVE_MINUTES, creditToken.address)).to.be.revertedWith("Initializable: contract is already initialized");
    });

    it("should set correct notice period", async () => {
      await marketv1.connect(admin).reinitialize(FIVE_MINUTES, creditToken.address);
      expect(await marketv1.noticePeriod()).to.equal(FIVE_MINUTES);
    });

    it("should set correct credit token address", async () => {
      await marketv1.connect(admin).reinitialize(FIVE_MINUTES, creditToken.address);
      expect(await marketv1.creditToken()).to.equal(creditToken.address);
    });

    it("should set correct job index", async () => {
      await marketv1.connect(admin).reinitialize(FIVE_MINUTES, creditToken.address);

      const chainId = (await ethers.provider.getNetwork()).chainId;
      const chainIdHex = chainId.toString(16).padStart(16, '0'); // 16 = 8 bytes * 2
      const jobIndex = '0x' + chainIdHex + '0'.repeat(48); // 48 = 64 (bytes32) - 16 (8 bytes)
      
      expect(await marketv1.jobIndex()).to.equal(jobIndex);
    });

    it("should open job with credit token", async () => {
      await marketv1.connect(admin).reinitialize(FIVE_MINUTES, creditToken.address);

      await creditToken.connect(admin).grantRole(await creditToken.MINTER_ROLE(), await admin.getAddress());
      await creditToken.connect(admin).grantRole(await creditToken.TRANSFER_ALLOWED_ROLE(), await user.getAddress());
      await creditToken.connect(admin).mint(await user.getAddress(), usdc(10000));
      expect(await creditToken.hasRole(await creditToken.TRANSFER_ALLOWED_ROLE(), await user.getAddress())).to.be.true;

      await expect(marketv1.connect(user).jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, usdc(100))).to.be.not.reverted;
    });
  });
});

describe("MarketV1", function () {
  let INITIAL_TIMESTAMP: number;

  let signers: Signer[];
  let addrs: string[];
  let marketv1: MarketV1;
  let creditToken: Credit;
  let token: Contract;

  let admin: Signer;
  let user: Signer;
  let provider: Signer;
  let user2: Signer;
  let admin2: Signer;

  let INITIAL_JOB_INDEX: string;
  let JOB_OPENED_TIMESTAMP: number;


  before(async function () {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    admin = signers[0];
    user = signers[1];
    provider = signers[2];
    user2 = signers[3];
    admin2 = signers[4];
    
    // Deploy USDC
    const USDC = await ethers.getContractFactory("Pond");
    token = await upgrades.deployProxy(USDC, ["Marlin", "USDC"], {
      kind: "uups",
      unsafeAllow: ["missing-initializer-call"],
    });
    await token.transfer(addrs[1], SIGNER1_INITIAL_FUND);
    await token.transfer(addrs[3], SIGNER2_INITIAL_FUND);
    
    // Deploy MarketV1
    const MarketV1 = await ethers.getContractFactory("MarketV1");
    const marketv1Contract = await upgrades.deployProxy(
      MarketV1,
      [addrs[0], token.address, SELECTORS, WAIT_TIMES],
      { kind: "uups", unsafeAllow: ["missing-initializer-call"] },
    );
    marketv1 = getMarketV1(marketv1Contract.address, signers[0]);
    await token.connect(user).approve(marketv1.address, usdc(100));

    // Deploy Credit
    const Credit = await ethers.getContractFactory("Credit");
    const creditTokenContract = await upgrades.deployProxy(Credit, [], {
      kind: "uups",
      unsafeAllow: ["missing-initializer-call"],
      constructorArgs: [marketv1.address, token.address],
      initializer: false
    });
    creditToken = getCredit(creditTokenContract.address, signers[0]);
    await creditToken.initialize(addrs[0]);
    await marketv1.connect(admin).reinitialize(FIVE_MINUTES, creditToken.address);
    
    await marketv1.updateNoticePeriod(FIVE_MINUTES);

    // Set initial timestamp
    await time.increaseTo(Math.floor((new Date().getTime()) / 1000));
    INITIAL_TIMESTAMP = (await ethers.provider.getBlock('latest')).timestamp;

    // Setup for using Credit
    await creditToken.connect(admin).grantRole(await creditToken.MINTER_ROLE(), await admin.getAddress());
    await creditToken.connect(admin).grantRole(await creditToken.TRANSFER_ALLOWED_ROLE(), await admin.getAddress());
    await creditToken.connect(admin).grantRole(await creditToken.TRANSFER_ALLOWED_ROLE(), marketv1.address);
    await token.connect(admin).transfer(creditToken.address, usdc(1000));

    // Fund user with 1000 Credit
    await creditToken.connect(admin).mint(await admin.getAddress(), usdc(1000));
    await creditToken.connect(admin).transfer(await user.getAddress(), usdc(1000));

    INITIAL_JOB_INDEX = await marketv1.jobIndex();
  });

  describe("Provider Registration", function () {
    describe("Provider Registers", function () {
      takeSnapshotBeforeAndAfterEveryTest(async () => { });
    
      it("should register as provider", async () => {
        await marketv1.connect(signers[1]).providerAdd("https://example.com/");
    
        expect(await marketv1.providers(addrs[1])).to.equal("https://example.com/");
      });
    
      it("should revert when registering as provider with empty cp", async () => {
        await expect(
          marketv1.connect(signers[1]).providerAdd(""),
        ).to.be.revertedWith("invalid");
      });
    
      it("should revert when registering as provider if already registered", async () => {
        await marketv1.connect(signers[1]).providerAdd("https://example.com/");
    
        await expect(
          marketv1.connect(signers[1]).providerAdd("https://example.com/"),
        ).to.be.revertedWith("already exists");
      });
    });
  
    describe("Provider Unregisters", function () {
      takeSnapshotBeforeAndAfterEveryTest(async () => { });
    
      it("should unregister as provider", async () => {
        await marketv1.connect(signers[1]).providerAdd("https://example.com/");
        await marketv1.connect(signers[1]).providerRemove();
    
        expect(await marketv1.providers(addrs[1])).to.equal("");
      });
    
      it("should revert when unregistering as provider if never registered", async () => {
        await expect(
          marketv1.connect(signers[1]).providerRemove(),
        ).to.be.revertedWith("not found");
      });
    
      it("should revert when unregistering as provider if already unregistered", async () => {
        await marketv1.connect(signers[1]).providerAdd("https://example.com/");
        await marketv1.connect(signers[1]).providerRemove();
    
        await expect(
          marketv1.connect(signers[1]).providerRemove(),
        ).to.be.revertedWith("not found");
      });
    });
  });

  describe("cp update", function () {
    takeSnapshotBeforeAndAfterEveryTest(async () => { });
  
    it("should update cp", async () => {
      await marketv1.connect(signers[1]).providerAdd("https://example.com/");
      await marketv1
        .connect(signers[1])
        .providerUpdateWithCp("https://example.com/new");
  
      expect(await marketv1.providers(addrs[1])).to.equal(
        "https://example.com/new",
      );
    });
  
    it("should revert when updating to empty cp", async () => {
      await marketv1.connect(signers[1]).providerAdd("https://example.com/");
      await expect(
        marketv1.connect(signers[1]).providerUpdateWithCp(""),
      ).to.be.revertedWith("invalid");
    });
  
    it("should revert when updating if never registered", async () => {
      await expect(
        marketv1
          .connect(signers[1])
          .providerUpdateWithCp("https://example.com/new"),
      ).to.be.revertedWith("not found");
    });
  });
  
  describe("Job Open", function () {
    takeSnapshotBeforeAndAfterEveryTest(async () => { });
  
    it("should open job with USDC only", async () => {
      const initialBalance = usdc(50);
      const noticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);

      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialBalance);
  
      const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
      expect(jobInfo.metadata).to.equal("some metadata");
      expect(jobInfo.owner).to.equal(await user.getAddress());
      expect(jobInfo.provider).to.equal(await provider.getAddress());
      expect(jobInfo.rate).to.equal(JOB_RATE_1);
      expect(jobInfo.balance).to.equal(initialBalance.sub(noticePeriodCost));
      expect(jobInfo.lastSettled).to.be.within(INITIAL_TIMESTAMP + FIVE_MINUTES, INITIAL_TIMESTAMP + FIVE_MINUTES + 1);
  
      expect(await token.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND.sub(initialBalance));
      expect(await token.balanceOf(marketv1.address)).to.equal(initialBalance.sub(noticePeriodCost));
    });

    it("should increment job index correctly", async () => {
      const initialBalance = usdc(10);

      const initialJobIndex = await marketv1.jobIndex();
      const chainId = (await ethers.provider.getNetwork()).chainId;
      const chainIdHex = chainId.toString(16).padStart(16, '0'); // 16 = 8 bytes * 2
      const jobIndex = '0x' + chainIdHex + '0'.repeat(48); // 48 = 64 (bytes32) - 16 (8 bytes)
      expect(initialJobIndex).to.equal(jobIndex);

      // Open First Job
      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialBalance);
      
      const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
      expect(jobInfo.metadata).to.equal("some metadata");

      // Open Second Job
      await marketv1
        .connect(user)
        .jobOpen("some metadata2", await provider.getAddress(), JOB_RATE_1, initialBalance);
      const jobInfo2 = await marketv1.jobs(incrementJobId(INITIAL_JOB_INDEX, 1));
      expect(jobInfo2.metadata).to.equal("some metadata2");

      // Open Third Job
      await marketv1
        .connect(user)
        .jobOpen("some metadata3", await provider.getAddress(), JOB_RATE_1, initialBalance);
      const jobInfo3 = await marketv1.jobs(incrementJobId(INITIAL_JOB_INDEX, 2));
      expect(jobInfo3.metadata).to.equal("some metadata3");
    });

    it("should open job with Credit only", async () => {
      const initialBalance = usdc(50);
      const noticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);

      await creditToken.connect(user).approve(marketv1.address, initialBalance);
      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialBalance);
  
      const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
      expect(jobInfo.metadata).to.equal("some metadata");
      expect(jobInfo.owner).to.equal(await user.getAddress());
      expect(jobInfo.provider).to.equal(await provider.getAddress());
      expect(jobInfo.rate).to.equal(JOB_RATE_1);
      expect(jobInfo.balance).to.equal(initialBalance.sub(noticePeriodCost));
      expect(jobInfo.lastSettled).to.be.within(INITIAL_TIMESTAMP + FIVE_MINUTES, INITIAL_TIMESTAMP + FIVE_MINUTES + 1);

      expect(await marketv1.jobCreditBalance(INITIAL_JOB_INDEX)).to.equal(initialBalance.sub(noticePeriodCost));
    });

    it("should open job with USDC and Credit", async () => {
      const totalBalance = usdc(50);
      const creditBalance = usdc(10);
      const noticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);

      await creditToken.connect(user).approve(marketv1.address, creditBalance);
      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, totalBalance);

      const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
      expect(jobInfo.metadata).to.equal("some metadata");
      expect(jobInfo.owner).to.equal(await user.getAddress());
      expect(jobInfo.provider).to.equal(await provider.getAddress());
      expect(jobInfo.rate).to.equal(JOB_RATE_1);
      expect(jobInfo.balance).to.equal(totalBalance.sub(noticePeriodCost));
      expect(await marketv1.jobCreditBalance(INITIAL_JOB_INDEX)).to.equal(creditBalance.sub(noticePeriodCost));
    })
  
    it("should revert when opening job without enough approved", async () => {
      await expect(
        marketv1.connect(signers[1]).jobOpen("some metadata", addrs[2], JOB_RATE_1, usdc(150)), // 100 USDC approved
      ).to.be.revertedWith("ERC20: insufficient allowance");
    });
  
    it("should revert when opening job without enough balance", async () => {
      await token.connect(signers[1]).approve(marketv1.address, usdc(5000));
      await expect(
        marketv1.connect(signers[1]).jobOpen("some metadata", addrs[2], JOB_RATE_1, usdc(5000)),
      ).to.be.revertedWith("ERC20: transfer amount exceeds balance");
    });
  });

  describe("Job Settle", function () {
    const initialDeposit = usdc(50);
    const initialBalance = initialDeposit.sub(calcNoticePeriodCost(JOB_RATE_1));

    beforeEach(async () => {
      JOB_OPENED_TIMESTAMP = (await ethers.provider.getBlock('latest')).timestamp;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    describe("USDC Only", function () {

      beforeEach(async () => {
        await token.connect(user).approve(marketv1.address, initialDeposit);
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
      });

      describe("CASE1: Settle Job immediately after Job Open", function () {
        it("should revert before lastSettled", async () => {
          await expect(marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX)).to.be.revertedWith("cannot settle before lastSettled");
        });
      });
  
      describe("CASE2: Settle Job 2 minutes after Job Open", function () {
        it("should revert before lastSettled", async () => {
          const TWO_MINUTES = 60 * 2;
          await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);
  
          await expect(marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX)).to.be.revertedWith("cannot settle before lastSettled");
        });
      });
  
      describe("CASE3: Settle Job 1 second before notice period", function () {
        it("should revert before lastSettled", async () => {
          const jobOpenedTimestamp = (await ethers.provider.getBlock('latest')).timestamp;
          await time.increaseTo(jobOpenedTimestamp + NOTICE_PERIOD - 1);
          
          const lastSettled = (await marketv1.jobs(INITIAL_JOB_INDEX)).lastSettled;
          expect(lastSettled).to.equal(jobOpenedTimestamp + NOTICE_PERIOD);
          await expect(marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX)).to.be.revertedWith("cannot settle before lastSettled");
        });
      });
  
      describe("CASE4: Settle Job 2 minutes after notice period", function () {
        it("should spend notice period cost and 2 minutes worth tokens", async () => {
          const TWO_MINUTES = 60 * 2;
          await time.increaseTo(INITIAL_TIMESTAMP + NOTICE_PERIOD + TWO_MINUTES);
  
          // Job Settle
          await marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX);
  
          const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
          expect(jobInfo.metadata).to.equal("some metadata");
          expect(jobInfo.owner).to.equal(await user.getAddress());
          expect(jobInfo.provider).to.equal(await provider.getAddress());
          expect(jobInfo.rate).to.equal(JOB_RATE_1);
  
          const jobBalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));
  
          const lastSettledTimestampExpected = INITIAL_TIMESTAMP + NOTICE_PERIOD + TWO_MINUTES;
          expect(jobInfo.lastSettled).to.equal(lastSettledTimestampExpected);
  
          // User balance
          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit);
          expect(await token.balanceOf(await user.getAddress())).to.equal(userBalanceExpected);
  
          // Provider balance
          const providerBalanceExpected = calcAmountToPay(JOB_RATE_1, TWO_MINUTES).add(calcNoticePeriodCost(JOB_RATE_1));
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));
  
          // MarketV1 balance
          const marketv1BalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
          expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });
    });

    describe("Credit Only", function () {
      beforeEach(async () => {
        // await token.connect(user).approve(marketv1.address, initialDeposit);
        await creditToken.connect(user).approve(marketv1.address, initialDeposit);
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
      });

      describe("CASE1: Settle Job immediately after Job Open", function () {
        it("should revert before lastSettled", async () => {
          await expect(marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX)).to.be.revertedWith("cannot settle before lastSettled");
        });
      });
  
      describe("CASE2: Settle Job 2 minutes after Job Open", function () {
        it("should revert before lastSettled", async () => {
          const TWO_MINUTES = 60 * 2;
          await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);
  
          await expect(marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX)).to.be.revertedWith("cannot settle before lastSettled");
        });
      });
  
      describe("CASE3: Settle Job exactly after notice period", function () {
        it("should revert before lastSettled", async () => {
          await time.increaseTo(INITIAL_TIMESTAMP + NOTICE_PERIOD);
  
          await expect(marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX)).to.be.revertedWith("cannot settle before lastSettled");
        });
      });
  
      describe("CASE4: Settle Job 2 minutes after notice period", function () {
        it("should spend notice period cost and 2 minutes worth tokens", async () => {
          const TWO_MINUTES = 60 * 2;
          await time.increaseTo(INITIAL_TIMESTAMP + NOTICE_PERIOD + TWO_MINUTES);
  
          // Job Settle
          await marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX);

          // Job Info After Settle
          const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
          expect(jobInfo.metadata).to.equal("some metadata");
          expect(jobInfo.owner).to.equal(await user.getAddress());
          expect(jobInfo.provider).to.equal(await provider.getAddress());
          expect(jobInfo.rate).to.equal(JOB_RATE_1);
  
          const jobBalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));
  
          const lastSettledTimestampExpected = INITIAL_TIMESTAMP + NOTICE_PERIOD + TWO_MINUTES;
          expect(jobInfo.lastSettled).to.be.within(lastSettledTimestampExpected - 3, lastSettledTimestampExpected + 3);
  
          // User balance
          const userTokenBalanceExpected = SIGNER1_INITIAL_FUND;
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userTokenBalanceExpected.sub(JOB_RATE_1), userTokenBalanceExpected.add(JOB_RATE_1));
          const userCreditBalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
          expect(await creditToken.balanceOf(await user.getAddress())).to.be.within(userCreditBalanceExpected.sub(JOB_RATE_1), userCreditBalanceExpected.add(JOB_RATE_1));
  
          // Provider balance
          const providerBalanceExpected = calcAmountToPay(JOB_RATE_1, TWO_MINUTES).add(calcNoticePeriodCost(JOB_RATE_1));
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));
  
          // MarketV1 balance
          const marketv1TokenBalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
          expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1TokenBalanceExpected.sub(JOB_RATE_1), marketv1TokenBalanceExpected.add(JOB_RATE_1));
          const marketv1CreditBalanceExpected = calcAmountToPay(JOB_RATE_1, TWO_MINUTES);
          expect(await creditToken.balanceOf(marketv1.address)).to.be.within(marketv1CreditBalanceExpected.sub(JOB_RATE_1), marketv1CreditBalanceExpected.add(JOB_RATE_1));
        });
      });
    });

    describe("Credit and USDC", function () {
      const creditDeposit = usdc(10);
      const usdcDeposit = usdc(40);

      beforeEach(async () => {
        await token.connect(user).approve(marketv1.address, usdcDeposit);
        await creditToken.connect(user).approve(marketv1.address, creditDeposit);
        // deposit 10 credit and 40 usdc
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, usdcDeposit.add(creditDeposit));
      });

      describe("CASE1: Settle Job immediately after Job Open", function () {
        it("should revert before lastSettled", async () => {
          await expect(marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX)).to.be.revertedWith("cannot settle before lastSettled");
        });
      });
  
      describe("CASE2: Settle Job 2 minutes after Job Open", function () {
        it("should revert before lastSettled", async () => {
          const TWO_MINUTES = 60 * 2;
          await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);
  
          await expect(marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX)).to.be.revertedWith("cannot settle before lastSettled");
        });
      });
  
      describe("CASE3: Settle Job exactly after notice period", function () {
        it("should revert before lastSettled", async () => {
          await time.increaseTo(INITIAL_TIMESTAMP + NOTICE_PERIOD);
  
          await expect(marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX)).to.be.revertedWith("cannot settle before lastSettled");
        });
      });
  
      describe("CASE4: Settle Job 2 minutes after notice period - only Credit is settled", function () {
        it("should settle notice period cost and 2 minutes worth tokens only from Credit", async () => {
          const TWO_MINUTES = 60 * 2;
          const TIME_JOB_OPEN = (await ethers.provider.getBlock('latest')).timestamp;
          await time.increaseTo(TIME_JOB_OPEN + NOTICE_PERIOD + TWO_MINUTES);
          const TIME_JOB_SETTLE = (await ethers.provider.getBlock('latest')).timestamp;
          const TIME_DIFF = TIME_JOB_SETTLE - TIME_JOB_OPEN;

          const noticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);
  
          // Job Settle
          await marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX);

          /* Job Info After Settle */
          const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
          expect(jobInfo.metadata).to.equal("some metadata");
          expect(jobInfo.owner).to.equal(await user.getAddress());
          expect(jobInfo.provider).to.equal(await provider.getAddress());
          expect(jobInfo.rate).to.equal(JOB_RATE_1);
          // Job Balance
          const jobBalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));
          // Job Last Settled
          const lastSettledTimestampExpected = TIME_JOB_OPEN + NOTICE_PERIOD + TWO_MINUTES;
          expect(jobInfo.lastSettled).to.be.within(lastSettledTimestampExpected - 3, lastSettledTimestampExpected + 3);
          // Job Credit Balance
          const amountSettledExpected = calcAmountToPay(JOB_RATE_1, TIME_DIFF);
          const jobCreditBalanceExpected = creditDeposit.sub(amountSettledExpected);
          expect(await marketv1.jobCreditBalance(INITIAL_JOB_INDEX)).to.be.within(jobCreditBalanceExpected.sub(JOB_RATE_1), jobCreditBalanceExpected.add(JOB_RATE_1));
  
          /* User balance */
          // User Token balance
          const userTokenBalanceExpected = SIGNER1_INITIAL_FUND.sub(usdcDeposit);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userTokenBalanceExpected.sub(JOB_RATE_1), userTokenBalanceExpected.add(JOB_RATE_1));
          // User Credit balance
          const userCreditBalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
          expect(await creditToken.balanceOf(await user.getAddress())).to.be.within(userCreditBalanceExpected.sub(JOB_RATE_1), userCreditBalanceExpected.add(JOB_RATE_1));
  
          /* Provider balance */
          // Provider Token balance
          const providerBalanceExpected = calcAmountToPay(JOB_RATE_1, TWO_MINUTES).add(calcNoticePeriodCost(JOB_RATE_1));
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));
  
          /* MarketV1 balance */
          // MarketV1 Token balance
          const marketv1TokenBalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
          expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1TokenBalanceExpected.sub(JOB_RATE_1), marketv1TokenBalanceExpected.add(JOB_RATE_1));
          // MarketV1 Credit balance
          const marketv1CreditBalanceExpected = calcAmountToPay(JOB_RATE_1, TWO_MINUTES);
          expect(await creditToken.balanceOf(marketv1.address)).to.be.within(marketv1CreditBalanceExpected.sub(JOB_RATE_1), marketv1CreditBalanceExpected.add(JOB_RATE_1));
        });
      });

      describe("CASE5: Settle Job 20 minutes after notice period - both Credit and USDC are settled", function () {
        it("should settle all Credits and some USDC", async () => {
          const TWENTY_MINUTES = 60 * 20;
          await time.increaseTo(JOB_OPENED_TIMESTAMP + NOTICE_PERIOD + TWENTY_MINUTES);
          const TIME_JOB_SETTLE = (await ethers.provider.getBlock('latest')).timestamp;
          const TIME_DIFF = TIME_JOB_SETTLE - JOB_OPENED_TIMESTAMP;

          const noticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);
  
          // Job Settle
          await marketv1.connect(user).jobSettle(INITIAL_JOB_INDEX);

          /* Job Info After Settle */
          const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
          expect(jobInfo.metadata).to.equal("some metadata");
          expect(jobInfo.owner).to.equal(await user.getAddress());
          expect(jobInfo.provider).to.equal(await provider.getAddress());
          expect(jobInfo.rate).to.equal(JOB_RATE_1);
          // Job Balance
          const jobBalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWENTY_MINUTES));
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));
          // Job Last Settled
          const lastSettledTimestampExpected = JOB_OPENED_TIMESTAMP + NOTICE_PERIOD + TWENTY_MINUTES;
          expect(jobInfo.lastSettled).to.be.within(lastSettledTimestampExpected - 3, lastSettledTimestampExpected + 3);
          // Job Credit Balance
          const amountSettledExpected = calcAmountToPay(JOB_RATE_1, TIME_DIFF);
          const jobCreditBalanceExpected = creditDeposit.sub(amountSettledExpected);
          expect(await marketv1.jobCreditBalance(INITIAL_JOB_INDEX)).to.be.within(jobCreditBalanceExpected.sub(JOB_RATE_1), jobCreditBalanceExpected.add(JOB_RATE_1));
          expect(await marketv1.jobCreditBalance(INITIAL_JOB_INDEX)).to.equal(0);
  
          /* User balance */
          // User Token balance
          const userTokenBalanceExpected = SIGNER1_INITIAL_FUND.sub(usdcDeposit);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userTokenBalanceExpected.sub(JOB_RATE_1), userTokenBalanceExpected.add(JOB_RATE_1));
          // User Credit balance
          const userCreditBalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
          expect(await creditToken.balanceOf(await user.getAddress())).to.be.within(userCreditBalanceExpected.sub(JOB_RATE_1), userCreditBalanceExpected.add(JOB_RATE_1));
  
          /* Provider balance */
          // Provider Token balance
          const providerBalanceExpected = calcAmountToPay(JOB_RATE_1, TWO_MINUTES).add(calcNoticePeriodCost(JOB_RATE_1));
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));
  
          /* MarketV1 balance */
          // MarketV1 Token balance
          const marketv1TokenBalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
          expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1TokenBalanceExpected.sub(JOB_RATE_1), marketv1TokenBalanceExpected.add(JOB_RATE_1));
          // MarketV1 Credit balance
          const marketv1CreditBalanceExpected = calcAmountToPay(JOB_RATE_1, TWO_MINUTES);
          expect(await creditToken.balanceOf(marketv1.address)).to.be.within(marketv1CreditBalanceExpected.sub(JOB_RATE_1), marketv1CreditBalanceExpected.add(JOB_RATE_1));
        });
      });
    });
  }); 

  describe("Job Deposit", function () {
    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    describe("USDC Only", function () {
      it("should deposit to job with USDC", async () => {
        const initialDeposit = usdc(50);
        const initialBalance = initialDeposit.sub(calcNoticePeriodCost(JOB_RATE_1));
        const additionalDepositAmount = usdc(25);
  
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
        
        // Deposit 25 USDC
        await marketv1
          .connect(signers[1])
          .jobDeposit(INITIAL_JOB_INDEX, additionalDepositAmount);
    
        // Job after deposit
        const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
        expect(jobInfo.metadata).to.equal("some metadata");
        expect(jobInfo.owner).to.equal(addrs[1]);
        expect(jobInfo.provider).to.equal(addrs[2]);
        expect(jobInfo.rate).to.equal(JOB_RATE_1);
        expect(jobInfo.balance).to.equal(initialBalance.add(additionalDepositAmount));
        expect(jobInfo.lastSettled).to.be.within(INITIAL_TIMESTAMP + FIVE_MINUTES - 3, INITIAL_TIMESTAMP + FIVE_MINUTES + 3);
        
        const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit).sub(additionalDepositAmount);
        expect(await token.balanceOf(addrs[1])).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));
  
        const marketv1BalanceExpected = initialBalance.add(additionalDepositAmount);
        expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
      });
    
      it("should revert when depositing to job without enough approved", async () => {
        const initialDeposit = usdc(50);
        const initialBalance = initialDeposit.sub(calcNoticePeriodCost(JOB_RATE_1));
        const additionalDepositAmount = usdc(25);
  
        await token.connect(user).approve(marketv1.address, initialDeposit);
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
        
        // Deposit 25 USDC
        await expect(marketv1
          .connect(user)
          .jobDeposit(INITIAL_JOB_INDEX, additionalDepositAmount)).to.be.revertedWith("ERC20: insufficient allowance");
      });
    
      it("should revert when depositing to job without enough balance", async () => {
        const initialDeposit = SIGNER1_INITIAL_FUND;
        const initialBalance = initialDeposit.sub(calcNoticePeriodCost(JOB_RATE_1));
        const additionalDepositAmount = usdc(25);
  
        // Open Job
        await token.connect(user).approve(marketv1.address, SIGNER1_INITIAL_FUND.add(usdc(1000)));
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
        
        // Deposit 25 USDC
        await expect(marketv1
          .connect(user)
          .jobDeposit(INITIAL_JOB_INDEX, additionalDepositAmount)).to.be.revertedWith("ERC20: transfer amount exceeds balance");
      });
    
      it("should revert when depositing to never registered job", async () => {
        await expect(marketv1
          .connect(user)
          .jobDeposit(ethers.utils.hexZeroPad("0x01", 32), 25)).to.be.revertedWith("job not found");
      });
    
      it("should revert when depositing to closed job", async () => {
        const initialDeposit = usdc(50);
  
        // Job Open
        await token.connect(user).approve(marketv1.address, initialDeposit);
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
    
        // Job Close
        await marketv1.connect(user).jobClose(INITIAL_JOB_INDEX);
    
        // Job Deposit
        await expect(marketv1
          .connect(signers[1])
          .jobDeposit(INITIAL_JOB_INDEX, 25)).to.be.revertedWith("job not found");
      });
    });

    describe("Credit Only", function () {
      const INITIAL_DEPOSIT_AMOUNT = usdc(50);
      const ADDITIONAL_DEPOSIT_AMOUNT = usdc(25);
      const NOTICE_PERIOD_COST = calcNoticePeriodCost(JOB_RATE_1);

      it("should deposit to job with Credit", async () => {
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, INITIAL_DEPOSIT_AMOUNT);
        
        // Deposit 25 Credit
        await creditToken.connect(user).approve(marketv1.address, ADDITIONAL_DEPOSIT_AMOUNT);
        await marketv1
          .connect(signers[1])
          .jobDeposit(INITIAL_JOB_INDEX, ADDITIONAL_DEPOSIT_AMOUNT);

        const currentTimestamp = (await ethers.provider.getBlock('latest')).timestamp;
    
        // Job after deposit
        const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
        expect(jobInfo.metadata).to.equal("some metadata");
        expect(jobInfo.owner).to.equal(await user.getAddress());
        expect(jobInfo.provider).to.equal(await provider.getAddress());
        expect(jobInfo.rate).to.equal(JOB_RATE_1);
        expect(jobInfo.balance).to.equal(INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).add(ADDITIONAL_DEPOSIT_AMOUNT));
        expect(jobInfo.lastSettled).to.equal(currentTimestamp + NOTICE_PERIOD);
        
        const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(INITIAL_DEPOSIT_AMOUNT).sub(ADDITIONAL_DEPOSIT_AMOUNT);
        expect(await token.balanceOf(addrs[1])).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));
  
        const marketv1BalanceExpected = INITIAL_DEPOSIT_AMOUNT.add(ADDITIONAL_DEPOSIT_AMOUNT);
        expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
      });
    
      it("should revert when depositing to job without approving both Credit and USDC", async () => {
        const additionalDepositAmount = usdc(25);
  
        await token.connect(user).approve(marketv1.address, INITIAL_DEPOSIT_AMOUNT);
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, INITIAL_DEPOSIT_AMOUNT);
        
        // Deposit without approving Credit
        await expect(marketv1
          .connect(user)
          .jobDeposit(INITIAL_JOB_INDEX, ADDITIONAL_DEPOSIT_AMOUNT)).to.be.revertedWith("ERC20: insufficient allowance");
      });
    
      it("should deposit USDC when Credit credit balance is not enough", async () => {
        const initialDeposit = SIGNER1_INITIAL_FUND;

        // Open Job
        await token.connect(user2).approve(marketv1.address, SIGNER1_INITIAL_FUND.add(usdc(1000)));
        await marketv1
          .connect(user2)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
        
        // Approve 25 Credit without having enough Credit balance
        await creditToken.connect(user2).approve(marketv1.address, ADDITIONAL_DEPOSIT_AMOUNT);
        await expect(marketv1
          .connect(user2)
          .jobDeposit(INITIAL_JOB_INDEX, ADDITIONAL_DEPOSIT_AMOUNT)).to.be.revertedWith("ERC20: transfer amount exceeds balance");
        
        const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
        const creditBalance = await creditToken.balanceOf(await user2.getAddress());
        expect(jobInfo.balance).to.equal(initialDeposit.sub(NOTICE_PERIOD_COST));
        expect(creditBalance).to.equal(0);
      });
    
      it("should revert when depositing to never registered job", async () => {
        await creditToken.connect(user).approve(marketv1.address, INITIAL_DEPOSIT_AMOUNT);
        await expect(marketv1
          .connect(user)
          .jobDeposit(INITIAL_JOB_INDEX, ADDITIONAL_DEPOSIT_AMOUNT)).to.be.revertedWith("job not found");
      });
    
      it("should revert when depositing to closed job", async () => {
        const initialDeposit = usdc(50);
  
        // Job Open
        await token.connect(user).approve(marketv1.address, initialDeposit);
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
    
        // Job Close
        await marketv1.connect(user).jobClose(INITIAL_JOB_INDEX);
    
        // Job Deposit
        await creditToken.connect(user).approve(marketv1.address, ADDITIONAL_DEPOSIT_AMOUNT);
        await expect(marketv1
          .connect(signers[1])
          .jobDeposit(INITIAL_JOB_INDEX, 25)).to.be.revertedWith("job not found");
      });
    });

    describe("Both Credit and USDC", function () {
      const INITIAL_DEPOSIT_AMOUNT = usdc(50);
      const NOTICE_PERIOD_COST = calcNoticePeriodCost(JOB_RATE_1);
      const TOTAL_ADITIONAL_DEPOSIT_AMOUNT = usdc(40);
      const ADDITIONAL_CREDIT_DEPOSIT_AMOUNT = usdc(30);
      const ADDITIONAL_USDC_DEPOSIT_AMOUNT = usdc(10);
      const TOTAL_DEPOSIT_AMOUNT = INITIAL_DEPOSIT_AMOUNT.add(ADDITIONAL_USDC_DEPOSIT_AMOUNT).add(ADDITIONAL_CREDIT_DEPOSIT_AMOUNT);

      it("should deposit 10 USDC and 30 Credit", async () => {
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, INITIAL_DEPOSIT_AMOUNT);
        expect((await marketv1.jobs(INITIAL_JOB_INDEX)).balance).to.equal(INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST));
        
        // Deposit 30 Credit and 10 USDC
        await creditToken.connect(user).approve(marketv1.address, ADDITIONAL_CREDIT_DEPOSIT_AMOUNT);
        await marketv1
          .connect(user)
          .jobDeposit(INITIAL_JOB_INDEX, TOTAL_ADITIONAL_DEPOSIT_AMOUNT);
        
        const currentTimestamp = (await ethers.provider.getBlock('latest')).timestamp;
        
        // Job after deposit
        const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
        const creditBalance = await marketv1.jobCreditBalance(INITIAL_JOB_INDEX);
        expect(jobInfo.metadata).to.equal("some metadata");
        expect(jobInfo.owner).to.equal(await user.getAddress());
        expect(jobInfo.provider).to.equal(await provider.getAddress());
        expect(jobInfo.rate).to.equal(JOB_RATE_1);
        expect(jobInfo.balance).to.equal(TOTAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST));
        expect(jobInfo.lastSettled).to.equal(currentTimestamp + NOTICE_PERIOD);
        expect(creditBalance).to.equal(ADDITIONAL_CREDIT_DEPOSIT_AMOUNT);
        
        // User Balance
        const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(INITIAL_DEPOSIT_AMOUNT).sub(ADDITIONAL_USDC_DEPOSIT_AMOUNT).sub(ADDITIONAL_CREDIT_DEPOSIT_AMOUNT);
        expect(await token.balanceOf(addrs[1])).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));
        
        // MarketV1 Balance
        const marketv1BalanceExpected = TOTAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST);
        expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
      });
    
      it("should revert when depositing to job without enough USDC approved", async () => {
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, INITIAL_DEPOSIT_AMOUNT);
        
        // Deposit 30 Credit and 1000 USDC
        await creditToken.connect(user).approve(marketv1.address, ADDITIONAL_CREDIT_DEPOSIT_AMOUNT);
        await expect(marketv1
          .connect(user)
          .jobDeposit(INITIAL_JOB_INDEX, ADDITIONAL_CREDIT_DEPOSIT_AMOUNT.add(SIGNER1_INITIAL_FUND))).to.be.revertedWith("ERC20: insufficient allowance");
      });

      it("should revert when user does not have enough USDC balance", async () => {
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, INITIAL_DEPOSIT_AMOUNT);
        
        // Deposit 30 Credit and 1000 USDC
        await creditToken.connect(user).approve(marketv1.address, ADDITIONAL_CREDIT_DEPOSIT_AMOUNT);
        await token.connect(user).approve(marketv1.address, SIGNER1_INITIAL_FUND);
        await expect(marketv1
          .connect(user)
          .jobDeposit(INITIAL_JOB_INDEX, ADDITIONAL_CREDIT_DEPOSIT_AMOUNT.add(SIGNER1_INITIAL_FUND))).to.be.revertedWith("ERC20: transfer amount exceeds balance");
      });
      
      it("should revert when balance is below notice period cost", async () => {
        // Open Job
        await token.connect(user).approve(marketv1.address, SIGNER1_INITIAL_FUND.add(usdc(1000)));
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, SIGNER1_INITIAL_FUND);
        
        // 100_000 seconds passed (spend 1000 usdc)
        await time.increaseTo(INITIAL_TIMESTAMP + 100_000);
        
        // Deposit 25 USDC
        await expect(marketv1
          .connect(user)
          .jobDeposit(INITIAL_JOB_INDEX, usdc(25))).to.be.revertedWith("insufficient funds to deposit");
      });
    });
  });

  describe("Job Withdraw", function () {
    const TWO_MINUTES = 60 * 2;
    const SEVEN_MINUTES = 60 * 7;

    takeSnapshotBeforeAndAfterEveryTest(async () => { });
    
    describe("USDC Only", function () {
      const INITIAL_DEPOSIT_AMOUNT = usdc(50);
      const NOTICE_PERIOD_COST = calcNoticePeriodCost(JOB_RATE_1);
      const TOTAL_WITHDRAW_AMOUNT = usdc(10);
  
      beforeEach(async () => {
        // Deposit 50 USDC
        await token.connect(user).approve(marketv1.address, INITIAL_DEPOSIT_AMOUNT);
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, INITIAL_DEPOSIT_AMOUNT);
      });

      it("should withdraw from job immediately", async () => {
        const withdrawAmount = usdc(10);
  
        // Job Withdraw
        await marketv1
          .connect(user)
          .jobWithdraw(INITIAL_JOB_INDEX, withdrawAmount);
        
        const currentTimestamp = (await ethers.provider.getBlock('latest')).timestamp;
    
        let jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
        expect(jobInfo.metadata).to.equal("some metadata");
        expect(jobInfo.owner).to.equal(await user.getAddress());
        expect(jobInfo.provider).to.equal(await provider.getAddress());
        expect(jobInfo.rate).to.equal(JOB_RATE_1);
        expect(jobInfo.balance).to.equal(INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(withdrawAmount));
        expect(jobInfo.lastSettled).to.equal(currentTimestamp + NOTICE_PERIOD);
      
        expect(await token.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND.sub(INITIAL_DEPOSIT_AMOUNT).add(withdrawAmount));
        expect(await token.balanceOf(await provider.getAddress())).to.equal(NOTICE_PERIOD_COST);
        expect(await token.balanceOf(marketv1.address)).to.equal(INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(withdrawAmount));
      });
    
      it("should withdraw from job before lastSettled", async () => {
  
        // 2 minutes passed
        await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);
  
        const providerBalanceBefore = await token.balanceOf(await provider.getAddress());
  
        // Job Withdraw
        await marketv1
          .connect(user)
          .jobWithdraw(INITIAL_JOB_INDEX, TOTAL_WITHDRAW_AMOUNT); // withdraw 10 USDC
  
        const SETTLED_AMOUNT = calcAmountToPay(JOB_RATE_1, TWO_MINUTES);
        
        // Job info after Withdrawal
        let jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
        expect(jobInfo.metadata).to.equal("some metadata");
        expect(jobInfo.owner).to.equal(await user.getAddress());
        expect(jobInfo.provider).to.equal(await provider.getAddress());
        expect(jobInfo.rate).to.equal(JOB_RATE_1);
        const jobBalanceExpected = INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(SETTLED_AMOUNT).sub(TOTAL_WITHDRAW_AMOUNT);
        expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));
        expect(jobInfo.lastSettled).to.be.within(INITIAL_TIMESTAMP + FIVE_MINUTES + TWO_MINUTES - 3, INITIAL_TIMESTAMP + FIVE_MINUTES + TWO_MINUTES + 3);
        
        // Check User USDC balance
        const userUSDCBalanceExpected = SIGNER1_INITIAL_FUND.sub(INITIAL_DEPOSIT_AMOUNT).add(TOTAL_WITHDRAW_AMOUNT);
        expect(await token.balanceOf(await user.getAddress())).to.be.within(userUSDCBalanceExpected.sub(JOB_RATE_1), userUSDCBalanceExpected.add(JOB_RATE_1));
  
        // Check Provider USDC balance
        const providerUSDCBalanceExpected = NOTICE_PERIOD_COST.add(SETTLED_AMOUNT);
        expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerUSDCBalanceExpected.sub(JOB_RATE_1), providerUSDCBalanceExpected.add(JOB_RATE_1));
  
        // Check MarketV1 USDC balance
        const marketv1BalanceExpected = INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(SETTLED_AMOUNT);
        expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
      });
    
      it("should withdraw from job after lastSettled with settlement", async () => {
        const settledAmountExpected = calcAmountToPay(JOB_RATE_1, TWO_MINUTES);
  
        // 7 minutes passed after Job Open
        await time.increaseTo(INITIAL_TIMESTAMP + NOTICE_PERIOD + TWO_MINUTES);
        await marketv1
          .connect(user)
          .jobWithdraw(INITIAL_JOB_INDEX, TOTAL_WITHDRAW_AMOUNT);
        
        expect(await token.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND.sub(INITIAL_DEPOSIT_AMOUNT).add(TOTAL_WITHDRAW_AMOUNT));
  
        const providerBalanceExpected = calcNoticePeriodCost(JOB_RATE_1).add(settledAmountExpected);
        expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));
  
        const marketv1BalanceExpected = INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(settledAmountExpected);
        expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
      });
    
      it("should revert when withdrawing from non existent job", async () => {
        const max_uint256_bytes32 = ethers.utils.hexZeroPad(ethers.constants.MaxUint256.toHexString(), 32);
    
        await expect(marketv1
          .connect(user)
          .jobWithdraw(max_uint256_bytes32, usdc(100))).to.be.revertedWith("job not found");
      });
    
      it("should revert when withdrawing from third party job", async () => {
        await expect(marketv1
          .connect(signers[3]) // neither owner nor provider
          .jobWithdraw(INITIAL_JOB_INDEX, usdc(100))).to.be.revertedWith("only job owner");
      });
    
      it("should revert when balance is below notice period cost", async () => {
        // deposited 50 USDC
        // 0.01 USDC/s
        // notice period cost: 0.01 * 300 = 3 USDC
        // 47 USDC left
  
        await time.increaseTo(INITIAL_TIMESTAMP + NOTICE_PERIOD + 4500); // spend 45 USDC (300 + 4500 seconds passed)
  
        await expect(marketv1
          .connect(user)
          .jobWithdraw(INITIAL_JOB_INDEX, usdc(1))).to.be.revertedWith("insufficient funds to withdraw");
      });
    
      it("should revert when withdrawal request amount exceeds max withdrawable amount", async () => {
        // Current balance: 47 USDC
  
        await expect(marketv1
          .connect(user)
          .jobWithdraw(INITIAL_JOB_INDEX, usdc(48))).to.be.revertedWith("withdrawal amount exceeds job balance");
      });
    });

    describe("Credit Only", function () {
      const INITIAL_DEPOSIT_AMOUNT = usdc(50);
      const NOTICE_PERIOD_COST = calcNoticePeriodCost(JOB_RATE_1);
      const CREDIT_WITHDRAW_AMOUNT = usdc(10);
      const TOTAL_WITHDRAW_AMOUNT = usdc(10);

      beforeEach(async () => {
        // Deposit 50 Credit
        await creditToken.connect(user).approve(marketv1.address, INITIAL_DEPOSIT_AMOUNT);
        await marketv1.connect(user).jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, INITIAL_DEPOSIT_AMOUNT);
      });

      it("should withdraw from job immediately", async () => {
        // Job Withdraw
        await marketv1
          .connect(user)
          .jobWithdraw(INITIAL_JOB_INDEX, CREDIT_WITHDRAW_AMOUNT); // withdraw 10 Credit
    
        const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
        const jobCreditBalance = await marketv1.jobCreditBalance(INITIAL_JOB_INDEX);
        const currentTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

        expect(jobInfo.metadata).to.equal("some metadata");
        expect(jobInfo.owner).to.equal(await user.getAddress());
        expect(jobInfo.provider).to.equal(await provider.getAddress());
        expect(jobInfo.rate).to.equal(JOB_RATE_1);
        expect(jobInfo.balance).to.equal(INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(CREDIT_WITHDRAW_AMOUNT));
        expect(jobInfo.lastSettled).to.equal(currentTimestamp + NOTICE_PERIOD);

        expect(jobCreditBalance).to.equal(INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(CREDIT_WITHDRAW_AMOUNT));
        
        // User Balance
        const userCreditBalanceExpected = SIGNER1_INITIAL_FUND.sub(INITIAL_DEPOSIT_AMOUNT).add(CREDIT_WITHDRAW_AMOUNT);
        expect(await creditToken.balanceOf(await user.getAddress())).to.equal(userCreditBalanceExpected);

        // Provider Balance
        const providerCreditBalanceExpected = 0;
        const providerUSDCBalanceExpected = NOTICE_PERIOD_COST;
        expect(await creditToken.balanceOf(await provider.getAddress())).to.equal(providerCreditBalanceExpected);
        expect(await token.balanceOf(await provider.getAddress())).to.equal(providerUSDCBalanceExpected);

        const marketv1CreditBalanceExpected = INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(CREDIT_WITHDRAW_AMOUNT);
        expect(await creditToken.balanceOf(marketv1.address)).to.equal(marketv1CreditBalanceExpected);
      });
    
      it("should withdraw from job before lastSettled", async () => {
        // 2 minutes passed
        await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);
        const SETTLED_AMOUNT = calcAmountToPay(JOB_RATE_1, TWO_MINUTES);
  
        // Job Withdraw
        await marketv1
          .connect(user)
          .jobWithdraw(INITIAL_JOB_INDEX, CREDIT_WITHDRAW_AMOUNT); // withdraw 10 Credit
        
        // Job info after Withdrawal
        let jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
        const jobCreditBalance = await marketv1.jobCreditBalance(INITIAL_JOB_INDEX);
        expect(jobInfo.metadata).to.equal("some metadata");
        expect(jobInfo.owner).to.equal(await user.getAddress());
        expect(jobInfo.provider).to.equal(await provider.getAddress());
        expect(jobInfo.rate).to.equal(JOB_RATE_1);
        const jobBalanceExpected = INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(SETTLED_AMOUNT).sub(TOTAL_WITHDRAW_AMOUNT);
        expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));
        expect(jobInfo.lastSettled).to.be.within(INITIAL_TIMESTAMP + FIVE_MINUTES + TWO_MINUTES - 3, INITIAL_TIMESTAMP + FIVE_MINUTES + TWO_MINUTES + 3);
        
        const jobCreditBalanceExpected = INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(SETTLED_AMOUNT).sub(TOTAL_WITHDRAW_AMOUNT);
        expect(jobCreditBalance).to.be.within(jobCreditBalanceExpected.sub(JOB_RATE_1), jobCreditBalanceExpected.add(JOB_RATE_1));
        
        // User Balance
        const userCreditBalanceExpected = SIGNER1_INITIAL_FUND.sub(INITIAL_DEPOSIT_AMOUNT).add(TOTAL_WITHDRAW_AMOUNT);
        const userUSDCBalanceExpected = 0;
        expect(await creditToken.balanceOf(await user.getAddress())).to.equal(userCreditBalanceExpected);
        expect(await token.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND);

        // Provider Balance
        const providerCreditBalanceExpected = 0;
        const providerUSDCBalanceExpected = NOTICE_PERIOD_COST.add(SETTLED_AMOUNT);
        expect(await creditToken.balanceOf(await provider.getAddress())).to.equal(providerCreditBalanceExpected);
        expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerUSDCBalanceExpected.sub(JOB_RATE_1), providerUSDCBalanceExpected.add(JOB_RATE_1));
  
        // Check MarketV1 USDC balance
        const marketv1CreditBalanceExpected = INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(SETTLED_AMOUNT).sub(TOTAL_WITHDRAW_AMOUNT);
        const marketv1USDCBalanceExpected = 0;
        expect(await creditToken.balanceOf(marketv1.address)).to.be.within(marketv1CreditBalanceExpected.sub(JOB_RATE_1), marketv1CreditBalanceExpected.add(JOB_RATE_1));
        expect(await token.balanceOf(marketv1.address)).to.equal(marketv1USDCBalanceExpected);
      });
    
      it("should withdraw from job after lastSettled with settlement", async () => {
        const settledAmountExpected = calcAmountToPay(JOB_RATE_1, SEVEN_MINUTES);
  
        // 7 minutes passed after Job Open
        await time.increaseTo(INITIAL_TIMESTAMP + SEVEN_MINUTES);
        await marketv1
          .connect(user)
          .jobWithdraw(INITIAL_JOB_INDEX, TOTAL_WITHDRAW_AMOUNT);
        
        
        // User Balance
        const userCreditBalanceExpected = SIGNER1_INITIAL_FUND.sub(INITIAL_DEPOSIT_AMOUNT).add(TOTAL_WITHDRAW_AMOUNT);
        const userUSDCBalanceExpected = SIGNER1_INITIAL_FUND;
        expect(await creditToken.balanceOf(await user.getAddress())).to.equal(userCreditBalanceExpected);
        expect(await token.balanceOf(await user.getAddress())).to.equal(userUSDCBalanceExpected);
  
        // Provider Balance
        const providerCreditBalanceExpected = 0;
        const providerUSDCBalanceExpected = NOTICE_PERIOD_COST.add(settledAmountExpected);
        expect(await creditToken.balanceOf(await provider.getAddress())).to.equal(providerCreditBalanceExpected);
        expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerUSDCBalanceExpected.sub(JOB_RATE_1), providerUSDCBalanceExpected.add(JOB_RATE_1));

        // Check MarketV1 Balance
        const marketv1CreditBalanceExpected = INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(settledAmountExpected).sub(TOTAL_WITHDRAW_AMOUNT);
        const marketv1USDCBalanceExpected = 0;
        expect(await creditToken.balanceOf(marketv1.address)).to.be.within(marketv1CreditBalanceExpected.sub(JOB_RATE_1), marketv1CreditBalanceExpected.add(JOB_RATE_1));
        expect(await token.balanceOf(marketv1.address)).to.equal(marketv1USDCBalanceExpected);
      });
    });

    describe("Both Credit and USDC", function () {
      const INITIAL_DEPOSIT_AMOUNT = usdc(50);
      const INITIAL_CREDIT_DEPOSIT_AMOUNT = usdc(40);
      const NOTICE_PERIOD_COST = calcNoticePeriodCost(JOB_RATE_1);
      const TOTAL_WITHDRAW_AMOUNT = usdc(20); // 13 USDC + 7 Credit

      beforeEach(async () => {
        // Deposit 10 Credit, 40 USDC
        await creditToken.connect(user).approve(marketv1.address, INITIAL_CREDIT_DEPOSIT_AMOUNT);
        await marketv1.connect(user).jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, INITIAL_DEPOSIT_AMOUNT);
      });

      it("should withdraw only USDC", async () => {
        const userCreditBalanceBefore = await creditToken.balanceOf(await user.getAddress());
        const userUSDCBalanceBefore = await token.balanceOf(await user.getAddress());

        const USDC_WITHDRAWAL_AMOUNT = usdc(5);

        // Job Withdraw
        await marketv1
          .connect(user)
          .jobWithdraw(INITIAL_JOB_INDEX, USDC_WITHDRAWAL_AMOUNT); // withdraw 5 usdc

        // Job Info
        const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
        const jobCreditBalance = await marketv1.jobCreditBalance(INITIAL_JOB_INDEX);
        const currentTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

        expect(jobInfo.metadata).to.equal("some metadata");
        expect(jobInfo.owner).to.equal(await user.getAddress());
        expect(jobInfo.provider).to.equal(await provider.getAddress());
        expect(jobInfo.rate).to.equal(JOB_RATE_1);
        const jobBalanceExpected = INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(TOTAL_WITHDRAW_AMOUNT);
        expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));
        expect(jobInfo.lastSettled).to.equal(currentTimestamp + NOTICE_PERIOD);
        const jobCreditBalanceExpected = INITIAL_CREDIT_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST);
        expect(jobCreditBalance).to.equal(jobCreditBalanceExpected);
        
        // User Balance
        const userCreditBalanceExpected = userCreditBalanceBefore;
        const userUSDCBalanceExpected = userUSDCBalanceBefore.sub(USDC_WITHDRAWAL_AMOUNT);
        expect(await creditToken.balanceOf(await user.getAddress())).to.equal(userCreditBalanceExpected);
        expect(await token.balanceOf(await user.getAddress())).to.be.within(userUSDCBalanceExpected.sub(JOB_RATE_1), userUSDCBalanceExpected.add(JOB_RATE_1));

        // Provider Balance
        const providerCreditBalanceExpected = 0;
        const providerUSDCBalanceExpected = NOTICE_PERIOD_COST;
        expect(await creditToken.balanceOf(await provider.getAddress())).to.equal(providerCreditBalanceExpected);
        expect(await token.balanceOf(await provider.getAddress())).to.equal(providerUSDCBalanceExpected);

        const marketv1CreditBalanceExpected = INITIAL_CREDIT_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST);
        const marketv1USDCBalanceExpected = INITIAL_DEPOSIT_AMOUNT.sub(INITIAL_CREDIT_DEPOSIT_AMOUNT).sub(USDC_WITHDRAWAL_AMOUNT);
        expect(await creditToken.balanceOf(marketv1.address)).to.be.within(marketv1CreditBalanceExpected.sub(JOB_RATE_1), marketv1CreditBalanceExpected.add(JOB_RATE_1));
        expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1USDCBalanceExpected.sub(JOB_RATE_1), marketv1USDCBalanceExpected.add(JOB_RATE_1));
      });
    
      it("should withdraw both USDC and Credit", async () => {
        const userCreditBalanceBefore = await creditToken.balanceOf(await user.getAddress());
        const userUSDCBalanceBefore = await token.balanceOf(await user.getAddress());

        const withdrawnUSDCAmountExpected = ((await marketv1.jobs(INITIAL_JOB_INDEX)).balance).sub(await marketv1.jobCreditBalance(INITIAL_JOB_INDEX));
        const withdrawnCreditAmountExpected = TOTAL_WITHDRAW_AMOUNT.sub(withdrawnUSDCAmountExpected);
        // Job Withdraw
        await marketv1
          .connect(user)
          .jobWithdraw(INITIAL_JOB_INDEX, TOTAL_WITHDRAW_AMOUNT); // withdraw 20 (13 USDC + 7 Credit)

        const currentTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

        // Job Info
        const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
        const jobCreditBalance = await marketv1.jobCreditBalance(INITIAL_JOB_INDEX);
        expect(jobInfo.metadata).to.equal("some metadata");
        expect(jobInfo.owner).to.equal(await user.getAddress());
        expect(jobInfo.provider).to.equal(await provider.getAddress());
        expect(jobInfo.rate).to.equal(JOB_RATE_1);
        const jobBalanceExpected = INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(TOTAL_WITHDRAW_AMOUNT);
        expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));
        expect(jobInfo.lastSettled).to.equal(currentTimestamp + NOTICE_PERIOD);
        expect(jobCreditBalance).to.equal(INITIAL_CREDIT_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(withdrawnCreditAmountExpected));
        
        // User Balance
        const userCreditBalanceExpected = userCreditBalanceBefore.add(withdrawnCreditAmountExpected);
        const userUSDCBalanceExpected = userUSDCBalanceBefore.add(withdrawnUSDCAmountExpected);
        expect(await creditToken.balanceOf(await user.getAddress())).to.equal(userCreditBalanceExpected);
        expect(await token.balanceOf(await user.getAddress())).to.equal(userUSDCBalanceExpected);

        // Provider Balance
        const providerCreditBalanceExpected = 0;
        const providerUSDCBalanceExpected = NOTICE_PERIOD_COST;
        expect(await creditToken.balanceOf(await provider.getAddress())).to.equal(providerCreditBalanceExpected);
        expect(await token.balanceOf(await provider.getAddress())).to.equal(providerUSDCBalanceExpected);

        // MarketV1 Balance
        const marketv1CreditBalanceExpected = INITIAL_CREDIT_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST).sub(withdrawnCreditAmountExpected);
        expect(await creditToken.balanceOf(marketv1.address)).to.equal(marketv1CreditBalanceExpected);
        expect(await token.balanceOf(marketv1.address)).to.equal(0);
      });
    });
  });

  describe("Job Revise Rate", function () {
    const JOB_LOWER_RATE = BN.from(5).e16().div(10);
    const JOB_HIGHER_RATE = BN.from(2).e16();

    const initialDeposit = usdc(50);
    const initialBalance = initialDeposit.sub(calcNoticePeriodCost(JOB_RATE_1));

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    beforeEach(async () => {
      await token.connect(user).approve(marketv1.address, initialDeposit);
      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
    });

    it("should revise rate higher", async () => {
      const currentTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

      await marketv1
        .connect(user)
        .jobReviseRate(INITIAL_JOB_INDEX, JOB_HIGHER_RATE);
      
      const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
      expect(jobInfo.rate).to.equal(JOB_HIGHER_RATE);
      expect(jobInfo.balance).to.equal(initialBalance);

      expect(jobInfo.lastSettled).to.equal(currentTimestamp + FIVE_MINUTES);
      expect(await token.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND.sub(initialDeposit));
      expect(await token.balanceOf(await provider.getAddress())).to.equal(calcNoticePeriodCost(JOB_RATE_1));
      expect(await token.balanceOf(marketv1.address)).to.equal(initialBalance);
    });

    it("should revise rate lower", async () => {
      const currentTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

      await marketv1
        .connect(user)
        .jobReviseRate(INITIAL_JOB_INDEX, JOB_LOWER_RATE);

      const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
      expect(jobInfo.rate).to.equal(JOB_LOWER_RATE);
      expect(jobInfo.balance).to.equal(initialBalance);
      expect(jobInfo.lastSettled).to.equal(currentTimestamp + FIVE_MINUTES);
      expect(await token.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND.sub(initialDeposit));
      expect(await token.balanceOf(await provider.getAddress())).to.equal(calcNoticePeriodCost(JOB_RATE_1));
      expect(await token.balanceOf(marketv1.address)).to.equal(initialBalance);
    });

    it("should revert when initiating rate revision for non existent job", async () => {
      await expect(marketv1
        .connect(user)
        .jobReviseRate(ethers.utils.hexZeroPad("0x01", 32), JOB_HIGHER_RATE)).to.be.revertedWith("job not found");
    });

    it("should revert when initiating rate revision for third party job", async () => {
      await expect(marketv1
        .connect(signers[3]) // neither owner nor provider
        .jobReviseRate(INITIAL_JOB_INDEX, JOB_HIGHER_RATE)).to.be.revertedWith("only job owner");
    });

    const HIGHER_RATE = BN.from(2).e16(); // 0.02 USDC/s
    const LOWER_RATE = BN.from(5).e15(); // 0.005 USDC/s
    
    describe("CASE 1: Revising Rate immediately after job open", function () {

      describe("when rate is higher", function () {

        it("should spend notice period cost only", async () => {
          const noticePeriodCostExpected = calcNoticePeriodCost(JOB_RATE_1);

          await marketv1
            .connect(user)
            .jobReviseRate(INITIAL_JOB_INDEX, HIGHER_RATE);

          // Job info after Rate Revision
          const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
          expect(jobInfo.rate).to.equal(HIGHER_RATE);
          const jobBalanceExpected = initialBalance.sub(noticePeriodCostExpected);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit).sub(noticePeriodCostExpected);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = noticePeriodCostExpected;
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });

      describe("when rate is lower", function () {
        it("should spend notice period cost only", async () => {
          const noticePeriodCostExpected = calcNoticePeriodCost(JOB_RATE_1);
  
          await marketv1
            .connect(user)
            .jobReviseRate(INITIAL_JOB_INDEX, LOWER_RATE);
          
          // Job info after Rate Revision
          const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
          expect(jobInfo.rate).to.equal(LOWER_RATE);
          const jobBalanceExpected = initialDeposit.sub(noticePeriodCostExpected);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));
  
          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(noticePeriodCostExpected);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = noticePeriodCostExpected;
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });
    });

    describe("CASE 2: Revising Rate 2 minutes after job open", function () {
      const TWO_MINUTES = 60 * 2;
      const SEVEN_MINUTES = 60 * 7;

      describe("when rate is higher", function () {
        it("should spend notice period cost + 3 minutes worth tokens with higher rate", async () => {
          // 5 min * initial rate + 3 min * higher rate
          const usdcSpentExpected = calcNoticePeriodCost(JOB_RATE_1).add(calcAmountToPay(HIGHER_RATE, TWO_MINUTES));
          const initialTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

          await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);

          await marketv1
            .connect(user)
            .jobReviseRate(INITIAL_JOB_INDEX, HIGHER_RATE);
            
          const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
          expect(jobInfo.rate).to.equal(HIGHER_RATE);

          const jobBalanceExpected = initialDeposit.sub(usdcSpentExpected);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const lastSettledTimestampExpected = (await ethers.provider.getBlock('latest')).timestamp + FIVE_MINUTES;
          expect(jobInfo.lastSettled).to.be.within(lastSettledTimestampExpected - 3, lastSettledTimestampExpected + 3);

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit).sub(usdcSpentExpected);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = usdcSpentExpected;
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });

      describe("when rate is lower", function () {
        it("should spend notice period cost + 3 minutes worth tokens with initial rate", async () => {
          // 5 min * initial rate + 3 min * initial rate
          const usdcSpentExpected = calcNoticePeriodCost(JOB_RATE_1).add(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
          const initialTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

          await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);

          await marketv1
            .connect(user)
            .jobReviseRate(INITIAL_JOB_INDEX, LOWER_RATE);
          
          const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
          expect(jobInfo.rate).to.equal(LOWER_RATE);

          const jobBalanceExpected = initialDeposit.sub(usdcSpentExpected);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const lastSettledTimestampExpected = (await ethers.provider.getBlock('latest')).timestamp + FIVE_MINUTES;
          expect(jobInfo.lastSettled).to.be.within(lastSettledTimestampExpected - 3, lastSettledTimestampExpected + 3);

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit).sub(usdcSpentExpected);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = usdcSpentExpected;
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });
    });

    describe("CASE 3: Revising Rate exactly after notice period", function () {
      const TEN_MINUTES = 60 * 10;

      describe("when rate is higher", function () {
        it("should spend 5 minutes worth tokens with initial rate and 5 minutes worth tokens with higher rate", async () => {
          const initialTimestamp = (await ethers.provider.getBlock('latest')).timestamp;
          const firstNoticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);
          const secondNoticePeriodCost = calcNoticePeriodCost(HIGHER_RATE);

          await time.increaseTo(INITIAL_TIMESTAMP + NOTICE_PERIOD);

          await marketv1
            .connect(user)
            .jobReviseRate(INITIAL_JOB_INDEX, HIGHER_RATE);
            
          const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
          expect(jobInfo.rate).to.equal(HIGHER_RATE);

          const jobBalanceExpected = initialDeposit.sub(firstNoticePeriodCost).sub(secondNoticePeriodCost);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const lastSettledTimestampExpected = (await ethers.provider.getBlock('latest')).timestamp + FIVE_MINUTES;
          expect(jobInfo.lastSettled).to.be.within(lastSettledTimestampExpected - 3, lastSettledTimestampExpected + 3);

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = firstNoticePeriodCost.add(secondNoticePeriodCost);
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });

      describe("when rate is lower", function () {
        it("should spend 5 minutes worth tokens with initial rate and 5 minutes worth tokens with initial rate", async () => {
          const initialTimestamp = (await ethers.provider.getBlock('latest')).timestamp;
          const firstNoticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);
          const secondNoticePeriodCost = calcNoticePeriodCost(LOWER_RATE);

          await time.increaseTo(INITIAL_TIMESTAMP + NOTICE_PERIOD);

          await marketv1
            .connect(user)
            .jobReviseRate(INITIAL_JOB_INDEX, LOWER_RATE);

          const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
          expect(jobInfo.rate).to.equal(LOWER_RATE);

          const jobBalanceExpected = initialDeposit.sub(firstNoticePeriodCost).sub(secondNoticePeriodCost);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const lastSettledTimestampExpected = (await ethers.provider.getBlock('latest')).timestamp + FIVE_MINUTES;
          expect(jobInfo.lastSettled).to.be.within(lastSettledTimestampExpected - 3, lastSettledTimestampExpected + 3);

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = firstNoticePeriodCost.add(secondNoticePeriodCost);
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });
    });

    describe("CASE 4: Revising Rate 2 minutes after notice period", function () {
      const TWO_MINUTES = 60 * 2;
      const TWELVE_MINUTES = 60 * 12;

      describe("when rate is higher", function () {
        it("should spend 7 minutes worth tokens with initial rate and 5 minutes worth tokens with higher rate", async () => {
          const initialTimestamp = (await ethers.provider.getBlock('latest')).timestamp;
          const firstNoticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);
          const secondNoticePeriodCost = calcNoticePeriodCost(HIGHER_RATE);

          await time.increaseTo(INITIAL_TIMESTAMP + NOTICE_PERIOD + TWO_MINUTES);

          await marketv1
            .connect(user)
            .jobReviseRate(INITIAL_JOB_INDEX, HIGHER_RATE);

          const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
          expect(jobInfo.rate).to.equal(HIGHER_RATE);

          const jobBalanceExpected = initialDeposit.sub(firstNoticePeriodCost).sub(secondNoticePeriodCost);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const lastSettledTimestampExpected = (await ethers.provider.getBlock('latest')).timestamp + FIVE_MINUTES;
          expect(jobInfo.lastSettled).to.be.within(lastSettledTimestampExpected - 3, lastSettledTimestampExpected + 3);
          
          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = firstNoticePeriodCost.add(secondNoticePeriodCost);
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });

      describe("when rate is lower", function () {
        it("should spend 7 minutes worth tokens with initial rate and 5 minutes worth tokens with initial rate", async () => {
          const initialTimestamp = (await ethers.provider.getBlock('latest')).timestamp;
          const firstNoticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);
          const secondNoticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);

          await time.increaseTo(INITIAL_TIMESTAMP + NOTICE_PERIOD + TWO_MINUTES);

          await marketv1
            .connect(user)
            .jobReviseRate(INITIAL_JOB_INDEX, LOWER_RATE);

          const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
          expect(jobInfo.rate).to.equal(LOWER_RATE);

          const jobBalanceExpected = initialDeposit.sub(firstNoticePeriodCost).sub(secondNoticePeriodCost);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const lastSettledTimestampExpected = (await ethers.provider.getBlock('latest')).timestamp + FIVE_MINUTES;
          expect(jobInfo.lastSettled).to.be.within(lastSettledTimestampExpected - 3, lastSettledTimestampExpected + 3);

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = firstNoticePeriodCost.add(secondNoticePeriodCost);
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await token.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });
    });
  });

  describe("Job Close", function () {
    const initialDeposit = usdc(50);
    const initialBalance = initialDeposit.sub(calcNoticePeriodCost(JOB_RATE_1));

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    describe("USDC Only", function () {
      beforeEach(async () => {
        await token.connect(user).approve(marketv1.address, initialDeposit);
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
      });
  
      it("should close job", async () => {
        // Job Close
        await marketv1
          .connect(user)
          .jobClose(INITIAL_JOB_INDEX); // here, user should get back (initial deposit - notice period cost)
  
        const jobInfo = await marketv1.jobs(INITIAL_JOB_INDEX);
        expect(jobInfo.metadata).to.equal("");
        expect(jobInfo.owner).to.equal(ethers.constants.AddressZero);
        expect(jobInfo.provider).to.equal(ethers.constants.AddressZero);
        expect(jobInfo.rate).to.equal(0);
        expect(jobInfo.balance).to.equal(0);
        expect(jobInfo.lastSettled).to.equal(0);
      
        const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit).sub(calcNoticePeriodCost(JOB_RATE_1));
        expect(await token.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));
      });
  
      it("should revert when closing non existent job", async () => {
        await expect(marketv1
          .connect(user)
          .jobClose(ethers.utils.hexZeroPad("0x01", 32))).to.be.revertedWith("job not found");
      });
  
      it("should revert when closing third party job", async () => {
        await expect(marketv1
          .connect(signers[3]) // neither owner nor provider
          .jobClose(INITIAL_JOB_INDEX)).to.be.revertedWith("only job owner");
      });
  
      describe("Scenario 1: Closing Job immediately after opening", function () {
        it("should spend notice period cost only", async () => {
          await marketv1
            .connect(user)
            .jobClose(INITIAL_JOB_INDEX);
  
          const noticePeriodCostExpected = calcNoticePeriodCost(JOB_RATE_1);
  
          // user balance after = initial fund - notice period cost
          expect(await token.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND.sub(noticePeriodCostExpected));
          // provider balance after = notice period cost
          expect(await token.balanceOf(await provider.getAddress())).to.equal(noticePeriodCostExpected);
          // marketv1 balance after = 0
          expect(await token.balanceOf(marketv1.address)).to.equal(0);
        });
      });
  
      describe("Scenario 2: Closing Job 2 minutes after opening (before notice period)", function () {
        it("should spend notice period cost only", async () => {
          const TWO_MINUTES = 60 * 2;
  
          await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);
  
          await marketv1
            .connect(user)
            .jobClose(INITIAL_JOB_INDEX);
        
          const noticePeriodCostExpected = calcNoticePeriodCost(JOB_RATE_1);
  
          // user balance after = initial fund - 3 minutes worth tokens - notice period cost
          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(usdc(TWO_MINUTES)).sub(noticePeriodCostExpected);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));
        
          // provider balance after = 2 minutes worth tokens + notice period cost
          const providerBalanceExpected = usdc(TWO_MINUTES).add(noticePeriodCostExpected);
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));
  
          // marketv1 balance after = 0
          expect(await token.balanceOf(marketv1.address)).to.equal(0);
        });
      });
  
      describe("Scenario 3: Closing Job exactly after notice period", function () {
        it("should spend 10 minutes worth tokens", async () => {
          const usdcSpentExpected = calcAmountToPay(JOB_RATE_1, FIVE_MINUTES).add(calcNoticePeriodCost(JOB_RATE_1));
  
          await time.increaseTo(INITIAL_TIMESTAMP + NOTICE_PERIOD);
  
          await marketv1
            .connect(user)
            .jobClose(INITIAL_JOB_INDEX);
        
          // user balance after = initial fund - 5 minutes worth tokens - notice period cost
          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(usdcSpentExpected);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));
  
          // provider balance after = 5 minutes worth tokens + notice period cost
          const providerBalanceExpected = usdcSpentExpected;
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));
  
          expect(await token.balanceOf(marketv1.address)).to.equal(0);
        });
      });
  
      describe("Scenario 4: Closing Job 2 minutes after notice period", function () {
        it("should spend 12 minutes worth tokens", async () => {
          const SEVEN_MINUTES = 60 * 7;
          const usdcSpentExpected = calcAmountToPay(JOB_RATE_1, SEVEN_MINUTES).add(calcNoticePeriodCost(JOB_RATE_1));
  
          await time.increaseTo(INITIAL_TIMESTAMP + NOTICE_PERIOD + SEVEN_MINUTES);
  
          await marketv1
            .connect(user)
            .jobClose(INITIAL_JOB_INDEX);
  
          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(usdcSpentExpected);
          expect(await token.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));
  
          const providerBalanceExpected = usdcSpentExpected;
          expect(await token.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));
        
          expect(await token.balanceOf(marketv1.address)).to.equal(0);
        });
      });
    });

    describe("Credit Only", function () {
      const INITIAL_DEPOSIT_AMOUNT = usdc(50);
      const NOTICE_PERIOD_COST = calcNoticePeriodCost(JOB_RATE_1);

      beforeEach(async () => {
        // Deposit 50 Credit
        await creditToken.connect(user).approve(marketv1.address, INITIAL_DEPOSIT_AMOUNT);
        await marketv1.connect(user).jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, INITIAL_DEPOSIT_AMOUNT);
      });

      it("should close job and withdraw all credit", async () => {
        expect(await marketv1.jobCreditBalance(INITIAL_JOB_INDEX)).to.equal(INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST));
        const userCreditBalanceBefore = await creditToken.balanceOf(await user.getAddress());
        const userUSDCBalanceBefore = await token.balanceOf(await user.getAddress());

        // Close job
        await marketv1.connect(user).jobClose(INITIAL_JOB_INDEX);

        const userCreditBalanceExpected = userCreditBalanceBefore.add(INITIAL_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST));
        const userUSDCBalanceExpected = userUSDCBalanceBefore;
        expect(await creditToken.balanceOf(await user.getAddress())).to.equal(userCreditBalanceExpected);
        expect(await token.balanceOf(await user.getAddress())).to.equal(userUSDCBalanceExpected);
      });
    });

    describe("Both Credit and USDC", function () {
      const INITIAL_DEPOSIT_AMOUNT = usdc(50);
      const INITIAL_CREDIT_DEPOSIT_AMOUNT = usdc(40);
      const NOTICE_PERIOD_COST = calcNoticePeriodCost(JOB_RATE_1);

      beforeEach(async () => {
        // Deposit 40 Credit, 10 USDC
        await creditToken.connect(user).approve(marketv1.address, INITIAL_CREDIT_DEPOSIT_AMOUNT);
        await marketv1.connect(user).jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, INITIAL_DEPOSIT_AMOUNT);
      });

      it("should close job and withdraw all Credit and USDC", async () => {
        const userCreditBalanceBefore = await creditToken.balanceOf(await user.getAddress());
        const userUSDCBalanceBefore = await token.balanceOf(await user.getAddress());

        // Close job
        await marketv1.connect(user).jobClose(INITIAL_JOB_INDEX);

        const userCreditBalanceExpected = userCreditBalanceBefore.add(INITIAL_CREDIT_DEPOSIT_AMOUNT.sub(NOTICE_PERIOD_COST));
        const userUSDCBalanceExpected = userUSDCBalanceBefore.add(INITIAL_DEPOSIT_AMOUNT.sub(INITIAL_CREDIT_DEPOSIT_AMOUNT));
        expect(await creditToken.balanceOf(await user.getAddress())).to.be.within(userCreditBalanceExpected.sub(JOB_RATE_1), userCreditBalanceExpected.add(JOB_RATE_1));
        expect(await token.balanceOf(await user.getAddress())).to.be.within(userUSDCBalanceExpected.sub(JOB_RATE_1), userUSDCBalanceExpected.add(JOB_RATE_1));
      });
    });
  });

  describe("Metdata Update", function () {
    const initialDeposit = usdc(50);

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    beforeEach(async () => {
      await token.connect(user).approve(marketv1.address, initialDeposit);
      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
    });

    it("should update metadata", async () => {
      await marketv1
        .connect(user)
        .jobMetadataUpdate(INITIAL_JOB_INDEX, "some updated metadata");

      const jobInfo2 = await marketv1.jobs(INITIAL_JOB_INDEX);
      expect(jobInfo2.metadata).to.equal("some updated metadata");
    });

    it("should revert when updating metadata of other jobs", async () => {
      await expect(marketv1
        .connect(signers[3]) // neither owner nor provider
        .jobMetadataUpdate(INITIAL_JOB_INDEX, "some updated metadata")).to.be.revertedWith("only job owner");
    });
  });

  describe("Emergency Withdraw", function () {
    const NUM_TOTAL_JOB = 5;
    const INITIAL_DEPOSIT_AMOUNT = usdc(50);
    let TOTAL_DEPOSIT_AMOUNT = BN.from(0);
    let jobs: string[] = [];
    let deposits: BN[] = [];
    
    beforeEach(async () => {
      await marketv1.connect(admin).grantRole(await marketv1.EMERGENCY_WITHDRAW_ROLE(), await admin2.getAddress());

      // open 5 jobs
      for (let i = 0; i < NUM_TOTAL_JOB; i++) {
        const EXTRA_DEPOSIT_AMOUNT = usdc(i * 10);
        const DEPOSIT_AMOUNT = INITIAL_DEPOSIT_AMOUNT.add(EXTRA_DEPOSIT_AMOUNT);
        
        // list of jobs and deposits
        jobs.push(await marketv1.jobIndex());
        deposits.push(DEPOSIT_AMOUNT);
        // total credit deposit amount
        TOTAL_DEPOSIT_AMOUNT = TOTAL_DEPOSIT_AMOUNT.add(DEPOSIT_AMOUNT);

        // open job only with credit
        await creditToken.connect(user).approve(marketv1.address, DEPOSIT_AMOUNT);
        await marketv1.connect(user).jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, DEPOSIT_AMOUNT);
      }
    });

    it("should revert when withdrawing to address without EMERGENCY_WITHDRAW_ROLE", async () => {
      await expect(marketv1
        .connect(admin)
        .emergencyWithdrawCredit(await user.getAddress(), [INITIAL_JOB_INDEX])).to.be.revertedWith("only to emergency withdraw role");
    });

    it("should revert when non-admin calls emergencyWithdrawCredit", async () => {
      await expect(marketv1
        .connect(user)
        .emergencyWithdrawCredit(await user.getAddress(), jobs)).to.be.revertedWith("only admin");
    });
    
    it("should settle all jobs and withdraw all credit", async () => {
      const totalSettledAmountExpected = calcNoticePeriodCost(JOB_RATE_1).mul(NUM_TOTAL_JOB);

      await marketv1.connect(admin).emergencyWithdrawCredit(await admin2.getAddress(), jobs);

      const CURRENT_TIMESTAMP = (await ethers.provider.getBlock('latest')).timestamp;
      for (let i = 0; i < NUM_TOTAL_JOB; i++) {
        // fetch job info
        const jobInfo = await marketv1.jobs(jobs[i]);
        
        // should settle all jobs
        expect(jobInfo.lastSettled).to.equal((CURRENT_TIMESTAMP + NOTICE_PERIOD).toString());
        
        // job credit balance should be 0
        expect(await marketv1.jobCreditBalance(jobs[i])).to.equal(0);
      }

      // withdrawal recipient
      const withdrawalAmountExpected = TOTAL_DEPOSIT_AMOUNT.sub(totalSettledAmountExpected);
      expect(await creditToken.balanceOf(await admin2.getAddress())).to.be.within(withdrawalAmountExpected.sub(JOB_RATE_1), withdrawalAmountExpected.add(JOB_RATE_1));

      // Provider
      expect(await token.balanceOf(await provider.getAddress())).to.be.within(totalSettledAmountExpected.sub(JOB_RATE_1), totalSettledAmountExpected.add(JOB_RATE_1));

      // MarketV1
      expect(await creditToken.balanceOf(marketv1.address)).to.equal(0);
    });
  })
});
  
  



