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

import { MarketV1 } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { getMarketV1 } from "../../utils/typechainConvertor";
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
const SHUTDOWN_DELAY = FIVE_MINUTES;
const SIGNER1_INITIAL_FUND = BN.from(1000).e6(); // 1000 USDC
const INITIAL_TIMESTAMP = Math.floor(Date.now() / 1000) + 86400;

const JOB_RATE_1 = BN.from(1).e16();

const calcShutdownDelayCost = (rate: BN) => {
	return calcAmountToPay(rate, SHUTDOWN_DELAY);
};

const calcAmountToPay = (rate: BN, duration: number) => {
  return rate.mul(BN.from(duration)).add(10 ** 12 - 1).div(10 ** 12);
}

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

describe("MarketV1", function () {
  let signers: Signer[];
  let addrs: string[];
  let marketv1: MarketV1;
  let pond: Contract;

  let user: Signer;
  let provider: Signer;

  before(async function () {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    user = signers[1];
    provider = signers[2];
    
    const Pond = await ethers.getContractFactory("Pond");
    pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
      kind: "uups",
      unsafeAllow: ["missing-initializer-call"],
    });
    await pond.transfer(addrs[1], SIGNER1_INITIAL_FUND);
    
    const MarketV1 = await ethers.getContractFactory("MarketV1");
    const marketv1Contract = await upgrades.deployProxy(
      MarketV1,
      [addrs[0], pond.address, SELECTORS, WAIT_TIMES],
      { kind: "uups", unsafeAllow: ["missing-initializer-call"] },
    );
    marketv1 = getMarketV1(marketv1Contract.address, signers[0]);
    await pond.connect(user).approve(marketv1.address, usdc(100));

    await marketv1.updateShutdownDelay(FIVE_MINUTES);

    await time.increaseTo(INITIAL_TIMESTAMP);
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
  
    it("should open job", async () => {
      const initialBalance = usdc(50);
      const shutdownDelayCost = calcShutdownDelayCost(JOB_RATE_1);

      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialBalance);
  
      const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
      expect(jobInfo.metadata).to.equal("some metadata");
      expect(jobInfo.owner).to.equal(await user.getAddress());
      expect(jobInfo.provider).to.equal(await provider.getAddress());
      expect(jobInfo.rate).to.equal(JOB_RATE_1);
      expect(jobInfo.balance).to.equal(initialBalance.sub(shutdownDelayCost));
      expect(jobInfo.paymentSettledTimestamp).to.be.within(INITIAL_TIMESTAMP + FIVE_MINUTES, INITIAL_TIMESTAMP + FIVE_MINUTES + 1);
  
      expect(await pond.balanceOf(addrs[1])).to.equal(SIGNER1_INITIAL_FUND.sub(initialBalance));
      expect(await pond.balanceOf(marketv1.address)).to.equal(initialBalance.sub(shutdownDelayCost));
    });
  
    it("should revert when opening job without enough approved", async () => {
      await expect(
        marketv1.connect(signers[1]).jobOpen("some metadata", addrs[2], JOB_RATE_1, usdc(150)), // 100 USDC approved
      ).to.be.revertedWith("ERC20: insufficient allowance");
    });
  
    it("should revert when opening job without enough balance", async () => {
      await pond.connect(signers[1]).approve(marketv1.address, usdc(5000));
      await expect(
        marketv1.connect(signers[1]).jobOpen("some metadata", addrs[2], JOB_RATE_1, usdc(5000)),
      ).to.be.revertedWith("ERC20: transfer amount exceeds balance");
    });
  });

  describe("Job Settle", function () {
    const initialDeposit = usdc(50);
    const initialBalance = initialDeposit.sub(calcShutdownDelayCost(JOB_RATE_1));

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    beforeEach(async () => {
      await pond.connect(user).approve(marketv1.address, initialDeposit);
      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
    });
  
    describe("CASE1: Settle Job immediately after Job Open", function () {
      it("should revert before paymentSettledTimestamp", async () => {
        await expect(marketv1.connect(user).jobSettle(ethers.constants.HashZero)).to.be.revertedWith("nothing to settle before paymentSettledTimestamp");
      });
    });

    describe("CASE2: Settle Job 2 minutes after Job Open", function () {
      it("should revert before paymentSettledTimestamp", async () => {
        const TWO_MINUTES = 60 * 2;
        await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);

        await expect(marketv1.connect(user).jobSettle(ethers.constants.HashZero)).to.be.revertedWith("nothing to settle before paymentSettledTimestamp");
      });
    });

    describe("CASE3: Settle Job exactly after shutdown delay", function () {
      it("should revert before paymentSettledTimestamp", async () => {
        await time.increaseTo(INITIAL_TIMESTAMP + SHUTDOWN_DELAY);

        await expect(marketv1.connect(user).jobSettle(ethers.constants.HashZero)).to.be.revertedWith("nothing to settle before paymentSettledTimestamp");
      });
    });

    describe("CASE4: Settle Job 2 minutes after shutdown delay", function () {
      it("should spend shutdown delay cost and 2 minutes worth tokens", async () => {
        const TWO_MINUTES = 60 * 2;
        await time.increaseTo(INITIAL_TIMESTAMP + SHUTDOWN_DELAY + TWO_MINUTES);

        // Job Settle
        await marketv1.connect(user).jobSettle(ethers.constants.HashZero);

        const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
        expect(jobInfo.metadata).to.equal("some metadata");
        expect(jobInfo.owner).to.equal(await user.getAddress());
        expect(jobInfo.provider).to.equal(await provider.getAddress());
        expect(jobInfo.rate).to.equal(JOB_RATE_1);

        const jobBalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
        expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

        const paymentSettledTimestampExpected = INITIAL_TIMESTAMP + SHUTDOWN_DELAY + TWO_MINUTES;
        expect(jobInfo.paymentSettledTimestamp).to.be.within(paymentSettledTimestampExpected - 3, paymentSettledTimestampExpected + 3);

        // User balance
        const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit).sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
        expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

        // Provider balance
        const providerBalanceExpected = calcAmountToPay(JOB_RATE_1, TWO_MINUTES).add(calcShutdownDelayCost(JOB_RATE_1));
        expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

        // MarketV1 balance
        const marketv1BalanceExpected = initialBalance.sub(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
        expect(await pond.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
      });
    });
  }); 

  describe("Job Deposit", function () {
    takeSnapshotBeforeAndAfterEveryTest(async () => { });
  
    it("should deposit to job", async () => {
      const initialDeposit = usdc(50);
      const initialBalance = initialDeposit.sub(calcShutdownDelayCost(JOB_RATE_1));
      const additionalDepositAmount = usdc(25);

      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
      
      // Deposit 25 USDC
      await marketv1
        .connect(signers[1])
        .jobDeposit(ethers.constants.HashZero, additionalDepositAmount);
  
      // Job after deposit
      const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
      expect(jobInfo.metadata).to.equal("some metadata");
      expect(jobInfo.owner).to.equal(addrs[1]);
      expect(jobInfo.provider).to.equal(addrs[2]);
      expect(jobInfo.rate).to.equal(JOB_RATE_1);
      expect(jobInfo.balance).to.equal(initialBalance.add(additionalDepositAmount));
      expect(jobInfo.paymentSettledTimestamp).to.be.within(INITIAL_TIMESTAMP + FIVE_MINUTES - 2, INITIAL_TIMESTAMP + FIVE_MINUTES + 2);
      
      const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit).sub(additionalDepositAmount);
      expect(await pond.balanceOf(addrs[1])).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

      const marketv1BalanceExpected = initialBalance.add(additionalDepositAmount);
      expect(await pond.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
    });
  
    it("should revert when depositing to job without enough approved", async () => {
      const initialDeposit = usdc(50);
      const initialBalance = initialDeposit.sub(calcShutdownDelayCost(JOB_RATE_1));
      const additionalDepositAmount = usdc(25);

      await pond.connect(user).approve(marketv1.address, initialDeposit);
      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
      
      // Deposit 25 USDC
      await expect(marketv1
        .connect(user)
        .jobDeposit(ethers.constants.HashZero, additionalDepositAmount)).to.be.revertedWith("ERC20: insufficient allowance");
    });
  
    it("should revert when depositing to job without enough balance", async () => {
      const initialDeposit = SIGNER1_INITIAL_FUND;
      const initialBalance = initialDeposit.sub(calcShutdownDelayCost(JOB_RATE_1));
      const additionalDepositAmount = usdc(25);

      // Open Job
      await pond.connect(user).approve(marketv1.address, SIGNER1_INITIAL_FUND.add(usdc(1000)));
      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
      
      // Deposit 25 USDC
      await expect(marketv1
        .connect(user)
        .jobDeposit(ethers.constants.HashZero, additionalDepositAmount)).to.be.revertedWith("ERC20: transfer amount exceeds balance");
    });
  
    it("should revert when depositing to never registered job", async () => {
      await expect(marketv1
        .connect(user)
        .jobDeposit(ethers.utils.hexZeroPad("0x01", 32), 25)).to.be.revertedWith("job not found");
    });
  
    it("should revert when depositing to closed job", async () => {
      const initialDeposit = usdc(50);

      // Job Open
      await pond.connect(user).approve(marketv1.address, initialDeposit);
      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
  
      // Job Close
      await marketv1.connect(user).jobClose(ethers.constants.HashZero);
  
      // Job Deposit
      await expect(marketv1
        .connect(signers[1])
        .jobDeposit(ethers.constants.HashZero, 25)).to.be.revertedWith("job not found");
    });
  });

  describe("Job Withdraw", function () {
    const initialDeposit = usdc(50);
    const initialBalance = initialDeposit.sub(calcShutdownDelayCost(JOB_RATE_1));

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    beforeEach(async () => {
      await pond.connect(user).approve(marketv1.address, initialDeposit);
      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
    });
  
    it("should withdraw from job immediately", async () => {
      const withdrawAmount = usdc(10);

      // Job Withdraw
      await marketv1
        .connect(signers[1])
        .jobWithdraw(ethers.constants.HashZero, withdrawAmount);
  
      let jobInfo = await marketv1.jobs(ethers.constants.HashZero);
      expect(jobInfo.metadata).to.equal("some metadata");
      expect(jobInfo.owner).to.equal(addrs[1]);
      expect(jobInfo.provider).to.equal(addrs[2]);
      expect(jobInfo.rate).to.equal(JOB_RATE_1);
      expect(jobInfo.balance).to.equal(initialBalance.sub(withdrawAmount));
      expect(jobInfo.paymentSettledTimestamp).to.be.within(INITIAL_TIMESTAMP + FIVE_MINUTES - 2, INITIAL_TIMESTAMP + FIVE_MINUTES + 2);
    
      expect(await pond.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND.sub(initialDeposit).add(withdrawAmount));
      expect(await pond.balanceOf(await provider.getAddress())).to.equal(calcShutdownDelayCost(JOB_RATE_1));
      expect(await pond.balanceOf(marketv1.address)).to.equal(initialBalance.sub(withdrawAmount));
    });
  
    it("should withdraw from job before paymentSettledTimestamp", async () => {
      const TWO_MINUTES = 60 * 2;
      const withdrawAmount = usdc(10);
      
      // 2 minutes passed
      await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);

      // Job Withdraw
      await marketv1
        .connect(user)
        .jobWithdraw(ethers.constants.HashZero, withdrawAmount);
      
      // Job info after Withdrawal
      let jobInfo = await marketv1.jobs(ethers.constants.HashZero);
      expect(jobInfo.metadata).to.equal("some metadata");
      expect(jobInfo.owner).to.equal(await user.getAddress());
      expect(jobInfo.provider).to.equal(await provider.getAddress());
      expect(jobInfo.rate).to.equal(JOB_RATE_1);
      expect(jobInfo.balance).to.equal(initialBalance.sub(withdrawAmount));
      // paymentSetteldTimestamp hasn't changed
      expect(jobInfo.paymentSettledTimestamp).to.be.within(INITIAL_TIMESTAMP + FIVE_MINUTES - 2, INITIAL_TIMESTAMP + FIVE_MINUTES + 2);
  
      expect(await pond.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND.sub(initialDeposit).add(withdrawAmount));
      expect(await pond.balanceOf(await provider.getAddress())).to.equal(calcShutdownDelayCost(JOB_RATE_1));
      expect(await pond.balanceOf(marketv1.address)).to.equal(initialBalance.sub(withdrawAmount));
    });
  
    it("should withdraw from job after paymentSettledTimestamp with settlement", async () => {
      const withdrawAmount = usdc(10);
      const settledAmountExpected = calcAmountToPay(JOB_RATE_1, TWO_MINUTES);

      // 7 minutes passed after Job Open
      await time.increaseTo(INITIAL_TIMESTAMP + SHUTDOWN_DELAY + TWO_MINUTES);
      await marketv1
        .connect(user)
        .jobWithdraw(ethers.constants.HashZero, withdrawAmount);
      
      expect(await pond.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND.sub(initialDeposit).add(withdrawAmount));

      const providerBalanceExpected = calcShutdownDelayCost(JOB_RATE_1).add(settledAmountExpected);
      expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

      const marketv1BalanceExpected = initialBalance.sub(withdrawAmount).sub(settledAmountExpected);
      expect(await pond.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
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
        .jobWithdraw(ethers.constants.HashZero, usdc(100))).to.be.revertedWith("only job owner");
    });
  
    it("should revert when balance is below shutdown delay cost", async () => {
      // deposited 50 USDC
      // 0.01 USDC/s
      // shutdown delay cost: 0.01 * 300 = 3 USDC
      // 47 USDC left

      await time.increaseTo(INITIAL_TIMESTAMP + SHUTDOWN_DELAY + 4500); // spend 45 USDC (300 + 4500 seconds passed)

      await expect(marketv1
        .connect(user)
        .jobWithdraw(ethers.constants.HashZero, usdc(1))).to.be.revertedWith("balance below shutdown delay cost");
    });
  
    it("should revert when withdrawal request amount exceeds max withdrawable amount", async () => {
      // Current balance: 47 USDC

      await expect(marketv1
        .connect(user)
        .jobWithdraw(ethers.constants.HashZero, usdc(48))).to.be.revertedWith("amount exceeds max withdrawable amount");
    });
  });

  describe("Job Revise Rate", function () {
    const JOB_LOWER_RATE = BN.from(5).e16().div(10);
    const JOB_HIGHER_RATE = BN.from(2).e16();

    const initialDeposit = usdc(50);
    const initialBalance = initialDeposit.sub(calcShutdownDelayCost(JOB_RATE_1));

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    beforeEach(async () => {
      await pond.connect(user).approve(marketv1.address, initialDeposit);
      await marketv1
        .connect(user)
        .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
    });

    it("should revise rate higher", async () => {
      const currentTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

      await marketv1
        .connect(user)
        .jobReviseRate(ethers.constants.HashZero, JOB_HIGHER_RATE);
      
      const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
      expect(jobInfo.rate).to.equal(JOB_HIGHER_RATE);
      expect(jobInfo.balance).to.equal(initialBalance);

      expect(jobInfo.paymentSettledTimestamp).to.equal(currentTimestamp + FIVE_MINUTES);
      expect(await pond.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND.sub(initialDeposit));
      expect(await pond.balanceOf(await provider.getAddress())).to.equal(calcShutdownDelayCost(JOB_RATE_1));
      expect(await pond.balanceOf(marketv1.address)).to.equal(initialBalance);
    });

    it("should revise rate lower", async () => {
      const currentTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

      await marketv1
        .connect(user)
        .jobReviseRate(ethers.constants.HashZero, JOB_LOWER_RATE);

      const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
      expect(jobInfo.rate).to.equal(JOB_LOWER_RATE);
      expect(jobInfo.balance).to.equal(initialBalance);
      expect(jobInfo.paymentSettledTimestamp).to.equal(currentTimestamp + FIVE_MINUTES);
      expect(await pond.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND.sub(initialDeposit));
      expect(await pond.balanceOf(await provider.getAddress())).to.equal(calcShutdownDelayCost(JOB_RATE_1));
      expect(await pond.balanceOf(marketv1.address)).to.equal(initialBalance);
    });

    it("should revert when initiating rate revision for non existent job", async () => {
      await expect(marketv1
        .connect(user)
        .jobReviseRate(ethers.utils.hexZeroPad("0x01", 32), JOB_HIGHER_RATE)).to.be.revertedWith("job not found");
    });

    it("should revert when initiating rate revision for third party job", async () => {
      await expect(marketv1
        .connect(signers[3]) // neither owner nor provider
        .jobReviseRate(ethers.constants.HashZero, JOB_HIGHER_RATE)).to.be.revertedWith("only job owner");
    });

    const HIGHER_RATE = BN.from(2).e16(); // 0.02 USDC/s
    const LOWER_RATE = BN.from(5).e15(); // 0.005 USDC/s
    
    describe("CASE 1: Revising Rate immediately after job open", function () {

      describe("when rate is higher", function () {

        it("should spend shutdown delay cost only", async () => {
          const shutdownDelayCostExpected = calcShutdownDelayCost(JOB_RATE_1);

          await marketv1
            .connect(user)
            .jobReviseRate(ethers.constants.HashZero, HIGHER_RATE);

          // Job info after Rate Revision
          const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
          expect(jobInfo.rate).to.equal(HIGHER_RATE);
          const jobBalanceExpected = initialBalance.sub(shutdownDelayCostExpected);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit).sub(shutdownDelayCostExpected);
          expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = shutdownDelayCostExpected;
          expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await pond.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });

      describe("when rate is lower", function () {
        it("should spend shutdown delay cost only", async () => {
          const shutdownDelayCostExpected = calcShutdownDelayCost(JOB_RATE_1);
  
          await marketv1
            .connect(user)
            .jobReviseRate(ethers.constants.HashZero, LOWER_RATE);
          
          // Job info after Rate Revision
          const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
          expect(jobInfo.rate).to.equal(LOWER_RATE);
          const jobBalanceExpected = initialDeposit.sub(shutdownDelayCostExpected);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));
  
          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(shutdownDelayCostExpected);
          expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = shutdownDelayCostExpected;
          expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await pond.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });
    });
    describe("CASE 2: Revising Rate 2 minutes after job open", function () {
      const TWO_MINUTES = 60 * 2;
      const SEVEN_MINUTES = 60 * 7;

      describe("when rate is higher", function () {
        it("should spend shutdown delay cost + 2 minutes worth tokens with higher rate", async () => {
          // 5 min * initial rate + 2 min * higher rate
          const usdcSpentExpected = calcShutdownDelayCost(JOB_RATE_1).add(calcAmountToPay(HIGHER_RATE, TWO_MINUTES));
          const initialTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

          await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);

          await marketv1
            .connect(user)
            .jobReviseRate(ethers.constants.HashZero, HIGHER_RATE);
            
          const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
          expect(jobInfo.rate).to.equal(HIGHER_RATE);

          const jobBalanceExpected = initialDeposit.sub(usdcSpentExpected);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const paymentSettledTimestampExpected = (await ethers.provider.getBlock('latest')).timestamp + FIVE_MINUTES;
          expect(jobInfo.paymentSettledTimestamp).to.be.within(paymentSettledTimestampExpected - 3, paymentSettledTimestampExpected + 3);

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit).sub(usdcSpentExpected);
          expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = usdcSpentExpected;
          expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await pond.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });

      describe("when rate is lower", function () {
        it("should spend shutdown delay cost + 2 minutes worth tokens with initial rate", async () => {
          // 5 min * initial rate + 2 min * initial rate
          const usdcSpentExpected = calcShutdownDelayCost(JOB_RATE_1).add(calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
          const initialTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

          await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);

          await marketv1
            .connect(user)
            .jobReviseRate(ethers.constants.HashZero, LOWER_RATE);
          
          const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
          expect(jobInfo.rate).to.equal(LOWER_RATE);

          const jobBalanceExpected = initialDeposit.sub(usdcSpentExpected);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const paymentSettledTimestampExpected = (await ethers.provider.getBlock('latest')).timestamp + FIVE_MINUTES;
          expect(jobInfo.paymentSettledTimestamp).to.be.within(paymentSettledTimestampExpected - 3, paymentSettledTimestampExpected + 3);

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit).sub(usdcSpentExpected);
          expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = usdcSpentExpected;
          expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await pond.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });
    });

    describe("CASE 3: Revising Rate exactly after shutdown delay", function () {
      const TEN_MINUTES = 60 * 10;

      describe("when rate is higher", function () {
        it("should spend 5 minutes worth tokens with initial rate and 5 minutes worth tokens with higher rate", async () => {
          const initialTimestamp = (await ethers.provider.getBlock('latest')).timestamp;
          const firstShutdownDelayCost = calcShutdownDelayCost(JOB_RATE_1);
          const secondShutdownDelayCost = calcShutdownDelayCost(HIGHER_RATE);

          await time.increaseTo(INITIAL_TIMESTAMP + SHUTDOWN_DELAY);

          await marketv1
            .connect(user)
            .jobReviseRate(ethers.constants.HashZero, HIGHER_RATE);
            
          const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
          expect(jobInfo.rate).to.equal(HIGHER_RATE);

          const jobBalanceExpected = initialDeposit.sub(firstShutdownDelayCost).sub(secondShutdownDelayCost);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const paymentSettledTimestampExpected = (await ethers.provider.getBlock('latest')).timestamp + FIVE_MINUTES;
          expect(jobInfo.paymentSettledTimestamp).to.be.within(paymentSettledTimestampExpected - 3, paymentSettledTimestampExpected + 3);

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit);
          expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = firstShutdownDelayCost.add(secondShutdownDelayCost);
          expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await pond.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });

      describe("when rate is lower", function () {
        it("should spend 5 minutes worth tokens with initial rate and 5 minutes worth tokens with initial rate", async () => {
          const initialTimestamp = (await ethers.provider.getBlock('latest')).timestamp;
          const firstShutdownDelayCost = calcShutdownDelayCost(JOB_RATE_1);
          const secondShutdownDelayCost = calcShutdownDelayCost(LOWER_RATE);

          await time.increaseTo(INITIAL_TIMESTAMP + SHUTDOWN_DELAY);

          await marketv1
            .connect(user)
            .jobReviseRate(ethers.constants.HashZero, LOWER_RATE);

          const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
          expect(jobInfo.rate).to.equal(LOWER_RATE);

          const jobBalanceExpected = initialDeposit.sub(firstShutdownDelayCost).sub(secondShutdownDelayCost);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const paymentSettledTimestampExpected = (await ethers.provider.getBlock('latest')).timestamp + FIVE_MINUTES;
          expect(jobInfo.paymentSettledTimestamp).to.be.within(paymentSettledTimestampExpected - 3, paymentSettledTimestampExpected + 3);

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit);
          expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = firstShutdownDelayCost.add(secondShutdownDelayCost);
          expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await pond.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });
    });

    describe("CASE 4: Revising Rate 2 minutes after shutdown delay", function () {
      const TWO_MINUTES = 60 * 2;
      const TWELVE_MINUTES = 60 * 12;

      describe("when rate is higher", function () {
        it("should spend 7 minutes worth tokens with initial rate and 5 minutes worth tokens with higher rate", async () => {
          const initialTimestamp = (await ethers.provider.getBlock('latest')).timestamp;
          const firstShutdownDelayCost = calcShutdownDelayCost(JOB_RATE_1);
          const secondShutdownDelayCost = calcShutdownDelayCost(HIGHER_RATE);

          await time.increaseTo(INITIAL_TIMESTAMP + SHUTDOWN_DELAY + TWO_MINUTES);

          await marketv1
            .connect(user)
            .jobReviseRate(ethers.constants.HashZero, HIGHER_RATE);

          const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
          expect(jobInfo.rate).to.equal(HIGHER_RATE);

          const jobBalanceExpected = initialDeposit.sub(firstShutdownDelayCost).sub(secondShutdownDelayCost);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const paymentSettledTimestampExpected = (await ethers.provider.getBlock('latest')).timestamp + FIVE_MINUTES;
          expect(jobInfo.paymentSettledTimestamp).to.be.within(paymentSettledTimestampExpected - 3, paymentSettledTimestampExpected + 3);
          
          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit);
          expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = firstShutdownDelayCost.add(secondShutdownDelayCost);
          expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await pond.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });

      describe("when rate is lower", function () {
        it("should spend 7 minutes worth tokens with initial rate and 5 minutes worth tokens with initial rate", async () => {
          const initialTimestamp = (await ethers.provider.getBlock('latest')).timestamp;
          const firstShutdownDelayCost = calcShutdownDelayCost(JOB_RATE_1);
          const secondShutdownDelayCost = calcShutdownDelayCost(JOB_RATE_1);

          await time.increaseTo(INITIAL_TIMESTAMP + SHUTDOWN_DELAY + TWO_MINUTES);

          await marketv1
            .connect(user)
            .jobReviseRate(ethers.constants.HashZero, LOWER_RATE);

          const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
          expect(jobInfo.rate).to.equal(LOWER_RATE);

          const jobBalanceExpected = initialDeposit.sub(firstShutdownDelayCost).sub(secondShutdownDelayCost);
          expect(jobInfo.balance).to.be.within(jobBalanceExpected.sub(JOB_RATE_1), jobBalanceExpected.add(JOB_RATE_1));

          const paymentSettledTimestampExpected = (await ethers.provider.getBlock('latest')).timestamp + FIVE_MINUTES;
          expect(jobInfo.paymentSettledTimestamp).to.be.within(paymentSettledTimestampExpected - 3, paymentSettledTimestampExpected + 3);

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit);
          expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = firstShutdownDelayCost.add(secondShutdownDelayCost);
          expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          const marketv1BalanceExpected = jobBalanceExpected;
          expect(await pond.balanceOf(marketv1.address)).to.be.within(marketv1BalanceExpected.sub(JOB_RATE_1), marketv1BalanceExpected.add(JOB_RATE_1));
        });
      });
    });
  });

    describe("Job Close", function () {
      const initialDeposit = usdc(50);
      const initialBalance = initialDeposit.sub(calcShutdownDelayCost(JOB_RATE_1));

      takeSnapshotBeforeAndAfterEveryTest(async () => { });

      beforeEach(async () => {
        await pond.connect(user).approve(marketv1.address, initialDeposit);
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
      });
  
      it("should close job", async () => {
        // Job Close
        await marketv1
          .connect(user)
          .jobClose(ethers.constants.HashZero); // here, user should get back (initial deposit - shutdown delay cost)

        const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
        expect(jobInfo.metadata).to.equal("");
        expect(jobInfo.owner).to.equal(ethers.constants.AddressZero);
        expect(jobInfo.provider).to.equal(ethers.constants.AddressZero);
        expect(jobInfo.rate).to.equal(0);
        expect(jobInfo.balance).to.equal(0);
        expect(jobInfo.paymentSettledTimestamp).to.equal(0);
      
        const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit).sub(calcShutdownDelayCost(JOB_RATE_1));
        expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));
      });
  
      it("should revert when closing non existent job", async () => {
        await expect(marketv1
          .connect(user)
          .jobClose(ethers.utils.hexZeroPad("0x01", 32))).to.be.revertedWith("job not found");
      });
  
      it("should revert when closing third party job", async () => {
        await expect(marketv1
          .connect(signers[3]) // neither owner nor provider
          .jobClose(ethers.constants.HashZero)).to.be.revertedWith("only job owner");
      });

      describe("Scenario 1: Closing Job immediately after opening", function () {
        it("should spend shutdown delay cost only", async () => {
          await marketv1
            .connect(user)
            .jobClose(ethers.constants.HashZero);

          const shutdownDelayCostExpected = calcShutdownDelayCost(JOB_RATE_1);

          // user balance after = initial fund - shutdown delay cost
          expect(await pond.balanceOf(await user.getAddress())).to.equal(SIGNER1_INITIAL_FUND.sub(shutdownDelayCostExpected));
          // provider balance after = shutdown delay cost
          expect(await pond.balanceOf(await provider.getAddress())).to.equal(shutdownDelayCostExpected);
          // marketv1 balance after = 0
          expect(await pond.balanceOf(marketv1.address)).to.equal(0);
        });
      });

      describe("Scenario 2: Closing Job 2 minutes after opening (before shutdown delay)", function () {
        it("should spend shutdown delay cost only", async () => {
          const TWO_MINUTES = 60 * 2;

          await time.increaseTo(INITIAL_TIMESTAMP + TWO_MINUTES);

          await marketv1
            .connect(user)
            .jobClose(ethers.constants.HashZero);
        
          const shutdownDelayCostExpected = calcShutdownDelayCost(JOB_RATE_1);

          // user balance after = initial fund - 2 minutes worth tokens - shutdown delay cost
          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(usdc(TWO_MINUTES)).sub(shutdownDelayCostExpected);
          expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));
        
          // provider balance after = 2 minutes worth tokens + shutdown delay cost
          const providerBalanceExpected = usdc(TWO_MINUTES).add(shutdownDelayCostExpected);
          expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          // marketv1 balance after = 0
          expect(await pond.balanceOf(marketv1.address)).to.equal(0);
        });
      });

      describe("Scenario 3: Closing Job exactly after shutdown delay", function () {
        it("should spend 10 minutes worth tokens", async () => {
          const usdcSpentExpected = calcAmountToPay(JOB_RATE_1, FIVE_MINUTES).add(calcShutdownDelayCost(JOB_RATE_1));

          await time.increaseTo(INITIAL_TIMESTAMP + SHUTDOWN_DELAY);

          await marketv1
            .connect(user)
            .jobClose(ethers.constants.HashZero);
        
          // user balance after = initial fund - 5 minutes worth tokens - shutdown delay cost
          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(usdcSpentExpected);
          expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          // provider balance after = 5 minutes worth tokens + shutdown delay cost
          const providerBalanceExpected = usdcSpentExpected;
          expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));

          expect(await pond.balanceOf(marketv1.address)).to.equal(0);
        });
      });

      describe("Scenario 4: Closing Job 2 minutes after shutdown delay", function () {
        it("should spend 12 minutes worth tokens", async () => {
          const SEVEN_MINUTES = 60 * 7;
          const usdcSpentExpected = calcAmountToPay(JOB_RATE_1, SEVEN_MINUTES).add(calcShutdownDelayCost(JOB_RATE_1));

          await time.increaseTo(INITIAL_TIMESTAMP + SHUTDOWN_DELAY + SEVEN_MINUTES);

          await marketv1
            .connect(user)
            .jobClose(ethers.constants.HashZero);

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(usdcSpentExpected);
          expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = usdcSpentExpected;
          expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));
        
          expect(await pond.balanceOf(marketv1.address)).to.equal(0);
        });
      });
    });
  
    describe("Metdata Update", function () {
      const initialDeposit = usdc(50);

      takeSnapshotBeforeAndAfterEveryTest(async () => { });

      beforeEach(async () => {
        await pond.connect(user).approve(marketv1.address, initialDeposit);
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
      });

      it("should update metadata", async () => {
        await marketv1
          .connect(user)
          .jobMetadataUpdate(ethers.constants.HashZero, "some updated metadata");
  
        const jobInfo2 = await marketv1.jobs(ethers.constants.HashZero);
        expect(jobInfo2.metadata).to.equal("some updated metadata");
      });
  
      it("should revert when updating metadata of other jobs", async () => {
        await expect(marketv1
          .connect(signers[3]) // neither owner nor provider
          .jobMetadataUpdate(ethers.constants.HashZero, "some updated metadata")).to.be.revertedWith("only job owner");
      });
    });

    describe.skip("Complex Scenario Test", function () {
      const initialDeposit = usdc(50);

      takeSnapshotBeforeAndAfterEveryTest(async () => { });

      beforeEach(async () => {
        await pond.connect(user).approve(marketv1.address, initialDeposit);
        await marketv1
          .connect(user)
          .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
      });

      describe("Scenario1", function () {
        const JOB_RATE_2 = BN.from(9).e15(); // 9e15
        const JOB_RATE_3 = BN.from(1).e16(); // 1e16
        const JOB_RATE_4 = BN.from(12).e15(); // 12e15
        const JOB_RATE_5 = BN.from(9).e15(); // 9e15

        const initialDeposit = usdc(50);
        
        it("[0min] should open a job with 50 USDC and have the correct initial balance", async function () {
          // user opens job
          await pond.connect(user).approve(marketv1.address, initialDeposit);
          await marketv1
            .connect(user)
            .jobOpen("some metadata", await provider.getAddress(), JOB_RATE_1, initialDeposit);
          
          const shutdownDelayCost = calcShutdownDelayCost(JOB_RATE_1);
          const initialBalanceExpected = initialDeposit.sub(shutdownDelayCost);

          const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
          expect(jobInfo.balance).to.equal(initialBalanceExpected); // initialDeposit(50USDC) - shutdownDelayCost(3USDC) = 47USDCs
        });

        it("[4min] should revise rate lower and pay 4min*previousRate", async function () {
          const FOUR_MINUTES = 60 * 4;
          const previousRate = JOB_RATE_1;
          const revisedRate = JOB_RATE_2;

          await time.increaseTo(INITIAL_TIMESTAMP + FOUR_MINUTES);
          
          await marketv1
            .connect(user)
            .jobReviseRate(ethers.constants.HashZero, revisedRate);

          const jobInfo = await marketv1.jobs(ethers.constants.HashZero);
          expect(jobInfo.rate).to.equal(revisedRate);

          const amountPaidExpected = calcAmountToPay(previousRate, FOUR_MINUTES);
          expect(jobInfo.balance).to.equal(initialBalanceExpected.sub(amountPaidExpected));

          const userBalanceExpected = SIGNER1_INITIAL_FUND.sub(initialDeposit);
          expect(await pond.balanceOf(await user.getAddress())).to.be.within(userBalanceExpected.sub(JOB_RATE_1), userBalanceExpected.add(JOB_RATE_1));

          const providerBalanceExpected = shutdownDelayCost.add(amountPaidExpected);
          expect(await pond.balanceOf(await provider.getAddress())).to.be.within(providerBalanceExpected.sub(JOB_RATE_1), providerBalanceExpected.add(JOB_RATE_1));
          
        })
      });
    });
  });
  
  



