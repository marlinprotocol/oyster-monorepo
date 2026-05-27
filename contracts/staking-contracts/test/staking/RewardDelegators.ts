import { expect, util } from "chai";
import { deployMockContract, MockContract } from "ethereum-waffle";
import { BigNumber as BN, Contract, Signer } from "ethers";
import { ethers, upgrades } from "hardhat";
import {
  Pond,
  RewardDelegators,
} from "../../typechain-types";
import { FuzzedNumber } from "../../utils/fuzzer";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import {
  getPond,
  getRewardDelegators,
} from "../../utils/typechainConvertor";
import { impersonate, setBalance, skipBlocks, skipTime } from "../helpers/common";
import { testERC165 } from "../helpers/erc165";
import { testAdminRole, testRole } from "../helpers/rbac";
const stakingConfig = require("../config/staking.json");

const START_DELAY = 100000;
const startTime = Math.floor(Date.now()/1000) + START_DELAY;

const e14 = ethers.utils.parseEther("0.0001");
const e16 = ethers.utils.parseEther("0.01");
const e18 = ethers.utils.parseEther("1");
const e20 = ethers.utils.parseEther("100");
const e22 = ethers.utils.parseEther("10000");
const e30 = ethers.utils.parseEther("1000000000000");

describe("RewardDelegators init and upgrades", function () {
    let signers: Signer[];
    let addrs: string[];

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
    });
  
    takeSnapshotBeforeAndAfterEveryTest(async () => {});
  
    it("deploys with initialization disabled", async () => {
        const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
        let rewardDelegators = await RewardDelegators.deploy();
    
        await expect(
            rewardDelegators.initialize(
                addrs[10],
                addrs[9],
                addrs[8],
                addrs[7],
                [ethers.utils.id(addrs[7]), ethers.utils.id(addrs[6])],
                [stakingConfig.PondRewardFactor, stakingConfig.MPondRewardFactor],
                [stakingConfig.PondWeightForThreshold, stakingConfig.MPondWeightForThreshold],
                [stakingConfig.PondWeightForDelegation, stakingConfig.MPondWeightForDelegation],
                [],
                []
            )
        ).to.be.reverted;
    });
  
    it("deploys as proxy and initializes", async function () {
        const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
        const rewardDelegatorsUntyped: Contract = await upgrades.deployProxy(RewardDelegators, {
            kind: "uups",
            initializer: false,
        });
        const rewardDelegators: RewardDelegators = getRewardDelegators(rewardDelegatorsUntyped.address, signers[0]);

        const fakeStakeManagerAddr = addrs[10];
        const fakeClusterRewardsAddr = addrs[9];
        const fakeClusterRegistryAddr = addrs[8];
        const fakePond = addrs[7];
        const fakeMPond = addrs[6];
        const pondTokenId = ethers.utils.id(fakePond);
        const mpondTokenId = ethers.utils.id(fakeMPond);
        const initializationTx = expect(rewardDelegators.initialize(
            fakeStakeManagerAddr,
            fakeClusterRewardsAddr,
            fakeClusterRegistryAddr,
            fakePond,
            [pondTokenId, mpondTokenId],
            [stakingConfig.PondRewardFactor, stakingConfig.MPondRewardFactor],
            [stakingConfig.PondWeightForThreshold, stakingConfig.MPondWeightForThreshold],
            [stakingConfig.PondWeightForDelegation, stakingConfig.MPondWeightForDelegation],
            [],
            []
        ))
        await initializationTx.to.emit(rewardDelegators, "AddReward").withArgs(pondTokenId, stakingConfig.PondRewardFactor);
        await initializationTx.to.emit(rewardDelegators, "AddReward").withArgs(mpondTokenId, stakingConfig.MPondRewardFactor);
        await initializationTx.to.emit(rewardDelegators, "TokenWeightsUpdated").withArgs(pondTokenId, stakingConfig.PondWeightForThreshold, stakingConfig.PondWeightForDelegation);
        await initializationTx.to.emit(rewardDelegators, "TokenWeightsUpdated").withArgs(mpondTokenId, stakingConfig.MPondWeightForThreshold, stakingConfig.MPondWeightForDelegation);

        expect(await rewardDelegators.stakeAddress()).to.equal(fakeStakeManagerAddr);
        expect(await rewardDelegators.clusterRegistry()).to.equal(fakeClusterRegistryAddr);
        expect(await rewardDelegators.clusterRewards()).to.equal(fakeClusterRewardsAddr);
        expect(await rewardDelegators.PONDToken()).to.equal(fakePond);
        expect(await rewardDelegators.rewardFactor(pondTokenId)).to.equal(stakingConfig.PondRewardFactor);
        expect(await rewardDelegators.rewardFactor(mpondTokenId)).to.equal(stakingConfig.MPondRewardFactor);
        const [pondWeightForDelegation, pondWeightForThreshold] = await rewardDelegators.tokenWeights(pondTokenId);
        expect([pondWeightForDelegation.toNumber(), pondWeightForThreshold.toNumber()]).to.eql([parseInt(stakingConfig.PondWeightForThreshold), parseInt(stakingConfig.PondWeightForDelegation)]);
        const [mpondWeightForDelegation, mpondWeightForThreshold] = await rewardDelegators.tokenWeights(mpondTokenId);
        expect([mpondWeightForDelegation.toNumber(), mpondWeightForThreshold.toNumber()]).to.eql([parseInt(stakingConfig.MPondWeightForThreshold), parseInt(stakingConfig.MPondWeightForDelegation)]);
        expect([
            (await rewardDelegators.tokenIndex(pondTokenId)).toNumber(), 
            (await rewardDelegators.tokenIndex(mpondTokenId)).toNumber()]
        ).to.eql([0, 1]);
        expect([await rewardDelegators.tokenList(0), await rewardDelegators.tokenList(1)]).to.eql([pondTokenId, mpondTokenId]);
        expect(await rewardDelegators.hasRole(await rewardDelegators.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });
  
    it("upgrades", async function () {
        const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
        const rewardDelegatorsUntyped: Contract = await upgrades.deployProxy(RewardDelegators, {
            kind: "uups",
            initializer: false,
        });
        const rewardDelegators: RewardDelegators = getRewardDelegators(rewardDelegatorsUntyped.address, signers[0]);
        
        const fakeStakeManagerAddr = addrs[10];
        const fakeClusterRewardsAddr = addrs[9];
        const fakeClusterRegistryAddr = addrs[8];
        const fakePond = addrs[7];
        const fakeMPond = addrs[6];
        const pondTokenId = ethers.utils.id(fakePond);
        const mpondTokenId = ethers.utils.id(fakeMPond);
        const initializationTx = expect(rewardDelegators.initialize(
            fakeStakeManagerAddr,
            fakeClusterRewardsAddr,
            fakeClusterRegistryAddr,
            fakePond,
            [pondTokenId, mpondTokenId],
            [stakingConfig.PondRewardFactor, stakingConfig.MPondRewardFactor],
            [stakingConfig.PondWeightForThreshold, stakingConfig.MPondWeightForThreshold],
            [stakingConfig.PondWeightForDelegation, stakingConfig.MPondWeightForDelegation],
            [],
            []
        ))
        await initializationTx.to.emit(rewardDelegators, "AddReward").withArgs(pondTokenId, stakingConfig.PondRewardFactor);
        await initializationTx.to.emit(rewardDelegators, "AddReward").withArgs(mpondTokenId, stakingConfig.MPondRewardFactor);
        await initializationTx.to.emit(rewardDelegators, "TokenWeightsUpdated").withArgs(pondTokenId, stakingConfig.PondWeightForThreshold, stakingConfig.PondWeightForDelegation);
        await initializationTx.to.emit(rewardDelegators, "TokenWeightsUpdated").withArgs(mpondTokenId, stakingConfig.MPondWeightForThreshold, stakingConfig.MPondWeightForDelegation);

        const originalImplemetationAddress = await upgrades.erc1967.getImplementationAddress(rewardDelegators.address);
        await upgrades.upgradeProxy(rewardDelegators.address, RewardDelegators, { kind: "uups", redeployImplementation: 'always' });
        expect(originalImplemetationAddress).to.not.equal(await upgrades.erc1967.getImplementationAddress(rewardDelegators.address));
        
        expect(await rewardDelegators.stakeAddress()).to.equal(fakeStakeManagerAddr);
        expect(await rewardDelegators.clusterRegistry()).to.equal(fakeClusterRegistryAddr);
        expect(await rewardDelegators.clusterRewards()).to.equal(fakeClusterRewardsAddr);
        expect(await rewardDelegators.PONDToken()).to.equal(fakePond);
        expect(await rewardDelegators.rewardFactor(pondTokenId)).to.equal(stakingConfig.PondRewardFactor);
        expect(await rewardDelegators.rewardFactor(mpondTokenId)).to.equal(stakingConfig.MPondRewardFactor);
        const [pondWeightForDelegation, pondWeightForThreshold] = await rewardDelegators.tokenWeights(pondTokenId);
        expect([pondWeightForDelegation.toNumber(), pondWeightForThreshold.toNumber()]).to.eql([parseInt(stakingConfig.PondWeightForThreshold), parseInt(stakingConfig.PondWeightForDelegation)]);
        const [mpondWeightForDelegation, mpondWeightForThreshold] = await rewardDelegators.tokenWeights(mpondTokenId);
        expect([mpondWeightForDelegation.toNumber(), mpondWeightForThreshold.toNumber()]).to.eql([parseInt(stakingConfig.MPondWeightForThreshold), parseInt(stakingConfig.MPondWeightForDelegation)]);
        expect([
            (await rewardDelegators.tokenIndex(pondTokenId)).toNumber(), 
            (await rewardDelegators.tokenIndex(mpondTokenId)).toNumber()]
        ).to.eql([0, 1]);
        expect([await rewardDelegators.tokenList(0), await rewardDelegators.tokenList(1)]).to.eql([pondTokenId, mpondTokenId]);
        expect(await rewardDelegators.hasRole(await rewardDelegators.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });
  
    it("does not upgrade without admin", async () => {
        const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
        const rewardDelegatorsUntyped: Contract = await upgrades.deployProxy(RewardDelegators, {
            kind: "uups",
            initializer: false,
        });
        const rewardDelegators: RewardDelegators = getRewardDelegators(rewardDelegatorsUntyped.address, signers[0]);
        
        const fakeStakeManagerAddr = addrs[10];
        const fakeClusterRewardsAddr = addrs[9];
        const fakeClusterRegistryAddr = addrs[8];
        const fakePond = addrs[7];
        const fakeMPond = addrs[6];
        const pondTokenId = ethers.utils.id(fakePond);
        const mpondTokenId = ethers.utils.id(fakeMPond);
        const initializationTx = expect(rewardDelegators.initialize(
            fakeStakeManagerAddr,
            fakeClusterRewardsAddr,
            fakeClusterRegistryAddr,
            fakePond,
            [pondTokenId, mpondTokenId],
            [stakingConfig.PondRewardFactor, stakingConfig.MPondRewardFactor],
            [stakingConfig.PondWeightForThreshold, stakingConfig.MPondWeightForThreshold],
            [stakingConfig.PondWeightForDelegation, stakingConfig.MPondWeightForDelegation],
            [],
            []
        ))
        await initializationTx.to.emit(rewardDelegators, "AddReward").withArgs(pondTokenId, stakingConfig.PondRewardFactor);
        await initializationTx.to.emit(rewardDelegators, "AddReward").withArgs(mpondTokenId, stakingConfig.MPondRewardFactor);
        await initializationTx.to.emit(rewardDelegators, "TokenWeightsUpdated").withArgs(pondTokenId, stakingConfig.PondWeightForThreshold, stakingConfig.PondWeightForDelegation);
        await initializationTx.to.emit(rewardDelegators, "TokenWeightsUpdated").withArgs(mpondTokenId, stakingConfig.MPondWeightForThreshold, stakingConfig.MPondWeightForDelegation);

        await upgrades.upgradeProxy(rewardDelegators.address, RewardDelegators, { kind: "uups" });
  
        await expect(upgrades.upgradeProxy(rewardDelegators.address, RewardDelegators.connect(signers[1]) ,{ kind: "uups" })).to.be.reverted;
    });
});

testERC165("ReceiverStaking ERC165", async function (signers: Signer[], addrs: string[]) {
        const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
        const rewardDelegatorsUntyped: Contract = await upgrades.deployProxy(RewardDelegators, {
            kind: "uups",
            initializer: false,
        });
        const rewardDelegators: RewardDelegators = getRewardDelegators(rewardDelegatorsUntyped.address, signers[0]);

        const fakeStakeManagerAddr = addrs[10];
        const fakeClusterRewardsAddr = addrs[9];
        const fakeClusterRegistryAddr = addrs[8];
        const fakePond = addrs[7];
        const fakeMPond = addrs[6];
        const pondTokenId = ethers.utils.id(fakePond);
        const mpondTokenId = ethers.utils.id(fakeMPond);
        await rewardDelegators.initialize(
            fakeStakeManagerAddr,
            fakeClusterRewardsAddr,
            fakeClusterRegistryAddr,
            fakePond,
            [pondTokenId, mpondTokenId],
            [stakingConfig.PondRewardFactor, stakingConfig.MPondRewardFactor],
            [stakingConfig.PondWeightForThreshold, stakingConfig.MPondWeightForThreshold],
            [stakingConfig.PondWeightForDelegation, stakingConfig.MPondWeightForDelegation],
            [],
            []
        );
        return rewardDelegators;
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
    }
);
  
testAdminRole("ReceiverStaking Admin role", async function (signers: Signer[], addrs: string[]) {
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    const rewardDelegatorsUntyped: Contract = await upgrades.deployProxy(RewardDelegators, {
        kind: "uups",
        initializer: false,
    });
    const rewardDelegators: RewardDelegators = getRewardDelegators(rewardDelegatorsUntyped.address, signers[0]);

    const fakeStakeManagerAddr = addrs[10];
    const fakeClusterRewardsAddr = addrs[9];
    const fakeClusterRegistryAddr = addrs[8];
    const fakePond = addrs[7];
    const fakeMPond = addrs[6];
    const pondTokenId = ethers.utils.id(fakePond);
    const mpondTokenId = ethers.utils.id(fakeMPond);
    await rewardDelegators.initialize(
        fakeStakeManagerAddr,
        fakeClusterRewardsAddr,
        fakeClusterRegistryAddr,
        fakePond,
        [pondTokenId, mpondTokenId],
        [stakingConfig.PondRewardFactor, stakingConfig.MPondRewardFactor],
        [stakingConfig.PondWeightForThreshold, stakingConfig.MPondWeightForThreshold],
        [stakingConfig.PondWeightForDelegation, stakingConfig.MPondWeightForDelegation],
        [],
        []
    );
    return rewardDelegators;
});

describe("RewardDelegators global var updates", function () {
    let signers: Signer[];
    let addrs: string[];

    let rewardDelegators: RewardDelegators;
    let pondTokenId: string;
    let mpondTokenId: string;
  
    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
        const rewardDelegatorsUntyped: Contract = await upgrades.deployProxy(RewardDelegators, {
            kind: "uups",
            initializer: false,
        });
        rewardDelegators = getRewardDelegators(rewardDelegatorsUntyped.address, signers[0]);

        const fakeStakeManagerAddr = addrs[10];
        const fakeClusterRewardsAddr = addrs[9];
        const fakeClusterRegistryAddr = addrs[8];
        const fakePond = addrs[7];
        const fakeMPond = addrs[6];
        pondTokenId = ethers.utils.id(fakePond);
        mpondTokenId = ethers.utils.id(fakeMPond);
        await rewardDelegators.initialize(
            fakeStakeManagerAddr,
            fakeClusterRewardsAddr,
            fakeClusterRegistryAddr,
            fakePond,
            [pondTokenId, mpondTokenId],
            [stakingConfig.PondRewardFactor, stakingConfig.MPondRewardFactor],
            [stakingConfig.PondWeightForThreshold, stakingConfig.MPondWeightForThreshold],
            [stakingConfig.PondWeightForDelegation, stakingConfig.MPondWeightForDelegation],
            [],
            []
        );
        return rewardDelegators;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => {});

    it("non owner cannot update PondAddress", async () => {
        const Pond = await ethers.getContractFactory("Pond");
        let pondInstance2 = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
        await expect(rewardDelegators.connect(signers[1]).updatePONDAddress(pondInstance2.address)).to.be.reverted;
    });

    it("cannot update PondAddress to 0", async () => {
        await expect(rewardDelegators.updatePONDAddress(ethers.constants.AddressZero)).to.be.reverted;
    });

    it("owner can update PondAddress", async () => {
        const Pond = await ethers.getContractFactory("Pond");
        let pondInstance2 = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
        await expect(rewardDelegators.updatePONDAddress(pondInstance2.address)).to.emit(rewardDelegators, "PONDAddressUpdated");
    });

    it("non owner cannot update ClusterRegistry", async () => {
        const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
        let clusterRegistryInstance2 = await upgrades.deployProxy(ClusterRegistry, { kind: "uups", initializer: false });
        await expect(rewardDelegators.connect(signers[1]).updateClusterRegistry(clusterRegistryInstance2.address)).to.be.reverted;
    });

    it("cannot update ClusterRegistry to 0", async () => {
        await expect(rewardDelegators.updateClusterRegistry(ethers.constants.AddressZero)).to.be.reverted;
    });

    it("owner can update ClusterRegistry", async () => {
        const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
        let clusterRegistryInstance2 = await upgrades.deployProxy(ClusterRegistry, { kind: "uups", initializer: false });
        await expect(await rewardDelegators.updateClusterRegistry(clusterRegistryInstance2.address)).to.emit(
            rewardDelegators,
            "ClusterRegistryUpdated"
        );
    });

    it("non owner cannot update ClusterRewards", async () => {
        const ClusterRewards = await ethers.getContractFactory("ClusterRewards");
        let clusterRewardsInstance2 = await upgrades.deployProxy(ClusterRewards, { kind: "uups", initializer: false });
        await expect(rewardDelegators.connect(signers[1]).updateClusterRewards(clusterRewardsInstance2.address)).to.be.reverted;
    });

    it("cannot update ClusterRewards to 0", async () => {
        await expect(rewardDelegators.updateClusterRewards(ethers.constants.AddressZero)).to.be.reverted;
    });

    it("owner can update ClusterRewards", async () => {
        const ClusterRewards = await ethers.getContractFactory("ClusterRewards");
        let clusterRewardsInstance2 = await upgrades.deployProxy(ClusterRewards, { kind: "uups", initializer: false });
        await expect(await rewardDelegators.updateClusterRewards(clusterRewardsInstance2.address)).to.emit(
            rewardDelegators,
            "ClusterRewardsAddressUpdated"
        );
    });

    it("non owner cannot update StakeManager", async () => {
        const StakeManager = await ethers.getContractFactory("StakeManager");
        let stakeManagerInstance2 = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
        await expect(rewardDelegators.connect(signers[1]).updateStakeAddress(stakeManagerInstance2.address)).to.be.reverted;
    });

    it("cannot update StakeManager to 0", async () => {
        await expect(rewardDelegators.updateStakeAddress(ethers.constants.AddressZero)).to.be.reverted;
    });

    it("owner can update StakeManager", async () => {
        const StakeManager = await ethers.getContractFactory("StakeManager");
        let stakeManagerInstance2 = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
        await expect(await rewardDelegators.updateStakeAddress(stakeManagerInstance2.address)).to.emit(
            rewardDelegators, 
            "StakeAddressUpdated"
        );
    });

    it("non owner cannot add rewardFactor", async () => {
        let testTokenId = await ethers.utils.keccak256(addrs[0]);
        await expect(rewardDelegators.connect(signers[1]).addRewardFactor(testTokenId, 1)).to.be.reverted;
    });

    it(" cannot add for already existing tokenId", async () => {
        await expect(rewardDelegators.addRewardFactor("" + pondTokenId, stakingConfig.PondRewardFactor)).to.be.reverted;
    });

    it("cannot add 0 reward Factor", async () => {
        let testTokenId = await ethers.utils.keccak256(addrs[0]);
        await expect(rewardDelegators.addRewardFactor(testTokenId, 0)).to.be.reverted;
    });

    it("owner can add rewardFactor", async () => {
        let testTokenId = await ethers.utils.keccak256(addrs[0]);
        await expect(await rewardDelegators.addRewardFactor(testTokenId, 1)).to.emit(rewardDelegators, "AddReward");
    });

    it("non owner cannot remove rewardFactor", async () => {
        await expect(rewardDelegators.connect(signers[1]).removeRewardFactor("" + pondTokenId)).to.be.reverted;
    });

    it("cannot remove non existing tokenId", async () => {
        let testTokenId = await ethers.utils.keccak256(addrs[0]);
        await expect(rewardDelegators.removeRewardFactor(testTokenId)).to.be.reverted;
    });

    it("owner can remove rewardFactor", async () => {
        await expect(await rewardDelegators.removeRewardFactor("" + pondTokenId)).to.emit(rewardDelegators, "RemoveReward");
    });

    it("non owner cannot update reward Factor", async () => {
        await expect(rewardDelegators.connect(signers[1]).updateRewardFactor("" + pondTokenId, stakingConfig.PondRewardFactor + 1))
            .to.be.reverted;
    });

    it("cannot update non existing tokenId", async () => {
        let testTokenId = await ethers.utils.keccak256(addrs[0]);
        await expect(rewardDelegators.updateRewardFactor(testTokenId, 1)).to.be.reverted;
    });

    it("cannot update rewardFactor to 0", async () => {
        await expect(rewardDelegators.updateRewardFactor("" + pondTokenId, 0)).to.be.reverted;
    });

    it("owner can update rewardFactor", async () => {
        await expect(await rewardDelegators.updateRewardFactor("" + pondTokenId, stakingConfig.PondRewardFactor + 1))
        .to.emit(
            rewardDelegators,
            "RewardsUpdated"
        );
    });
});

describe("RewardDelegators Admin Call", function() {
    let signers: Signer[]
    let rewardDelegatorsOwner: Signer
    let rewardDelegators: RewardDelegators;
    let addrs: string[];
    let pondTokenId: string;
    let mpondTokenId: string;
    
    const networkId = ethers.utils.id("DOT");

    before(async () => {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        rewardDelegatorsOwner = signers[0];

        const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
        let rewardDelegatorsContract = await upgrades.deployProxy(RewardDelegators, {
            kind: "uups",
            initializer: false,
        });
        rewardDelegators = getRewardDelegators(rewardDelegatorsContract.address, signers[0]);
        
        const fakeStakeManagerAddr = addrs[10];
        const fakeClusterRewardsAddr = addrs[9];
        const fakeClusterRegistryAddr = addrs[8];
        const fakePond = addrs[7];
        const fakeMPond = addrs[6];
        pondTokenId = ethers.utils.id(fakePond);
        mpondTokenId = ethers.utils.id(fakeMPond);
        await rewardDelegators.initialize(
            fakeStakeManagerAddr,
            fakeClusterRewardsAddr,
            fakeClusterRegistryAddr,
            fakePond,
            [pondTokenId, mpondTokenId],
            [stakingConfig.PondRewardFactor, stakingConfig.MPondRewardFactor],
            [stakingConfig.PondWeightForThreshold, stakingConfig.MPondWeightForThreshold],
            [stakingConfig.PondWeightForDelegation, stakingConfig.MPondWeightForDelegation],
            [],
            []
        );
    })

    takeSnapshotBeforeAndAfterEveryTest(async () => {});

    it("Update weight", async () => {
        await expect(rewardDelegators.connect(rewardDelegatorsOwner).updateTokenWeights(networkId, 120, 200))
          .to.emit(rewardDelegators, "TokenWeightsUpdated")
          .withArgs(networkId, 120, 200);
    });

    it("update threshold for selection", async () => {
    const threshold = 12;
    await expect(rewardDelegators.connect(rewardDelegatorsOwner).updateThresholdForSelection(networkId, threshold))
        .to.emit(rewardDelegators, "ThresholdForSelectionUpdated")
        .withArgs(networkId, threshold);
    });

    it("Add, remove and update reward Factor", async () => {
        const testTokenId = ethers.utils.id("testTokenId");
        // only owner can add the reward factor
        await expect(rewardDelegators.connect(signers[1]).addRewardFactor(testTokenId, 10)).to.be.reverted;
        await expect(await rewardDelegators.connect(rewardDelegatorsOwner).addRewardFactor(testTokenId, 10)).to.emit(
            rewardDelegators,
          "AddReward"
        );
    
        // only owner can update the reward factor
        await expect(rewardDelegators.connect(signers[1]).updateRewardFactor(testTokenId, 100)).to.be.reverted;
        await expect(await rewardDelegators.connect(rewardDelegatorsOwner).updateRewardFactor(testTokenId, 100)).to.emit(
            rewardDelegators,
          "RewardsUpdated"
        );
    
        // only owner can remove the reward factor
        await expect(rewardDelegators.connect(signers[1]).removeRewardFactor(testTokenId)).to.be.reverted;
        await expect(await rewardDelegators.connect(rewardDelegatorsOwner).removeRewardFactor(testTokenId)).to.emit(
            rewardDelegators,
          "RemoveReward"
        );
      });
})

describe("RewardDelegators ", function () {
    let signers: Signer[];
    let addrs: string[];

    let registeredClusters: Signer[];
    let registeredClusterRewardAddresses: string[];
    let clientKeys: string[];
    let delegators: Signer[];

    let rewardDelegators: RewardDelegators;
    let fakeStakeManager: MockContract;
    let imperonatedStakeManager: Signer;
    let fakeClusterRewards: MockContract;
    let fakeClusterRegistry: MockContract;
    let impersonatedClusterRegistry: Signer;

    let pond: Pond;
    let pondTokenId: string;
    let mpondTokenId: string;

    let fakeClusterSelectors: Record<string, MockContract> = {};
  
    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        registeredClusters = signers.slice(20, 30);
        registeredClusterRewardAddresses = addrs.slice(30, 40);
        clientKeys = addrs.slice(40, 50);
        delegators = signers.slice(50, 60);

        const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
        const rewardDelegatorsUntyped: Contract = await upgrades.deployProxy(RewardDelegators, {
            kind: "uups",
            initializer: false,
        });
        rewardDelegators = getRewardDelegators(rewardDelegatorsUntyped.address, signers[0]);

        const StakeManager = await ethers.getContractFactory("StakeManager");
        // setting address while deploying mock is not yet implemented in ethereum-waffle yet
        fakeStakeManager = await deployMockContract(signers[9], StakeManager.interface.format());
        imperonatedStakeManager = await impersonate(ethers, fakeStakeManager.address);
        // mocking receive function is not implemented in ethereum-waffle yet
        await setBalance(ethers, fakeStakeManager.address, e18);
        const ClusterRewards = await ethers.getContractFactory("ClusterRewards");
        fakeClusterRewards = await deployMockContract(signers[8], ClusterRewards.interface.format());
        const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
        fakeClusterRegistry = await deployMockContract(signers[7], ClusterRegistry.interface.format());
        impersonatedClusterRegistry = await impersonate(ethers, fakeClusterRegistry.address);
        await setBalance(ethers, fakeClusterRegistry.address, e18);
        const Pond = await ethers.getContractFactory("Pond");
        const pondUntyped = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
        pond = getPond(pondUntyped.address, signers[0]);
        const fakeMPond = addrs[6];
        pondTokenId = ethers.utils.id(pond.address);
        mpondTokenId = ethers.utils.id(fakeMPond);
        await rewardDelegators.initialize(
            fakeStakeManager.address,
            fakeClusterRewards.address,
            fakeClusterRegistry.address,
            pond.address,
            [pondTokenId, mpondTokenId],
            [stakingConfig.PondRewardFactor, stakingConfig.MPondRewardFactor],
            [stakingConfig.PondWeightForThreshold, stakingConfig.MPondWeightForThreshold],
            [stakingConfig.PondWeightForDelegation, stakingConfig.MPondWeightForDelegation],
            [],
            []
        );

        await pond.transfer(rewardDelegators.address, ethers.utils.parseEther("100000"));
        
        const clusterSelector = await ethers.getContractFactory("ClusterSelector");
        await fakeClusterRewards.mock.clusterSelectors.returns(ethers.constants.AddressZero);
        fakeClusterSelectors["ETH"] = await deployMockContract(signers[5], clusterSelector.interface.format());
        await fakeClusterRewards.mock.clusterSelectors.withArgs(ethers.utils.id("ETH")).returns(fakeClusterSelectors["ETH"].address);
        fakeClusterSelectors["DOT"] = await deployMockContract(signers[4], clusterSelector.interface.format());
        await fakeClusterRewards.mock.clusterSelectors.withArgs(ethers.utils.id("DOT")).returns(fakeClusterSelectors["DOT"].address);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => {});

    // NOTE: Reward factor doesn't do anything rn
    it("delegate to cluster single token", async () => {
        const delegator = await delegators[0].getAddress();
        const delegator1 = await delegators[1].getAddress();
        const cluster = await registeredClusters[FuzzedNumber.randomInRange(0, registeredClusters.length).toNumber()].getAddress();
        const rewardAddress = registeredClusterRewardAddresses[FuzzedNumber.randomInRange(0, registeredClusterRewardAddresses.length).toNumber()];
        const networkId = ethers.utils.id("ETH");

        let rewardAmount = FuzzedNumber.randomInRange(100000, 500000);
        let commission = FuzzedNumber.randomInRange(0, 100);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(rewardAmount);
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster).returns(commission, rewardAddress);
        await fakeClusterRegistry.mock.getNetwork.withArgs(cluster).returns(networkId);
        await fakeClusterSelectors["ETH"].mock.upsert.returns();

        // ----------------- Give reward when previous total delegation and user has no prev rewards ---------------
        const amount1 = FuzzedNumber.randomInRange(e16, e18);
        await expect(rewardDelegators.delegate(delegator, cluster, [pondTokenId], [amount1]))
            .to.be.revertedWith("RD:OS-only stake contract can invoke");

        let clusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        let delegationInit = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        let rewardPerShare =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        await expect(rewardDelegators.connect(imperonatedStakeManager).delegate(delegator, cluster, [pondTokenId], [amount1]))
            .to.changeTokenBalances(
                pond, 
                [rewardDelegators, rewardAddress, delegator], 
                [-(commission.mul(rewardAmount).div(100)), commission.mul(rewardAmount).div(100), 0]
            );
        let clusterDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        let delegation = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        let rewardPerShare1 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);

        expect(clusterDelegation).to.equal(clusterDelegationInit.add(amount1));
        expect(delegation).to.equal(delegationInit.add(amount1));
        // as there is only pond token all reward  is given to pond token
        expect(rewardPerShare1.sub(rewardPerShare)).to.equal(0);

        // ----------------- Give reward when previous total delegation is non 0 and user has no prev rewards ---------------
        clusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        delegationInit = await rewardDelegators.getDelegation(cluster, delegator1, pondTokenId);
        let clusterCommission = commission.mul(rewardAmount).div(100);
        await expect(rewardDelegators.connect(imperonatedStakeManager).delegate(delegator1, cluster, [pondTokenId], [amount1]))
            .to.changeTokenBalances(
                pond, 
                [rewardDelegators, rewardAddress, delegator1], 
                [-clusterCommission, clusterCommission, 0]
            );
        clusterDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        delegation = await rewardDelegators.getDelegation(cluster, delegator1, pondTokenId);
        const rewardPerShare2 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);

        expect(clusterDelegation).to.equal(clusterDelegationInit.add(amount1));
        expect(delegation).to.equal(delegationInit.add(amount1));
        // as there is only pond token all reward  is given to pond token
        expect(rewardPerShare2.sub(rewardPerShare1)).to.equal(rewardAmount.sub(clusterCommission).mul(e30).div(clusterDelegationInit));

        // ----------------- Gives reward when previous delegation is non 0 and user has prev rewards, no new rewards for cluster ---------------
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(0);

        clusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        delegationInit = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        let delegatorCurrentReward = rewardPerShare2.sub(rewardPerShare).mul(delegationInit).div(e30);
        await expect(rewardDelegators.connect(imperonatedStakeManager).delegate(delegator, cluster, [pondTokenId], [amount1]))
            .to.changeTokenBalances(
                pond, 
                [rewardDelegators, rewardAddress, delegator], 
                [-delegatorCurrentReward, 0, delegatorCurrentReward]
            );
        clusterDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        delegation = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        const rewardPerShare3 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);

        expect(clusterDelegation).to.equal(clusterDelegationInit.add(amount1));
        expect(delegation).to.equal(delegationInit.add(amount1));
        expect(rewardPerShare3).to.equal(rewardPerShare2);

        // ----------------- Give new rewards to cluster ---------------
        const rewardAmount1 = rewardAmount.mul(2).div(3);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(rewardAmount1);
        clusterCommission = rewardAmount1.mul(commission).div(100);
        await expect(rewardDelegators._updateRewards(cluster)).to.changeTokenBalances(
            pond,
            [rewardDelegators, rewardAddress, delegator, delegator1],
            [-clusterCommission, clusterCommission, 0, 0]
        );
        const rewardPerShare4 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);

        expect(rewardPerShare4.sub(rewardPerShare3)).to.equal(rewardAmount1.sub(clusterCommission).mul(e30).div(clusterDelegation));

        // ----------------- Gives reward when previous delegation is non 0 and user has prev rewards, new rewards for cluster ---------------
        const amount2 = FuzzedNumber.randomInRange(100000, 500000);

        clusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        delegationInit = await rewardDelegators.getDelegation(cluster, delegator1, pondTokenId);
        // TODO: fix the add(1) at the end
        let delegator1CurrentReward = rewardPerShare4.add(rewardAmount1.sub(clusterCommission).mul(e30).div(clusterDelegationInit)).sub(rewardPerShare2).mul(delegationInit).div(e30).add(1);
        clusterCommission = rewardAmount1.mul(commission).div(100);
        await expect(rewardDelegators.connect(imperonatedStakeManager).delegate(delegator1, cluster, [pondTokenId], [amount2]))
            .to.changeTokenBalances(
                pond,
                [rewardDelegators, rewardAddress, delegator1], 
                [-(delegator1CurrentReward.add(clusterCommission)), clusterCommission, delegator1CurrentReward]
            );
        clusterDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        delegation = await rewardDelegators.getDelegation(cluster, delegator1, pondTokenId);
        const rewardPerShare5 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);

        expect(clusterDelegation).to.equal(clusterDelegationInit.add(amount2));
        expect(delegation).to.equal(delegationInit.add(amount2));
        expect(rewardPerShare5.sub(rewardPerShare4)).to.equal(rewardAmount1.sub(clusterCommission).mul(e30).div(clusterDelegationInit));

        // ----------------- Gives reward when previous delegation is non 0 and user has prev rewards, new rewards for cluster,0 commission ---------------
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster).returns(0, rewardAddress);

        clusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        delegationInit = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        delegatorCurrentReward = rewardPerShare5.add(rewardAmount1.mul(e30).div(clusterDelegationInit)).sub(rewardPerShare3).mul(delegationInit).div(e30).add(1);
        await expect(rewardDelegators.connect(imperonatedStakeManager).delegate(delegator, cluster, [pondTokenId], [amount2]))
            .to.changeTokenBalances(
                pond, 
                [rewardDelegators, rewardAddress, delegator], 
                [-(delegatorCurrentReward), 0, delegatorCurrentReward]
            );
        clusterDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        delegation = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        const rewardPerShare6 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);

        expect(clusterDelegation).to.equal(clusterDelegationInit.add(amount2));
        expect(delegation).to.equal(delegationInit.add(amount2));
        expect(rewardPerShare6.sub(rewardPerShare5)).to.equal(rewardAmount1.mul(e30).div(clusterDelegationInit));
    });

    it("delegate to cluster multiple tokens", async () => {
        const delegator = await delegators[0].getAddress();
        const delegator1 = await delegators[1].getAddress();
        const cluster = await registeredClusters[FuzzedNumber.randomInRange(0, registeredClusters.length).toNumber()].getAddress();
        const rewardAddress = registeredClusterRewardAddresses[FuzzedNumber.randomInRange(0, registeredClusterRewardAddresses.length).toNumber()];
        const networkId = ethers.utils.id("ETH");

        let rewardAmount = FuzzedNumber.randomInRange(100000, 500000);
        let commission = FuzzedNumber.randomInRange(0, 100);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(rewardAmount);
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster).returns(commission, rewardAddress);
        await fakeClusterRegistry.mock.getNetwork.withArgs(cluster).returns(networkId);
        await fakeClusterSelectors["ETH"].mock.upsert.returns();

        // ----------------- Give reward when previous total delegation and user has no prev rewards ---------------
        const amount1 = FuzzedNumber.randomInRange(e20, e22);
        const mpondAmount1 = FuzzedNumber.randomInRange(e16, e18);
        await expect(rewardDelegators.delegate(delegator, cluster, [pondTokenId, mpondTokenId], [amount1, mpondAmount1]))
            .to.be.revertedWith("RD:OS-only stake contract can invoke");

        let clusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        let mpondClusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        let delegationInit = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        let mpondDelegationInit = await rewardDelegators.getDelegation(cluster, delegator, mpondTokenId);
        let rewardPerShare =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        let mpondRewardPerShare =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);
        await expect(rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator, 
            cluster, 
            [pondTokenId, mpondTokenId], 
            [amount1, mpondAmount1])
        ).to.changeTokenBalances(
            pond, 
            [rewardDelegators, rewardAddress, delegator], 
            [-(commission.mul(rewardAmount).div(100)), commission.mul(rewardAmount).div(100), 0]
        );
        let clusterDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        let mpondClusterDelegation = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        let delegation = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        let mpondDelegation = await rewardDelegators.getDelegation(cluster, delegator, mpondTokenId);
        let rewardPerShare1 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        let mpondRewardPerShare1 =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);

        expect(clusterDelegation).to.equal(clusterDelegationInit.add(amount1));
        expect(mpondClusterDelegation).to.equal(mpondClusterDelegationInit.add(mpondAmount1));
        expect(delegation).to.equal(delegationInit.add(amount1));
        expect(mpondDelegation).to.equal(mpondDelegationInit.add(mpondAmount1));
        expect(rewardPerShare1.sub(rewardPerShare)).to.equal(0);
        expect(mpondRewardPerShare1.sub(mpondRewardPerShare)).to.equal(0);

        // ----------------- Give reward when previous total delegation is non 0 and user has no prev rewards ---------------
        clusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        mpondClusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        delegationInit = await rewardDelegators.getDelegation(cluster, delegator1, pondTokenId);
        mpondDelegationInit = await rewardDelegators.getDelegation(cluster, delegator1, mpondTokenId);
        rewardPerShare =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        mpondRewardPerShare =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);
        let clusterCommission = commission.mul(rewardAmount).div(100);
        await expect(rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator1, 
            cluster, 
            [pondTokenId, mpondTokenId], 
            [amount1, mpondAmount1])
        ).to.changeTokenBalances(
            pond, 
            [rewardDelegators, rewardAddress, delegator1], 
            [-clusterCommission, clusterCommission, 0]
        );
        clusterDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        mpondClusterDelegation = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        delegation = await rewardDelegators.getDelegation(cluster, delegator1, pondTokenId);
        mpondDelegation = await rewardDelegators.getDelegation(cluster, delegator1, mpondTokenId);
        const rewardPerShare2 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        const mpondRewardPerShare2 =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);

        expect(clusterDelegation).to.equal(clusterDelegationInit.add(amount1));
        expect(mpondClusterDelegation).to.equal(mpondClusterDelegationInit.add(mpondAmount1));
        expect(delegation).to.equal(delegationInit.add(amount1));
        expect(mpondDelegation).to.equal(mpondDelegationInit.add(mpondAmount1));
        expect(rewardPerShare2.sub(rewardPerShare1)).to.equal(rewardAmount.sub(clusterCommission).mul(e30).div(2).div(clusterDelegationInit));
        expect(mpondRewardPerShare2.sub(mpondRewardPerShare1)).to.equal(rewardAmount.sub(clusterCommission).mul(e30).div(2).div(mpondClusterDelegationInit));

        // ----------------- Gives reward when previous delegation is non 0 and user has prev rewards, no new rewards for cluster ---------------
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(0);

        clusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        mpondClusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        delegationInit = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        mpondDelegationInit = await rewardDelegators.getDelegation(cluster, delegator, mpondTokenId);
        let delegatorCurrentReward = rewardPerShare2.sub(rewardPerShare).mul(delegationInit).div(e30);
        let delegatorCurrentRewardMpond = mpondRewardPerShare2.sub(mpondRewardPerShare).mul(mpondDelegationInit).div(e30);
        await expect(rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator, 
            cluster, 
            [pondTokenId, mpondTokenId], 
            [amount1, mpondAmount1])
        ).to.changeTokenBalances(
            pond, 
            [rewardDelegators, rewardAddress, delegator], 
            [-delegatorCurrentReward.add(delegatorCurrentRewardMpond), 0, delegatorCurrentReward.add(delegatorCurrentRewardMpond)]
        );
        clusterDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        mpondClusterDelegation = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        delegation = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        mpondDelegation = await rewardDelegators.getDelegation(cluster, delegator, mpondTokenId);
        const rewardPerShare3 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        const mpondRewardPerShare3 =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);

        expect(clusterDelegation).to.equal(clusterDelegationInit.add(amount1));
        expect(mpondClusterDelegation).to.equal(mpondClusterDelegationInit.add(mpondAmount1));
        expect(delegation).to.equal(delegationInit.add(amount1));
        expect(mpondDelegation).to.equal(mpondDelegationInit.add(mpondAmount1));
        expect(rewardPerShare3.sub(rewardPerShare2)).to.equal(0);
        expect(mpondRewardPerShare3.sub(mpondRewardPerShare2)).to.equal(0);

        // ----------------- Give new rewards to cluster ---------------
        const rewardAmount1 = rewardAmount.mul(2).div(3);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(rewardAmount1);
        clusterCommission = rewardAmount1.mul(commission).div(100);
        await expect(rewardDelegators._updateRewards(cluster)).to.changeTokenBalances(
            pond,
            [rewardDelegators, rewardAddress, delegator, delegator1],
            [-clusterCommission, clusterCommission, 0, 0]
        );
        const rewardPerShare4 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        const mpondRewardPerShare4 =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);

        expect(rewardPerShare4.sub(rewardPerShare3)).to.equal(rewardAmount1.sub(clusterCommission).mul(e30).div(2).div(clusterDelegation));
        expect(mpondRewardPerShare4.sub(mpondRewardPerShare3)).to.equal(rewardAmount1.sub(clusterCommission).mul(e30).div(2).div(mpondClusterDelegation));

        // ----------------- Gives reward when previous delegation is non 0 and user has prev rewards, new rewards for cluster ---------------
        const amount2 = FuzzedNumber.randomInRange(100000, 500000);
        const mpondAmount2 = FuzzedNumber.randomInRange(100, 500);

        clusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        mpondClusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        delegationInit = await rewardDelegators.getDelegation(cluster, delegator1, pondTokenId);
        mpondDelegationInit = await rewardDelegators.getDelegation(cluster, delegator1, mpondTokenId);
        // TODO: Fix add(1) at the end
        let delegator1CurrentReward = rewardPerShare4.add(rewardAmount1.sub(clusterCommission).mul(e30).div(2).div(clusterDelegationInit)).sub(rewardPerShare2).mul(delegationInit).div(e30).add(1);
        let delegator1CurrentRewardMpond = mpondRewardPerShare4.add(rewardAmount1.sub(clusterCommission).mul(e30).div(2).div(mpondClusterDelegation)).sub(mpondRewardPerShare2).mul(mpondDelegationInit).div(e30).add(1);
        clusterCommission = rewardAmount1.mul(commission).div(100);
        const balancesBefore = await Promise.all([rewardDelegators.address, rewardAddress, delegator1].map(async(a) => await pond.balanceOf(a)))
        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator1, 
            cluster, 
            [pondTokenId, mpondTokenId], 
            [amount2, mpondAmount2])
        const balancesAfter = await Promise.all([rewardDelegators.address, rewardAddress, delegator1].map(async(a) => await pond.balanceOf(a)))
        const balancesChange = balancesAfter.map((a, index) => a.sub(balancesBefore[index]))
        
        expect(balancesChange[0]).to.closeTo(-delegator1CurrentReward.add(delegator1CurrentRewardMpond).add(clusterCommission), 2)
        expect(balancesChange[1]).to.closeTo(clusterCommission, 0)
        expect(balancesChange[2]).to.closeTo(delegator1CurrentReward.add(delegator1CurrentRewardMpond), 0)

        clusterDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        mpondClusterDelegation = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        delegation = await rewardDelegators.getDelegation(cluster, delegator1, pondTokenId);
        mpondDelegation = await rewardDelegators.getDelegation(cluster, delegator1, mpondTokenId);
        const rewardPerShare5 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        const mpondRewardPerShare5 =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);

        expect(clusterDelegation).to.equal(clusterDelegationInit.add(amount2));
        expect(mpondClusterDelegation).to.equal(mpondClusterDelegationInit.add(mpondAmount2));
        expect(delegation).to.equal(delegationInit.add(amount2));
        expect(mpondDelegation).to.equal(mpondDelegationInit.add(mpondAmount2));
        expect(rewardPerShare5.sub(rewardPerShare4).div(e14)).to.equal(rewardAmount1.sub(clusterCommission).div(2).mul(e30).div(clusterDelegationInit).div(e14));
        expect(mpondRewardPerShare5.sub(mpondRewardPerShare4).div(e14)).to.equal(rewardAmount1.sub(clusterCommission).div(2).mul(e30).div(mpondClusterDelegation).div(e14));

        // ----------------- Gives reward when previous delegation is non 0 and user has prev rewards, new rewards for cluster,0 commission ---------------
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster).returns(0, rewardAddress);

        clusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        mpondClusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        delegationInit = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        mpondDelegationInit = await rewardDelegators.getDelegation(cluster, delegator, mpondTokenId);
        // TODO: Fix add(1) at the end
        let changeInRewardPerShare = rewardAmount1.mul(e30).div(2).div(clusterDelegationInit);
        let changeInRewardPerShareMpond = rewardAmount1.mul(e30).div(2).div(mpondClusterDelegation);
        delegatorCurrentReward = rewardPerShare5.add(changeInRewardPerShare).sub(rewardPerShare3).mul(delegationInit).div(e30).add(1);
        delegatorCurrentRewardMpond = mpondRewardPerShare5.add(changeInRewardPerShareMpond).sub(mpondRewardPerShare3).mul(mpondDelegationInit).div(e30).add(1);
        await expect(rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator, 
            cluster, 
            [pondTokenId, mpondTokenId], 
            [amount2, mpondAmount2])
        ).to.changeTokenBalances(
            pond, 
            [rewardDelegators, rewardAddress, delegator], 
            [-delegatorCurrentReward.add(delegatorCurrentRewardMpond), 0, delegatorCurrentReward.add(delegatorCurrentRewardMpond)]
        );
        clusterDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        mpondClusterDelegation = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        delegation = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        mpondDelegation = await rewardDelegators.getDelegation(cluster, delegator, mpondTokenId);
        const rewardPerShare6 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        const mpondRewardPerShare6 =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);

        expect(clusterDelegation).to.equal(clusterDelegationInit.add(amount2));
        expect(mpondClusterDelegation).to.equal(mpondClusterDelegationInit.add(mpondAmount2));
        expect(delegation).to.equal(delegationInit.add(amount2));
        expect(mpondDelegation).to.equal(mpondDelegationInit.add(mpondAmount2));
        expect(rewardPerShare6.sub(rewardPerShare5)).to.equal(changeInRewardPerShare);
        expect(mpondRewardPerShare6.sub(mpondRewardPerShare5)).to.equal(changeInRewardPerShareMpond);
    });

    it("undelegate from cluster", async () => {
        const delegator = await delegators[0].getAddress();
        const delegator1 = await delegators[1].getAddress();
        const cluster = await registeredClusters[FuzzedNumber.randomInRange(0, registeredClusters.length).toNumber()].getAddress();
        const rewardAddress = registeredClusterRewardAddresses[FuzzedNumber.randomInRange(0, registeredClusterRewardAddresses.length).toNumber()];
        const networkId = ethers.utils.id("ETH");

        let rewardAmount = FuzzedNumber.randomInRange(100000, 500000);
        let commission = FuzzedNumber.randomInRange(0, 100);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(rewardAmount);
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster).returns(commission, rewardAddress);
        await fakeClusterRegistry.mock.getNetwork.withArgs(cluster).returns(networkId);
        await fakeClusterSelectors["ETH"].mock.upsert.returns();
        // ----------------- Setup clusters and their delegations ---------------
        const amount1 = FuzzedNumber.randomInRange(e18, e20);
        const mpondAmount1 = FuzzedNumber.randomInRange(e18, e20);
        const amount2 = FuzzedNumber.randomInRange(e18, e20);
        const mpondAmount2 = FuzzedNumber.randomInRange(e18, e20);
        await rewardDelegators.connect(imperonatedStakeManager).delegate(delegator, cluster, [pondTokenId, mpondTokenId], [amount1, mpondAmount1]);
        const rewardPerShare1 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        const mpondRewardPerShare1 =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);
        await rewardDelegators.connect(imperonatedStakeManager).delegate(delegator1, cluster, [pondTokenId, mpondTokenId], [amount2, mpondAmount2]);
        const rewardPerShare2 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        const mpondRewardPerShare2 =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);

        // ----------------- Undelegate when there are rewards for delegator and no new rewards for cluster ---------------
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(0);

        await expect(rewardDelegators.undelegate(
            delegator, 
            cluster, 
            [pondTokenId, mpondTokenId], 
            [amount1.mul(1).div(3), mpondAmount1.mul(1).div(3)])
        ).to.be.revertedWith("RD:OS-only stake contract can invoke");

        let clusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        let mpondClusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        let delegationInit = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        let mpondDelegationInit = await rewardDelegators.getDelegation(cluster, delegator, mpondTokenId);
        let delegatorCurrentReward = rewardPerShare2.sub(rewardPerShare1).mul(delegationInit).div(e30);
        let delegatorCurrentRewardMpond = mpondRewardPerShare2.sub(mpondRewardPerShare1).mul(mpondDelegationInit).div(e30);
        await expect(rewardDelegators.connect(imperonatedStakeManager).undelegate(
            delegator, 
            cluster, 
            [pondTokenId, mpondTokenId], 
            [amount1.div(3), mpondAmount1.div(3)])
        ).to.changeTokenBalances(
            pond, 
            [rewardDelegators, rewardAddress, delegator], 
            [-(delegatorCurrentReward.add(delegatorCurrentRewardMpond)), 0, delegatorCurrentReward.add(delegatorCurrentRewardMpond)]
        );
        let clusterDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        let mpondClusterDelegation = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        let delegation = await rewardDelegators.getDelegation(cluster, delegator, pondTokenId);
        let mpondDelegation = await rewardDelegators.getDelegation(cluster, delegator, mpondTokenId);
        let rewardPerShare3 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        let mpondRewardPerShare3 =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);

        expect(clusterDelegation).to.equal(clusterDelegationInit.sub(amount1.div(3)));
        expect(mpondClusterDelegation).to.equal(mpondClusterDelegationInit.sub(mpondAmount1.div(3)));
        expect(delegation).to.equal(delegationInit.sub(amount1.div(3)));
        expect(mpondDelegation).to.equal(mpondDelegationInit.sub(mpondAmount1.div(3)));
        expect(rewardPerShare3.sub(rewardPerShare2)).to.equal(0);
        expect(mpondRewardPerShare3.sub(mpondRewardPerShare2)).to.equal(0);

        // ----------------- Give new rewards to cluster ---------------
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(rewardAmount);

        const rewardAmount1 = rewardAmount.mul(2).div(3);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(rewardAmount1);
        let clusterCommission = rewardAmount1.mul(commission).div(100);
        await expect(rewardDelegators._updateRewards(cluster)).to.changeTokenBalances(
            pond,
            [rewardDelegators, rewardAddress, delegator, delegator1],
            [-clusterCommission, clusterCommission, 0, 0]
        );
        const rewardPerShare4 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        const mpondRewardPerShare4 =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);

        expect(rewardPerShare4.sub(rewardPerShare3)).to.equal(rewardAmount1.sub(clusterCommission).mul(e30).div(2).div(clusterDelegation));
        expect(mpondRewardPerShare4.sub(mpondRewardPerShare3)).to.equal(rewardAmount1.sub(clusterCommission).mul(e30).div(2).div(mpondClusterDelegation));

        // ----------------- Undelegate when there are rewards for delegator and new rewards for cluster ---------------
        clusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        mpondClusterDelegationInit = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        delegationInit = await rewardDelegators.getDelegation(cluster, delegator1, pondTokenId);
        mpondDelegationInit = await rewardDelegators.getDelegation(cluster, delegator1, mpondTokenId);
        // TODO: Fix add(1) at the end
        let changeInRewardPerShare = rewardAmount1.sub(clusterCommission).mul(e30).div(2).div(clusterDelegation);
        let changeInRewardPerShareMpond = rewardAmount1.sub(clusterCommission).mul(e30).div(2).div(mpondClusterDelegation);
        delegatorCurrentReward = rewardPerShare4.add(changeInRewardPerShare).sub(rewardPerShare2).mul(delegationInit).div(e30).add(1);
        delegatorCurrentRewardMpond = mpondRewardPerShare4.add(changeInRewardPerShareMpond).sub(mpondRewardPerShare2).mul(mpondDelegationInit).div(e30).add(1);
        clusterCommission = commission.mul(rewardAmount1).div(100);

        const balancesBefore = await Promise.all([rewardDelegators.address, rewardAddress, delegator1].map(async(a) => await pond.balanceOf(a)))
        await rewardDelegators.connect(imperonatedStakeManager).undelegate(
            delegator1, 
            cluster, 
            [pondTokenId, mpondTokenId], 
            [amount2.div(2), mpondAmount2.div(2)])
        const balanceAfter = await Promise.all([rewardDelegators.address, rewardAddress, delegator1].map(async(a) => await pond.balanceOf(a)))
        const balanceChange = balanceAfter.map((a,index) => a.sub(balancesBefore[index]))
        
        expect(balanceChange[0]).to.closeTo(-(delegatorCurrentReward.add(delegatorCurrentRewardMpond).add(clusterCommission)), 2)
        expect(balanceChange[1]).to.closeTo(clusterCommission, 2)
        expect(balanceChange[2]).to.closeTo(delegatorCurrentReward.add(delegatorCurrentRewardMpond), 2)
        
        clusterDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        mpondClusterDelegation = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        delegation = await rewardDelegators.getDelegation(cluster, delegator1, pondTokenId);
        mpondDelegation = await rewardDelegators.getDelegation(cluster, delegator1, mpondTokenId);
        let rewardPerShare5 =  await rewardDelegators.getAccRewardPerShare(cluster, pondTokenId);
        let mpondRewardPerShare5 =  await rewardDelegators.getAccRewardPerShare(cluster, mpondTokenId);

        expect(clusterDelegation).to.equal(clusterDelegationInit.sub(amount2.div(2)));
        expect(mpondClusterDelegation).to.equal(mpondClusterDelegationInit.sub(mpondAmount2.div(2)));
        expect(delegation).to.equal(delegationInit.sub(amount2.div(2)));
        expect(mpondDelegation).to.equal(mpondDelegationInit.sub(mpondAmount2.div(2)));
        expect(rewardPerShare5.sub(rewardPerShare4)).to.equal(changeInRewardPerShare);
        expect(mpondRewardPerShare5.sub(mpondRewardPerShare4)).to.equal(changeInRewardPerShareMpond);

        // ----------------- Undelegate only pond when there are rewards for delegator and new rewards for cluster ---------------

        // ----------------- Undelegate only mpond when there are rewards for delegator and new rewards for cluster ---------------
    });

    it("update cluster delegation", async () => {
        const delegator = await delegators[0].getAddress();
        const delegator1 = await delegators[1].getAddress();
        const cluster = await registeredClusters[0].getAddress();
        const cluster1 = await registeredClusters[1].getAddress();
        const cluster2 = await registeredClusters[2].getAddress();
        const rewardAddress = registeredClusterRewardAddresses[FuzzedNumber.randomInRange(0, registeredClusterRewardAddresses.length).toNumber()];
        const networkId = ethers.utils.id("ETH");

        let rewardAmount = FuzzedNumber.randomInRange(100000, 500000);
        let commission = FuzzedNumber.randomInRange(0, 100);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(rewardAmount);
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster).returns(commission, rewardAddress);
        await fakeClusterRegistry.mock.getNetwork.withArgs(cluster).returns(networkId);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster1).returns(rewardAmount);
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster1).returns(commission, rewardAddress);
        await fakeClusterRegistry.mock.getNetwork.withArgs(cluster1).returns(networkId);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster2).returns(rewardAmount);
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster2).returns(commission, rewardAddress);
        await fakeClusterRegistry.mock.getNetwork.withArgs(cluster2).returns(networkId);
        await fakeClusterSelectors["ETH"].mock.upsert.returns();

        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator, 
            cluster,
            [pondTokenId],
            [10000000000]
        );
        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator, 
            cluster1,
            [mpondTokenId],
            [6]
        );
        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator, 
            cluster2,
            [mpondTokenId],
            [10]
        );

        await fakeClusterSelectors["ETH"].mock.upsert.revertsWithReason("unexpected upsert");
        await fakeClusterSelectors["ETH"].mock.deleteIfPresent.revertsWithReason("unexpected delete");

        await rewardDelegators.updateThresholdForSelection(networkId, 10000000);
        await expect(rewardDelegators.connect(impersonatedClusterRegistry).updateClusterDelegation(cluster, networkId))
            .to.be.revertedWith("unexpected delete");
        await expect(rewardDelegators.connect(impersonatedClusterRegistry).updateClusterDelegation(cluster1, networkId))
            .to.be.revertedWith("unexpected delete");
        await expect(rewardDelegators.connect(impersonatedClusterRegistry).updateClusterDelegation(cluster2, networkId))
            .to.be.revertedWith("unexpected upsert");

        await rewardDelegators.updateThresholdForSelection(networkId, 0);
        await fakeClusterSelectors["ETH"].mock.upsert.returns();
        await fakeClusterSelectors["ETH"].mock.deleteIfPresent.returns();
        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator, 
            cluster,
            [mpondTokenId],
            [12]
        );
        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator, 
            cluster1,
            [pondTokenId],
            [4000000]
        );
        await rewardDelegators.connect(imperonatedStakeManager).undelegate(delegator, cluster2, [mpondTokenId], [1]);

        await rewardDelegators.updateThresholdForSelection(networkId, 10000000);
        await fakeClusterSelectors["ETH"].mock.upsert.revertsWithReason("upsert called");
        await fakeClusterSelectors["ETH"].mock.deleteIfPresent.revertsWithReason("delete called");
        await rewardDelegators.connect(impersonatedClusterRegistry).updateClusterDelegation(cluster, ethers.utils.id("RANDOM"));

        await expect(rewardDelegators.connect(impersonatedClusterRegistry).updateClusterDelegation(cluster, networkId))
            .to.be.revertedWith("upsert called");
        await expect(rewardDelegators.connect(impersonatedClusterRegistry).updateClusterDelegation(cluster1, networkId))
            .to.be.revertedWith("delete called");
        await expect(rewardDelegators.connect(impersonatedClusterRegistry).updateClusterDelegation(cluster2, networkId))
            .to.be.revertedWith("delete called");
    });

    it("remove cluster delegation", async () => {
        const cluster = await registeredClusters[0].getAddress();
        await fakeClusterSelectors["ETH"].mock.deleteIfPresent.revertsWithReason("delete called");
        expect(fakeClusterSelectors["ETH"].address).to.not.equal(ethers.constants.AddressZero);
        await rewardDelegators.connect(impersonatedClusterRegistry).removeClusterDelegation(cluster, ethers.utils.id("RANDOM"));
        await expect(rewardDelegators.connect(impersonatedClusterRegistry).removeClusterDelegation(cluster, ethers.utils.id("ETH")))
            .to.be.revertedWith("delete called");
    });

    it("withdraw rewards", async () => {
        const delegator = await delegators[0].getAddress();
        const delegator1 = await delegators[1].getAddress();
        const cluster = await registeredClusters[0].getAddress();
        const cluster1 = await registeredClusters[1].getAddress();
        const cluster2 = await registeredClusters[2].getAddress();
        const rewardAddress = registeredClusterRewardAddresses[FuzzedNumber.randomInRange(0, registeredClusterRewardAddresses.length).toNumber()];
        const networkId = ethers.utils.id("ETH");

        let commission = FuzzedNumber.randomInRange(0, 100).toNumber();
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(0);
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster).returns(commission, rewardAddress);
        await fakeClusterRegistry.mock.getNetwork.withArgs(cluster).returns(networkId);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster1).returns(0);
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster1).returns(commission, rewardAddress);
        await fakeClusterRegistry.mock.getNetwork.withArgs(cluster1).returns(networkId);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster2).returns(0);
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster2).returns(commission, rewardAddress);
        await fakeClusterRegistry.mock.getNetwork.withArgs(cluster2).returns(networkId);
        await fakeClusterSelectors["ETH"].mock.upsert.returns();
        
        // TODO: fix this
        // await expect(rewardDelegators["withdrawRewards(address,address)"](delegator, cluster))
        //     .to.changeTokenBalances(pond, [rewardDelegators.address, delegator, cluster], [0, 0, 0]);

        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator, 
            cluster,
            [pondTokenId],
            [20000000]
        );
        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator1, 
            cluster1,
            [pondTokenId],
            [100000]
        );
        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator1,
            cluster,
            [pondTokenId, mpondTokenId],
            [4000000, 6]
        );
        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator1, 
            cluster2,
            [mpondTokenId],
            [10]
        );
        let reward = 100000000;
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(reward);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster1).returns(reward);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster2).returns(reward);
        await rewardDelegators._updateRewards(cluster);
        await rewardDelegators._updateRewards(cluster1);
        await rewardDelegators._updateRewards(cluster2);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(0);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster1).returns(0);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster2).returns(0);
        
        let rewardAfterCommission = reward*(100-commission)/100;
        let delegatorClusterReward = Math.floor(rewardAfterCommission*20000000/(20000000 + 4000000)/2);
        await expect(rewardDelegators["withdrawRewards(address,address)"](delegator, cluster))
            .to.changeTokenBalances(pond, [rewardDelegators.address, delegator, cluster], [-delegatorClusterReward, delegatorClusterReward, 0]);
        await expect(rewardDelegators["withdrawRewards(address,address)"](delegator1, cluster1))
            .to.changeTokenBalances(pond, [rewardDelegators.address, delegator1, cluster1], [-rewardAfterCommission, rewardAfterCommission, 0]);

        await expect(rewardDelegators["withdrawRewards(address,address)"](delegator1, cluster2))
            .to.changeTokenBalances(pond, [rewardDelegators.address, delegator1, cluster2], [-rewardAfterCommission, rewardAfterCommission, 0]);

        const balancesBefore = await Promise.all([rewardDelegators.address, delegator1, cluster].map(async(a) => await pond.balanceOf(a)))
        await rewardDelegators["withdrawRewards(address,address)"](delegator1, cluster)
        const balancesAfter = await Promise.all([rewardDelegators.address, delegator1, cluster].map(async(a) => await pond.balanceOf(a)))
        const balanceChange = balancesBefore.map((a, index) => balancesAfter[index].sub(a))

        expect(balanceChange[0]).to.be.closeTo(-(rewardAfterCommission - delegatorClusterReward), 2)
        expect(balanceChange[1]).to.be.closeTo(rewardAfterCommission - delegatorClusterReward, 2)
        expect(balanceChange[2]).to.be.closeTo(0, 0)

        // no reward when already withdrawn
        await expect(rewardDelegators["withdrawRewards(address,address)"](delegator1, cluster1))
            .to.changeTokenBalances(pond, [rewardDelegators.address, delegator1, cluster1], [0, 0, 0]);

        await expect(rewardDelegators["withdrawRewards(address,address)"](delegator1, cluster2))
            .to.changeTokenBalances(pond, [rewardDelegators.address, delegator1, cluster2], [0, 0, 0]);

        await expect(rewardDelegators["withdrawRewards(address,address)"](delegator1, cluster))
            .to.changeTokenBalances(pond, [rewardDelegators.address, delegator1, cluster], [0, 0, 0]);
    });

    it("refresh cluster delegation", async () => {
        const delegator = await delegators[0].getAddress();
        const delegator1 = await delegators[1].getAddress();
        const cluster = await registeredClusters[0].getAddress();
        const cluster1 = await registeredClusters[1].getAddress();
        const cluster2 = await registeredClusters[2].getAddress();
        const rewardAddress = registeredClusterRewardAddresses[FuzzedNumber.randomInRange(0, registeredClusterRewardAddresses.length).toNumber()];
        const networkId = ethers.utils.id("ETH");

        let rewardAmount = FuzzedNumber.randomInRange(100000, 500000);
        let commission = FuzzedNumber.randomInRange(0, 100);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster).returns(0);
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster).returns(commission, rewardAddress);
        await fakeClusterRegistry.mock.getNetwork.withArgs(cluster).returns(networkId);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster1).returns(0);
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster1).returns(commission, rewardAddress);
        await fakeClusterRegistry.mock.getNetwork.withArgs(cluster1).returns(networkId);
        await fakeClusterRewards.mock.claimReward.withArgs(cluster2).returns(0);
        await fakeClusterRegistry.mock.getRewardInfo.withArgs(cluster2).returns(commission, rewardAddress);
        await fakeClusterRegistry.mock.getNetwork.withArgs(cluster2).returns(networkId);
        await fakeClusterSelectors["ETH"].mock.upsert.returns();

        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator, 
            cluster,
            [pondTokenId],
            [1000000]
        );
        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator1, 
            cluster1,
            [pondTokenId],
            [10000]
        );
        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator1,
            cluster,
            [pondTokenId, mpondTokenId],
            [2000000, 6]
        );
        await rewardDelegators.connect(imperonatedStakeManager).delegate(
            delegator1, 
            cluster2,
            [mpondTokenId],
            [100]
        );

        await fakeClusterSelectors["ETH"].mock.upsertMultiple.withArgs([cluster, cluster1, cluster2], [3000, 100, 10000]).returns();
        await rewardDelegators.refreshClusterDelegation(networkId, [cluster, cluster1, cluster2]);
        await fakeClusterSelectors["ETH"].mock.upsertMultiple.withArgs([cluster, cluster1, cluster2], [3000, 100, 10000]).reverts();

        await rewardDelegators.updateThresholdForSelection(networkId, 1000000);
        await fakeClusterSelectors["ETH"].mock.upsertMultiple.withArgs([cluster, cluster2], [3000, 10000]).returns();
        await rewardDelegators.refreshClusterDelegation(networkId, [cluster, cluster1, cluster2]);
        await fakeClusterSelectors["ETH"].mock.upsertMultiple.withArgs([cluster, cluster2], [3000, 10000]).reverts();

        await rewardDelegators.updateThresholdForSelection(networkId, 6000000);
        await fakeClusterSelectors["ETH"].mock.upsertMultiple.withArgs([cluster, cluster2], [3000, 10000]).returns();
        await rewardDelegators.refreshClusterDelegation(networkId, [cluster, cluster1, cluster2]);
        await fakeClusterSelectors["ETH"].mock.upsertMultiple.withArgs([cluster, cluster2], [3000, 10000]).reverts();

        await rewardDelegators.updateThresholdForSelection(networkId, 6000001);
        await fakeClusterSelectors["ETH"].mock.upsertMultiple.withArgs([cluster2], [10000]).returns();
        await rewardDelegators.refreshClusterDelegation(networkId, [cluster, cluster1, cluster2]);
        await fakeClusterSelectors["ETH"].mock.upsertMultiple.withArgs([cluster2], [10000]).reverts();
    });
});