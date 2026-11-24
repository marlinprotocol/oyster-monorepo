import { expect } from "chai";
import { BigNumber as BN, Signer } from "ethers";
import { ethers, upgrades } from "hardhat";
import {
  ArbGasInfo__factory,
  ClusterRegistry,
  ClusterRewards,
  ClusterSelector,
  MPond,
  Pond,
  ReceiverStaking,
  RewardDelegators,
  StakeManager,
} from "../../typechain-types";
import { FuzzedNumber } from "../../utils/fuzzer";
import { saveAndRestoreStateToParent, takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";

import {
  getClusterRegistry,
  getClusterRewards,
  getClusterSelector,
  getMpond,
  getPond,
  getReceiverStaking,
  getRewardDelegators,
  getStakeManager,
} from "../../utils/typechainConvertor";
import { BIG_ZERO, getRandomElementsFromArray, random, skipTime } from "../helpers/common";
const stakingConfig = require("../config/staking.json");

const UNDELEGATION_WAIT_TIME = 604800;
const REDELEGATION_WAIT_TIME = 21600;
const REWARD_PER_EPOCH = BN.from(10).pow(21).mul(35);
const MAX_TICKETS = BN.from(2).pow(16)

describe("Integration", function () {
  let signers: Signer[];

  let pond: Pond;
  let mpond: MPond;

  let pondTokenId: string;
  let mpondTokenId: string;

  let stakeManager: StakeManager;
  let rewardDelegators: RewardDelegators;
  let clusterRewards: ClusterRewards;
  let clusterRegistry: ClusterRegistry;
  let receiverStaking: ReceiverStaking;

  //users
  let clusterRewardsAdmin: Signer;
  let stakeManagerGateway: Signer;
  let clusterSelectorAdmin: Signer;
  let stakeManagerAdmin: Signer;
  let receiverStakingAdmin: Signer;
  let mpondWhiteListedAddress: Signer;
  let pondHoldingAddress: Signer;
  let rewardDelegatorAdmin: Signer;

  let clusters: Signer[];
  let delegators: Signer[];
  let receivers: Signer[];
  let invalidReceivers: Signer[];
  let ethClusters: Signer[];
  let dotClusters: Signer[];
  let maticClusters: Signer[];

  let ethReceivers: Signer[];
  let dotReceivers: Signer[];
  let maticReceivers: Signer[];

  let ethDelegators: Signer[];
  let dotDelegators: Signer[];
  let maticDelegators: Signer[];

  //networks data
  const supportedNetworks = ["ETH", "DOT", "MATIC"];
  const supportedNetworksWeights = [50, 30, 20];
  const supportedNetworkIds = supportedNetworks.map((a) => ethers.utils.id(a));
  const lockWaitTimes = [20, 21, 22];
  const clusterSelectors: ClusterSelector[] = [];

  // derived data;
  let clusterAddresses: string[];
  let delegatorAddresss: string[];
  let receiverAddresses: string[];
  let epochDuration: number;

  let ethClusterAddresses: string[];
  let dotClusterAddresses: string[];
  let maticClusterAddresses: string[];

  const minMPondToUse = BN.from(10).pow(18).div(2);
  const maxMPondToUse = BN.from(10).pow(19);

  const minPondToUse = minMPondToUse.mul("1000000");
  const maxPondToUse = maxMPondToUse.mul("10000000");

  const minPondToUseByReceiver = BN.from(10).pow(16);
  const maxPondToUseByReeiver = BN.from(10).pow(20);

  const MAX_REWARD_FOR_CLUSTER_SELECTION = BN.from(10).pow(18) // 1 ETH
  const REFUND_GAS_FOR_CLUSTER_SELECTION = BN.from(10).pow(9).mul('100') // 100 gwei

  const _perL2Tx = 1000
  const _gasForL1Calldata = 1000
  const _storageArbGas = 1000

  const skipEpoch = async () => {
    await skipTime(ethers, epochDuration);
    await skipTime(ethers, 1); // extra 1 second for safety
  };

  before(async function() {
    this.timeout(400000);
    signers = await ethers.getSigners();

    clusterRewardsAdmin = signers[1];
    stakeManagerGateway = signers[2];
    clusterSelectorAdmin = signers[3];
    stakeManagerAdmin = signers[4];
    receiverStakingAdmin = signers[5];
    mpondWhiteListedAddress = signers[6];
    pondHoldingAddress = signers[7];
    rewardDelegatorAdmin = signers[8];

    clusters = signers.slice(20, 35); // 15 clusters
    delegators = signers.slice(35, 110); // 75 delegators
    receivers = signers.slice(150, 300); // 150 receivers
    invalidReceivers = signers.slice(300, 310); // 10 invalid receivers

    // derived
    ethReceivers = receivers.slice(0, 50);
    dotReceivers = receivers.slice(50, 100);
    maticReceivers = receivers.slice(100, 150);

    // derived
    ethDelegators = delegators.slice(0, 25);
    dotDelegators = delegators.slice(25, 50);
    maticDelegators = delegators.slice(50, 75);

    ethClusters = clusters;
    dotClusters = signers.slice(335, 350);
    maticClusters = signers.slice(320, 335);

    clusterAddresses = await Promise.all(clusters.map((a) => a.getAddress()));
    delegatorAddresss = await Promise.all(delegators.map((a) => a.getAddress()));
    receiverAddresses = await Promise.all(receivers.map((a) => a.getAddress()));

    ethClusterAddresses = await Promise.all(ethClusters.map((a) => a.getAddress()));
    dotClusterAddresses = await Promise.all(dotClusters.map((a) => a.getAddress()));
    maticClusterAddresses = await Promise.all(maticClusters.map((a) => a.getAddress()));

    const blockNum = await ethers.provider.getBlockNumber();
    const blockData = await ethers.provider.getBlock(blockNum);

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);
    await pond.transfer(await pondHoldingAddress.getAddress(), BN.from(10).pow(18).mul("10000000000"));

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    const StakeManager = await ethers.getContractFactory("StakeManager");
    const stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);

    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    const rewardDelegatorsContract = await upgrades.deployProxy(RewardDelegators, {
      kind: "uups",
      initializer: false,
    });
    rewardDelegators = getRewardDelegators(rewardDelegatorsContract.address, signers[0]);

    const ClusterRewards = await ethers.getContractFactory("ClusterRewards");
    const clusterRewardsContract = await upgrades.deployProxy(ClusterRewards, { kind: "uups", initializer: false });
    clusterRewards = getClusterRewards(clusterRewardsContract.address, signers[0]);

    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    const clusterRegistryContract = await upgrades.deployProxy(ClusterRegistry, { kind: "uups", initializer: false });
    clusterRegistry = getClusterRegistry(clusterRegistryContract.address, signers[0]);

    let ReceiverStaking = await ethers.getContractFactory("ReceiverStaking");
    const receiverStakingContract = await upgrades.deployProxy(ReceiverStaking, {
      constructorArgs: [blockData.timestamp, 4 * 3600, pond.address],
      kind: "uups",
      initializer: false,
    });
    receiverStaking = getReceiverStaking(receiverStakingContract.address, signers[0]);

    await receiverStaking.initialize(await receiverStakingAdmin.getAddress(), "Receiver POND", "rPOND");

    const arbGasInfo = await new ArbGasInfo__factory(signers[0]).deploy()
    // find the right values and set it
    await arbGasInfo.setPrices(_perL2Tx, _gasForL1Calldata, _storageArbGas)
    let ClusterSelector = await ethers.getContractFactory("ClusterSelector");
    for (let index = 0; index < supportedNetworks.length; index++) {
      let clusterSelectorContract = await upgrades.deployProxy(
        ClusterSelector,
        [
          await clusterSelectorAdmin.getAddress(),
          rewardDelegators.address
        ],
        {
          kind: "uups",
          constructorArgs: [await receiverStaking.START_TIME(), await receiverStaking.EPOCH_LENGTH(), arbGasInfo.address, MAX_REWARD_FOR_CLUSTER_SELECTION, REFUND_GAS_FOR_CLUSTER_SELECTION],
        }
      );
      let clusterSelector = getClusterSelector(clusterSelectorContract.address, signers[0]);
      clusterSelectors.push(clusterSelector);
    }

    await clusterRewards.initialize(
      await clusterRewardsAdmin.getAddress(),
      rewardDelegators.address,
      receiverStaking.address,
      supportedNetworkIds,
      supportedNetworksWeights,
      clusterSelectors.map((a) => a.address),
      REWARD_PER_EPOCH
    );

    await rewardDelegators
      .connect(rewardDelegatorAdmin)
      .initialize(
        stakeManager.address,
        clusterRewards.address,
        clusterRegistry.address,
        pond.address,
        [pondTokenId, mpondTokenId],
        [stakingConfig.PondRewardFactor, stakingConfig.MPondRewardFactor],
        [stakingConfig.PondWeightForThreshold, stakingConfig.MPondWeightForThreshold],
        [stakingConfig.PondWeightForDelegation, stakingConfig.MPondWeightForDelegation],
        [supportedNetworkIds[0], supportedNetworkIds[1], supportedNetworkIds[2]],
        [0,0,0]
      );

    await clusterRegistry.initialize([lockWaitTimes[0], lockWaitTimes[1], lockWaitTimes[2]], rewardDelegators.address);

    await stakeManager
      .connect(stakeManagerAdmin)
      .initialize(
        [pondTokenId, mpondTokenId],
        [pond.address, mpond.address],
        [false, true],
        rewardDelegators.address,
        REDELEGATION_WAIT_TIME,
        UNDELEGATION_WAIT_TIME
      );

    // derivations
    epochDuration = BN.from(await clusterSelectors[0].EPOCH_LENGTH()).toNumber();

    //post deployment operations
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), stakeManager.address);
    await mpond.grantRole(await mpond.WHITELIST_ROLE(), await mpondWhiteListedAddress.getAddress());
    await mpond.transfer(await mpondWhiteListedAddress.getAddress(), await mpond.totalSupply());

    await populateBalances(
      mpond,
      pond,
      mpondWhiteListedAddress,
      pondHoldingAddress,
      ethClusterAddresses,
      dotClusterAddresses,
      maticClusterAddresses,
      minMPondToUse,
      maxMPondToUse,
      minPondToUse,
      maxPondToUse,
      delegatorAddresss,
      receiverAddresses,
      minPondToUseByReceiver,
      maxPondToUseByReeiver
    );
  });

  it("Ensure Balances", async () => {
    for (let index = 0; index < clusterAddresses.length; index++) {
      const cluster = clusterAddresses[index];
      const mpondBalance = await mpond.balanceOf(cluster);
      expect(mpondBalance).gt(0);
      const pondBalance = await pond.balanceOf(cluster);
      expect(pondBalance).gt(0);
    }

    for (let index = 0; index < delegatorAddresss.length; index++) {
      const delegatorAddress = delegatorAddresss[index];
      const mpondBalance = await mpond.balanceOf(delegatorAddress);
      expect(mpondBalance).gt(0);
      const pondBalance = await pond.balanceOf(delegatorAddress);
      expect(pondBalance).gt(0);
    }
  });

  describe(`Only ETH Delegations, All Commissions equal, 5 clusters, All Equal Delegations (by delegators)`, async function() {
    this.timeout(200000);
    const totalClusters = 5;
    const delegatorsToUse = 20;

    saveAndRestoreStateToParent(async () => {
      // skip epoch till switching
      let currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toNumber();
      const switchingEpoch = BN.from(33).mul(86400).div(4 * 3600).toNumber() // coded as private variables in contract
      while(currentEpoch <= switchingEpoch){
        await skipEpoch()
        currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toNumber();
        // console.log('current epoch', currentEpoch)
      }

      for (let index = 0; index < ethClusters.length; index++) {
        const cluster = ethClusters[index];
        const commission = 15;

        await clusterRegistry
          .connect(cluster)
          .register(supportedNetworkIds[0], commission, ethClusterAddresses[index], ethClusterAddresses[index]);
      }
      await populateEpochReward(pond, pondHoldingAddress, rewardDelegators);

      for (let index = 0; index < delegatorsToUse; index++) {
        const delegator = delegators[index];
        const clusterToDelegate = clusterAddresses[index % totalClusters];

        await pond.connect(delegator).approve(stakeManager.address, minPondToUse.toString());
        await mpond.connect(delegator).approve(stakeManager.address, minMPondToUse.toString());
        await stakeManager
          .connect(delegator)
          .createStashAndDelegate([pondTokenId, mpondTokenId], [minPondToUse.toString(), minMPondToUse.toString()], clusterToDelegate);
      }
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => {});

    it("Check Delegations", async () => {
      const clustersToVerify = clusterAddresses.slice(0, totalClusters);
      for (let index = 0; index < clustersToVerify.length; index++) {
        const cluster = clustersToVerify[index];
        const totalPondDelegation = await rewardDelegators.getClusterDelegation(cluster, pondTokenId);
        const totalMPondDelegation = await rewardDelegators.getClusterDelegation(cluster, mpondTokenId);
        expect(totalMPondDelegation).gt(0);
        expect(totalPondDelegation).gt(0);
      }
    });

    it('Cluster selection should rewarded', async() => {
      await signers[0].sendTransaction({to: clusterSelectors[0].address, value: ethers.utils.parseEther('10')})
      const provider = signers[0].provider

      const balanceBefore = await provider?.getBalance(clusterSelectorAdmin.getAddress())
      const tx = await clusterSelectors[0].connect(clusterSelectorAdmin).selectClusters();
      const receipt = await tx.wait()
      const balanceAfter = await provider?.getBalance(clusterSelectorAdmin.getAddress())
      expect(balanceAfter).gt(balanceBefore)

      // values derived from contract
      let _reward = BN.from(REFUND_GAS_FOR_CLUSTER_SELECTION).add(_perL2Tx).add(_gasForL1Calldata*4).mul(receipt.effectiveGasPrice);
      if (_reward.gt(MAX_REWARD_FOR_CLUSTER_SELECTION)){
        _reward = BN.from(MAX_REWARD_FOR_CLUSTER_SELECTION);
      } 

      expect(balanceAfter?.sub(BN.from(balanceBefore))).to.be.closeTo(_reward, _reward.div(1000))
    })

    it(`All ${totalClusters} clusters should be selected`, async () => {
      let currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toString();
      let nextEpoch = BN.from(currentEpoch).add(1).toString();

      await clusterSelectors[0].connect(clusterSelectorAdmin).selectClusters();
      await skipEpoch();

      let clusters = (await clusterSelectors[0].getClusters(nextEpoch)) as string[];

      for (let index = 0; index < totalClusters; index++) {
        expect(clusters.includes(clusterAddresses[index])).to.be.true;
      }

      for (let index = totalClusters; index < clusterAddresses.length; index++) {
        const cluster = clusterAddresses[index];
        expect(clusters.includes(cluster)).to.be.false;
      }
    }); 

    it("Only 1 receiver, all cluster should get equal reward", async () => {
      const receiver = receivers[0];
      const totalWeight = MAX_TICKETS.sub(1);
      let equiWeightedTickets = totalWeight.div(totalClusters);
      const weights = [equiWeightedTickets, equiWeightedTickets, equiWeightedTickets, equiWeightedTickets, totalWeight.sub(equiWeightedTickets.mul(4))];
      // let missingWeights = totalWeight.sub(weights.reduce((prev, curr) => prev.add(curr), BN.from(0)))
      // console.log('weights', weights.map(a => a.toString()))

      await receiverDeposit(pond, receiverStaking, receiver, minPondToUseByReceiver);
      await skipEpoch();
      let currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toString();

      const [pondRewards, mpondRewards] = await issueTicketsForClusters(
        clusterSelectors[0],
        rewardDelegators,
        clusterRegistry,
        pond,
        receiver,
        [supportedNetworkIds[0]],
        clusterAddresses.slice(0, totalClusters),
        weights,
        currentEpoch,
        clusterSelectorAdmin,
        skipEpoch,
        clusterRewards,
        mpondWhiteListedAddress,
        pondTokenId,
        mpondTokenId
      );

      for (let index = 0; index < pondRewards.length - 1; index++) {
        const element = pondRewards[index];
        expect(element).gt(0);
        expect(element).to.be.closeTo(pondRewards[index + 1], pondRewards[index + 1].div(10000));
      }

      for (let index = 0; index < mpondRewards.length - 1; index++) {
        const element = mpondRewards[index];
        expect(element).gt(0);
        expect(element).to.be.closeTo(mpondRewards[index + 1], mpondRewards[index + 1].div(10000));
      }
    });

    it("Only 1 receiver, tickets ratio 1:2:3:4:5", async () => {
      const receiver = receivers[0];
      const totalWeight = MAX_TICKETS.sub(1);
      let fration = totalWeight.div(15);
      const weights = [fration.mul(1), fration.mul(2), fration.mul(3), fration.mul(4), totalWeight.sub(fration.mul(10))];
      await receiverDeposit(pond, receiverStaking, receiver, minPondToUseByReceiver);
      await skipEpoch();
      let currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toString();

      const [pondRewardsPerShare, mpondRewardsPerShare] = await issueTicketsForClusters(
        clusterSelectors[0],
        rewardDelegators,
        clusterRegistry,
        pond,
        receiver,
        [supportedNetworkIds[0]],
        clusterAddresses.slice(0, totalClusters),
        weights,
        currentEpoch,
        clusterSelectorAdmin,
        skipEpoch,
        clusterRewards,
        mpondWhiteListedAddress,
        pondTokenId,
        mpondTokenId
      );

      expect(pondRewardsPerShare[0]).gt(0)
      expect(pondRewardsPerShare[0]).to.closeTo(pondRewardsPerShare[1].div(2), pondRewardsPerShare[0].div(1000))
      expect(pondRewardsPerShare[0]).to.closeTo(pondRewardsPerShare[2].div(3), pondRewardsPerShare[0].div(1000))
      expect(pondRewardsPerShare[0]).to.closeTo(pondRewardsPerShare[3].div(4), pondRewardsPerShare[0].div(1000))
      expect(pondRewardsPerShare[0]).to.closeTo(pondRewardsPerShare[4].div(5), pondRewardsPerShare[0].div(1000))

      expect(mpondRewardsPerShare[0]).gt(0)
      expect(mpondRewardsPerShare[0]).to.closeTo(mpondRewardsPerShare[1].div(2), mpondRewardsPerShare[0].div(1000))
      expect(mpondRewardsPerShare[0]).to.closeTo(mpondRewardsPerShare[2].div(3), mpondRewardsPerShare[0].div(1000))
      expect(mpondRewardsPerShare[0]).to.closeTo(mpondRewardsPerShare[3].div(4), mpondRewardsPerShare[0].div(1000))
      expect(mpondRewardsPerShare[0]).to.closeTo(mpondRewardsPerShare[4].div(5), mpondRewardsPerShare[0].div(1000))
    });

    it("4 Clusters get rewards, tickets ratio 1:1:1:1:0", async () => {
      const receiver = receivers[0];
      let fration = MAX_TICKETS.div(4);
      const zero = BN.from(0);
      const weights = [fration, fration, fration, fration, zero];
      await receiverDeposit(pond, receiverStaking, receiver, minPondToUseByReceiver);
      await skipEpoch();
      let currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toString();
      const selectedClusters = clusterAddresses.slice(0, totalClusters)
      const [pondRewards, mpondRewards, commision, orderOfSelectedClusters, orderedWeights] = await issueTicketsForClusters(
        clusterSelectors[0],
        rewardDelegators,
        clusterRegistry,
        pond,
        receiver,
        [supportedNetworkIds[0]],
        selectedClusters,
        weights,
        currentEpoch,
        clusterSelectorAdmin,
        skipEpoch,
        clusterRewards,
        mpondWhiteListedAddress,
        pondTokenId,
        mpondTokenId
      );

      expect(pondRewards[0]).gt(0)
      expect(pondRewards[0]).eq(pondRewards[1])
      expect(pondRewards[0]).eq(pondRewards[2])
      expect(pondRewards[0]).eq(pondRewards[3])
      expect(pondRewards[4]).eq(0)

      expect(mpondRewards[0]).gt(0)
      expect(mpondRewards[0]).eq(mpondRewards[1])
      expect(mpondRewards[0]).eq(mpondRewards[2])
      expect(mpondRewards[0]).eq(mpondRewards[3])
      expect(mpondRewards[4]).eq(0)

      expect(commision[0]).gt(0)
      expect(commision[0]).eq(commision[1])
      expect(commision[0]).eq(commision[2])
      expect(commision[0]).eq(commision[3])
      expect(commision[4]).eq(0)
      
    });

    it("Only 1 receiver, tickets ratio 0:0:0:0:1", async () => {
      const receiver = receivers[0];
      let fration = MAX_TICKETS.sub(1);
      const zero = BN.from(0);
      const weights = [zero, zero, zero, zero, fration];
      await receiverDeposit(pond, receiverStaking, receiver, minPondToUseByReceiver);
      await skipEpoch();
      let currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toString();
      const selectedClusters = clusterAddresses.slice(0, totalClusters)
      const [pondRewards, mpondRewards, commision, orderOfSelectedClusters, orderedWeights] = await issueTicketsForClusters(
        clusterSelectors[0],
        rewardDelegators,
        clusterRegistry,
        pond,
        receiver,
        [supportedNetworkIds[0]],
        selectedClusters,
        weights,
        currentEpoch,
        clusterSelectorAdmin,
        skipEpoch,
        clusterRewards,
        mpondWhiteListedAddress,
        pondTokenId,
        mpondTokenId
      );
      
      expect(pondRewards[0]).eq(0)
      expect(pondRewards[1]).eq(0)
      expect(pondRewards[2]).eq(0)
      expect(pondRewards[3]).eq(0)
      expect(pondRewards[4]).gt(0)

      expect(mpondRewards[0]).eq(0)
      expect(mpondRewards[1]).eq(0)
      expect(mpondRewards[2]).eq(0)
      expect(mpondRewards[3]).eq(0)
      expect(mpondRewards[4]).gt(0)

      expect(commision[0]).eq(0)
      expect(commision[1]).eq(0)
      expect(commision[2]).eq(0)
      expect(commision[3]).eq(0)
      expect(commision[4]).gt(0)
      
    });

    it("1 receiver, ticket ratio 1:1:1:1:1, all delegator get equal rewards, totalReward < rewardPerEpoch", async () => {
      const receiver = receivers[0];
      let equiWeightedTickets = MAX_TICKETS.div(totalClusters);
      const weights = [equiWeightedTickets, equiWeightedTickets, equiWeightedTickets, equiWeightedTickets];
      await receiverDeposit(pond, receiverStaking, receiver, minPondToUseByReceiver);
      await skipEpoch();
      let currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toString();
      const [, , clusterCommisionReceived] = await issueTicketsForClusters(
        clusterSelectors[0],
        rewardDelegators,
        clusterRegistry,
        pond,
        receiver,
        [supportedNetworkIds[0]],
        clusterAddresses.slice(0, totalClusters),
        weights,
        currentEpoch,
        clusterSelectorAdmin,
        skipEpoch,
        clusterRewards,
        mpondWhiteListedAddress,
        pondTokenId,
        mpondTokenId
      );

      const delegatorRewardsRecevied = await withdrawRewards(
        pond,
        rewardDelegators,
        delegatorAddresss.slice(0, delegatorsToUse),
        clusterAddresses.slice(0, totalClusters)
      );

      const totalPondDistributed = [...delegatorRewardsRecevied, ...clusterCommisionReceived].reduce(
        (prev, val) => prev.add(val),
        BN.from(0)
      );
      const totalExpectedRewardToBeDistributed = REWARD_PER_EPOCH.mul(supportedNetworksWeights[0]).div(100);

      expect(totalPondDistributed).lt(totalExpectedRewardToBeDistributed);
      expect(totalExpectedRewardToBeDistributed).is.closeTo(totalPondDistributed, totalPondDistributed.div(10000));
    });

    it("2 Receiver Stake 1:2, Tickets: 1:1 to their respective cluster, delegator reward should be 1:2", async () => {
      const [receiver1, receiver2] = getRandomElementsFromArray(receivers, 2);
      const [clusterAddress1, clusterAddress2] = getRandomElementsFromArray(clusterAddresses.slice(0, 5), 2);

      await receiverDeposit(pond, receiverStaking, receiver1, minPondToUseByReceiver.div(2));
      await receiverDeposit(pond, receiverStaking, receiver2, minPondToUseByReceiver);
      const fraction = MAX_TICKETS.sub(1);
      await skipEpoch();
      let currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toString();

      const [, , clusterCommisionReceived1] = await issueTicketsForClusters(
        clusterSelectors[0],
        rewardDelegators,
        clusterRegistry,
        pond,
        receiver1,
        [supportedNetworkIds[0]],
        [clusterAddress1],
        [fraction],
        currentEpoch,
        clusterSelectorAdmin,
        skipEpoch,
        clusterRewards,
        mpondWhiteListedAddress,
        pondTokenId,
        mpondTokenId
      );
      const [, , clusterCommisionReceived2] = await issueTicketsForClusters(
        clusterSelectors[0],
        rewardDelegators,
        clusterRegistry,
        pond,
        receiver2,
        [supportedNetworkIds[0]],
        [clusterAddress2],
        [fraction],
        currentEpoch,
        clusterSelectorAdmin,
        skipEpoch,
        clusterRewards,
        mpondWhiteListedAddress,
        pondTokenId,
        mpondTokenId
      );

      const delegatorRewardsRecevied = await withdrawRewards(pond, rewardDelegators, delegatorAddresss.slice(0, delegatorsToUse), [
        clusterAddress1,
        clusterAddress2,
      ]);

      const totalPondDistributed = [...delegatorRewardsRecevied, ...[...clusterCommisionReceived1, ...clusterCommisionReceived2]].reduce(
        (prev, val) => prev.add(val),
        BN.from(0)
      );
      const totalExpectedRewardToBeDistributed = REWARD_PER_EPOCH.mul(supportedNetworksWeights[0]).div(100);

      expect(totalPondDistributed).lt(totalExpectedRewardToBeDistributed);
      expect(totalExpectedRewardToBeDistributed).is.closeTo(totalPondDistributed, totalPondDistributed.div(10000));
    });

    // it.skip("Should Fail: Submit tickets to unselected cluster", async () => {
    //   const receiver = receivers[0];
    //   const fraction = BN.from(10).pow(18);
    //   await receiverDeposit(pond, receiverStaking, receiver, minPondToUseByReceiver);
    //   await skipEpoch();
    //   let currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toString();
    //   await expect(
    //     issueTicketsForClusters(
    //       clusterSelectors[0],
    //       rewardDelegators,
    //       clusterRegistry,
    //       pond,
    //       receiver,
    //       [supportedNetworkIds[0]],
    //       [clusterAddresses[5]],
    //       [fraction],
    //       currentEpoch,
    //       clusterSelectorAdmin,
    //       skipEpoch,
    //       clusterRewards,
    //       mpondWhiteListedAddress,
    //       pondTokenId,
    //       mpondTokenId
    //     )
    //   ).to.be.revertedWith("CRW:IT-Invalid cluster to issue ticket");
    // });

    it("Should Fail: Invalid Receiver can't submit tickets", async () => {
      const receiver = invalidReceivers[0];
      const fraction = MAX_TICKETS.sub(1);
      
      // move some epoch/s ahead
      await skipEpoch();

      let currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toNumber();

      await expect(
        clusterRewards.connect(receiver)["issueTickets(bytes32,uint24,uint16[])"](supportedNetworkIds[0], currentEpoch, [fraction])
      ).to.be.revertedWith("CRW:IT-Epoch not completed");
    });

    it("Should fail: Receiver submits not equal to tickets allowed", async () => {
      await receiverDeposit(pond, receiverStaking, ethReceivers[0], BN.from(10).pow(18));

      let currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toNumber();
      let currentPlusOne = BN.from(currentEpoch).add(1).toString();
      await clusterSelectors[0].selectClusters();

      // skipping to get simulate the desired failure case
      await skipEpoch();
      await skipEpoch();

      // const selectedClusters = await clusterSelectors[0].getClusters(currentPlusOne);

      const totalTickets = await clusterRewards.RECEIVER_TICKETS_PER_EPOCH();
      const firstClusterTickets = totalTickets.mul(2).div(3);

      await expect(
        clusterRewards.connect(ethReceivers[0])["issueTickets(bytes32,uint24,uint16[])"](
          supportedNetworkIds[0], 
          currentPlusOne, 
          [firstClusterTickets, totalTickets.sub(firstClusterTickets).add(1), 0, 0, 0]
        )
      ).to.be.revertedWith("CRW:IPRT-Total ticket count invalid");
    });
  });

  describe("All Network, with different commissions", async () => {
    let numberOfClustersPerNetworkToTest = 2;
    let numberOfReceiverStakerPerNetworkToTest = 3;
    let numberOfDelegatorsPerCluster = 3;

    let randomEthClusters: string[] = [];
    let randomDotClusters: string[] = [];
    let randomMaticClusters: string[] = [];
    let randomEthClustersTotalPondDelegation: string[] = [];
    let randomDotClustersTotalPondDelegation: string[] = [];
    let randomMaticClustersTotalPondDelegation: string[] = [];
    let randomEthClustersTotalMPondDelegation: string[] = [];
    let randomDotClustersTotalMPondDelegation: string[] = [];
    let randomMaticClustersTotalMPondDelegation: string[] = [];

    let ethClustersSelectedAt: string;
    let dotClustersSelectedAt: string;
    let maticClustersSelectedAt: string;

    let ethReceiversToUse: Signer[] = [];
    let dotReceiversToUse: Signer[] = [];
    let maticReceiversToUse: Signer[] = [];
    let ethReceiversStakeAmount: string[] = [];
    let dotReceiversStakeAmount: string[] = [];
    let maticReceiversStakeAmount: string[] = [];

    let ethDelegatorsToUse: Signer[] = [];
    let dotDelegatorsToUse: Signer[] = [];
    let maticDelegatorsToUse: Signer[] = [];
    let pondDelegatedByEthDelegators: string[] = [];
    let pondDelegatedByDotDelegators: string[] = [];
    let pondDelegatedByMaticDelegators: string[] = [];
    let mpondDelegatedByEthDelegators: string[] = [];
    let mpondDelegatedByDotDelegators: string[] = [];
    let mpondDelegatedByMaticDelegators: string[] = [];

    saveAndRestoreStateToParent(async () => {
      expect(ethClusters.length == dotClusters.length, "In these tests number of eth clusters should to equal to dot clusters").to.be.true;
      expect(maticClusters.length == dotClusters.length, "In these tests number of matic clusters should to equal to dot clusters").to.be
        .true;

      for (let index = 0; index < ethClusters.length; index++) {
        const ethCluster = ethClusters[index];
        const dotCluster = dotClusters[index];
        const maticCluster = maticClusters[index];

        const commision = index + 1;
        await clusterRegistry
          .connect(ethCluster)
          .register(supportedNetworkIds[0], commision, ethClusterAddresses[index], ethClusterAddresses[index]);
        await pond.connect(ethCluster).approve(stakeManager.address, minPondToUse.toString());
        await mpond.connect(ethCluster).approve(stakeManager.address, minMPondToUse.toString());
        await stakeManager
          .connect(ethCluster)
          .createStashAndDelegate(
            [pondTokenId, mpondTokenId],
            [minPondToUse.toString(), minMPondToUse.toString()],
            ethClusterAddresses[index]
          );

        await clusterRegistry
          .connect(dotCluster)
          .register(supportedNetworkIds[1], commision, dotClusterAddresses[index], dotClusterAddresses[index]);
        await pond.connect(dotCluster).approve(stakeManager.address, minPondToUse.toString());
        await mpond.connect(dotCluster).approve(stakeManager.address, minMPondToUse.toString());
        await stakeManager
          .connect(dotCluster)
          .createStashAndDelegate(
            [pondTokenId, mpondTokenId],
            [minPondToUse.toString(), minMPondToUse.toString()],
            dotClusterAddresses[index]
          );

        await clusterRegistry
          .connect(maticCluster)
          .register(supportedNetworkIds[2], commision, maticClusterAddresses[index], maticClusterAddresses[index]);
        await pond.connect(maticCluster).approve(stakeManager.address, minPondToUse.toString());
        await mpond.connect(maticCluster).approve(stakeManager.address, minMPondToUse.toString());
        await stakeManager
          .connect(maticCluster)
          .createStashAndDelegate(
            [pondTokenId, mpondTokenId],
            [minPondToUse.toString(), minMPondToUse.toString()],
            maticClusterAddresses[index]
          );
      }
      await skipEpoch();

      randomEthClusters = getRandomElementsFromArray(ethClusterAddresses, numberOfClustersPerNetworkToTest);
      randomDotClusters = getRandomElementsFromArray(dotClusterAddresses, numberOfClustersPerNetworkToTest);
      randomMaticClusters = getRandomElementsFromArray(maticClusterAddresses, numberOfClustersPerNetworkToTest);
      ethReceiversToUse = getRandomElementsFromArray(ethReceivers, numberOfReceiverStakerPerNetworkToTest);
      dotReceiversToUse = getRandomElementsFromArray(dotReceivers, numberOfReceiverStakerPerNetworkToTest);
      maticReceiversToUse = getRandomElementsFromArray(maticReceivers, numberOfReceiverStakerPerNetworkToTest);
      ethDelegatorsToUse = getRandomElementsFromArray(ethDelegators, numberOfDelegatorsPerCluster * numberOfClustersPerNetworkToTest);
      dotDelegatorsToUse = getRandomElementsFromArray(dotDelegators, numberOfDelegatorsPerCluster * numberOfClustersPerNetworkToTest);
      maticDelegatorsToUse = getRandomElementsFromArray(maticDelegators, numberOfDelegatorsPerCluster * numberOfClustersPerNetworkToTest);

      ethReceiversStakeAmount = ethReceiversToUse.map(() => random(minPondToUseByReceiver.div(10000), minPondToUseByReceiver));
      dotReceiversStakeAmount = dotReceiversToUse.map(() => random(minPondToUseByReceiver.div(10000), minPondToUseByReceiver));
      maticReceiversStakeAmount = maticReceiversToUse.map(() => random(minPondToUseByReceiver.div(10000), minPondToUseByReceiver));

      pondDelegatedByEthDelegators = ethDelegatorsToUse.map(() => random(minPondToUse.div(10000), minPondToUse));
      pondDelegatedByDotDelegators = dotDelegatorsToUse.map(() => random(minPondToUse.div(10000), minPondToUse));
      pondDelegatedByMaticDelegators = maticDelegatorsToUse.map(() => random(minPondToUse.div(10000), minPondToUse));

      mpondDelegatedByEthDelegators = ethDelegatorsToUse.map(() => random(minMPondToUse.div(10000), minMPondToUse));
      mpondDelegatedByDotDelegators = dotDelegatorsToUse.map(() => random(minMPondToUse.div(10000), minMPondToUse));
      mpondDelegatedByMaticDelegators = maticDelegatorsToUse.map(() => random(minMPondToUse.div(10000), minMPondToUse));

      for (let index = 0; index < ethReceiversToUse.length; index++) {
        const receiver = ethReceiversToUse[index];
        await receiverDeposit(pond, receiverStaking, receiver, BN.from(ethReceiversStakeAmount[index]));
      }

      for (let index = 0; index < dotReceiversToUse.length; index++) {
        const receiver = dotReceiversToUse[index];
        await receiverDeposit(pond, receiverStaking, receiver, BN.from(dotReceiversStakeAmount[index]));
      }

      for (let index = 0; index < maticReceiversToUse.length; index++) {
        const receiver = maticReceiversToUse[index];
        await receiverDeposit(pond, receiverStaking, receiver, BN.from(maticReceiversStakeAmount[index]));
      }

      await skipEpoch();

      for (let index = 0; index < ethDelegatorsToUse.length; index++) {
        const delegator = ethDelegatorsToUse[index];
        const clusterUsed = randomEthClusters[index % randomEthClusters.length];

        await newDelegation(
          pond,
          mpond,
          delegator,
          pondDelegatedByEthDelegators[index],
          mpondDelegatedByEthDelegators[index],
          clusterUsed,
          stakeManager,
          pondTokenId,
          mpondTokenId
        );
      }

      for (let index = 0; index < dotDelegatorsToUse.length; index++) {
        const delegator = dotDelegatorsToUse[index];
        const clusterUsed = randomDotClusters[index % randomDotClusters.length];
        await newDelegation(
          pond,
          mpond,
          delegator,
          pondDelegatedByDotDelegators[index],
          mpondDelegatedByDotDelegators[index],
          clusterUsed,
          stakeManager,
          pondTokenId,
          mpondTokenId
        );
      }

      for (let index = 0; index < maticDelegatorsToUse.length; index++) {
        const delegator = maticDelegatorsToUse[index];
        const clusterUsed = randomMaticClusters[index % randomMaticClusters.length];
        await newDelegation(
          pond,
          mpond,
          delegator,
          pondDelegatedByMaticDelegators[index],
          mpondDelegatedByMaticDelegators[index],
          clusterUsed,
          stakeManager,
          pondTokenId,
          mpondTokenId
        );
      }

      for (let index = 0; index < randomEthClusters.length; index++) {
        const cluster = randomEthClusters[index];
        const totalPondDelegation = (await rewardDelegators.getClusterDelegation(cluster, pondTokenId)).toString();
        const totalMPondDelegation = (await rewardDelegators.getClusterDelegation(cluster, mpondTokenId)).toString();
        randomEthClustersTotalPondDelegation.push(totalPondDelegation);
        randomEthClustersTotalMPondDelegation.push(totalMPondDelegation);
      }

      for (let index = 0; index < randomDotClusters.length; index++) {
        const cluster = randomDotClusters[index];
        const totalPondDelegation = (await rewardDelegators.getClusterDelegation(cluster, pondTokenId)).toString();
        const totalMPondDelegation = (await rewardDelegators.getClusterDelegation(cluster, mpondTokenId)).toString();
        randomDotClustersTotalPondDelegation.push(totalPondDelegation);
        randomDotClustersTotalMPondDelegation.push(totalMPondDelegation);
      }

      for (let index = 0; index < randomMaticClusters.length; index++) {
        const cluster = randomMaticClusters[index];
        const totalPondDelegation = (await rewardDelegators.getClusterDelegation(cluster, pondTokenId)).toString();
        const totalMPondDelegation = (await rewardDelegators.getClusterDelegation(cluster, mpondTokenId)).toString();
        randomMaticClustersTotalPondDelegation.push(totalPondDelegation);
        randomMaticClustersTotalMPondDelegation.push(totalMPondDelegation);
      }

      // skip epoch till switching
      let currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toNumber();
      const switchingEpoch = BN.from(33).mul(86400).div(4 * 3600).toNumber() // coded as private variables in contract
      while(currentEpoch <= switchingEpoch){
        await skipEpoch()
        currentEpoch = (await clusterSelectors[0].getCurrentEpoch()).toNumber();
        // console.log('selection clusters in all epochs')
        await Promise.all(clusterSelectors.map(async (a) => await a.selectClusters({gasLimit: "20000000"})));
      }

      await skipEpoch();

      [ethClustersSelectedAt] = await mineTillGivenClustersAreSelected(clusterSelectors[0], randomEthClusters, skipEpoch);
      [dotClustersSelectedAt] = await mineTillGivenClustersAreSelected(clusterSelectors[1], randomDotClusters, skipEpoch);
      [maticClustersSelectedAt] = await mineTillGivenClustersAreSelected(clusterSelectors[2], randomMaticClusters, skipEpoch);

      // changes will reflect in next epoch
      await populateEpochReward(pond, pondHoldingAddress, rewardDelegators);
      await skipEpoch();
      // console.log({ ethClustersSelectedAt, dotClustersSelectedAt, maticClustersSelectedAt });
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => {});

    let test_scene = async (
      clusterSelectedAtEpoch: string,
      randomClustersSelected: string[],
      receiversUsedHere: Signer[],
      clusterSelector: ClusterSelector,
      networkId: string,
      commissionChecker: (comm: string | BN) => void = function () {}
    ): Promise<void> => {
      const epoch = BN.from(clusterSelectedAtEpoch).sub(1).toString();
      const weights: BN[] = [];
      let pendingFraction = MAX_TICKETS.sub(1);

      for (let index = 0; index < randomClustersSelected.length - 1; index++) {
        const fraction = FuzzedNumber.randomInRange("1", pendingFraction);
        weights.push(BN.from(fraction));
        pendingFraction = pendingFraction.sub(fraction);
      }
      weights.push(pendingFraction);

      const clusterCommissions: string[] = [];
      for (let index = 0; index < randomClustersSelected.length; index++) {
        const cluster = randomClustersSelected[index];
        const data = await clusterRegistry.callStatic.getCommission(cluster);
        clusterCommissions.push(data.toString());
      }
      // console.log({ clusterCommissions });

      for (let index = 0; index < receiversUsedHere.length; index++) {
        const receiver = receiversUsedHere[index];

        const [, , clusterCommisionReceived] = await issueTicketsForClusters(
          clusterSelector,
          rewardDelegators,
          clusterRegistry,
          pond,
          receiver,
          [networkId],
          randomClustersSelected,
          weights,
          epoch,
          clusterSelectorAdmin,
          skipEpoch,
          clusterRewards,
          mpondWhiteListedAddress,
          pondTokenId,
          mpondTokenId
        );

        const it_mul_cp = weights.map((val, index) => val.mul(clusterCommissions[index]));

        const t_com = clusterCommisionReceived.reduce((prev, val) => prev.add(val), BN.from(0));
        const t_it_mul_cp = it_mul_cp.reduce((prev, mul) => prev.add(mul), BN.from(0));

        const scaler = BN.from(2).pow(16);
        for (let index = 0; index < it_mul_cp.length; index++) {
          const w = it_mul_cp[index].toString();
          const c = clusterCommisionReceived[index].toString();
          expect(t_com.mul(scaler).div(c)).to.be.closeTo(t_it_mul_cp.mul(scaler).div(w), 100000);
        }

        for (let index = 0; index < clusterCommisionReceived.length; index++) {
          const element = clusterCommisionReceived[index];
          commissionChecker(element);
        }
      }
    };
    it("Commission received proportional to (issued tickets * commission percent) -- ETH", async () => {
      await test_scene(ethClustersSelectedAt, randomEthClusters, ethReceiversToUse, clusterSelectors[0], supportedNetworkIds[0]);
    });

    it("Commission received proportional to (issued tickets * commission percent) -- DOT", async () => {
      await test_scene(dotClustersSelectedAt, randomDotClusters, dotReceiversToUse, clusterSelectors[1], supportedNetworkIds[1]);
    });

    it("Commission received proportional to (issued tickets * commission percent) -- MATIC", async () => {
      await test_scene(maticClustersSelectedAt, randomMaticClusters, maticReceiversToUse, clusterSelectors[2], supportedNetworkIds[2]);
    });

    it("Commission received proportional to (issued tickets * commission percent) -- (ETH,DOT,MATIC)", async () => {
      await test_scene(ethClustersSelectedAt, randomEthClusters, ethReceiversToUse, clusterSelectors[0], supportedNetworkIds[0]);
      await test_scene(dotClustersSelectedAt, randomDotClusters, dotReceiversToUse, clusterSelectors[1], supportedNetworkIds[1]);
      await test_scene(maticClustersSelectedAt, randomMaticClusters, maticReceiversToUse, clusterSelectors[2], supportedNetworkIds[2]);
    });
  });
});

const mineTillGivenClustersAreSelected = async (
  clusterSelector: ClusterSelector,
  clusterAddresses: string[],
  whenNotFound: () => Promise<void>
): Promise<[string, string[]]> => {
  let currentEpoch = (await clusterSelector.getCurrentEpoch()).toString();
  for (;;) {
    let clusters = (await clusterSelector.getClusters(currentEpoch)) as string[];
    clusters = clusters.map((a) => a.toLowerCase());
    clusterAddresses = clusterAddresses.map((a) => a.toLowerCase());

    let allSelected = true;
    for (let index = 0; index < clusterAddresses.length; index++) {
      const clusterAddress = clusterAddresses[index];
      allSelected = allSelected && clusters.includes(clusterAddress);
    }

    if (allSelected) {
      return [currentEpoch, clusters];
    } else {
      await whenNotFound();
      await clusterSelector.selectClusters();
      currentEpoch = BN.from(currentEpoch.toString()).add(1).toString();
    }
  }
};

const populateEpochReward = async (pondInstance: Pond, pondHoldingAddress: Signer, rewardDelegatorsInstance: RewardDelegators) => {
  await pondInstance.connect(pondHoldingAddress).transfer(rewardDelegatorsInstance.address, REWARD_PER_EPOCH);
};

const receiverDeposit = async (pondInstance: Pond, receiverStakingInstance: ReceiverStaking, receiver: Signer, amount: BN) => {
  await pondInstance.connect(receiver).approve(receiverStakingInstance.address, amount);
  await receiverStakingInstance.connect(receiver).depositAndSetSigner(amount, await receiver.getAddress()); //n
};

const newDelegation = async (
  pondInstance: Pond,
  mpondInstance: MPond,
  delegator: Signer,
  pondToUse: BN | string,
  mpondToUse: BN | string,
  clusterAddress: string,
  stakeManagerInstance: StakeManager,
  pondTokenId: string,
  mpondTokenId: string
) => {
  await pondInstance.connect(delegator).approve(stakeManagerInstance.address, pondToUse.toString());
  await mpondInstance.connect(delegator).approve(stakeManagerInstance.address, mpondToUse.toString());
  await stakeManagerInstance
    .connect(delegator)
    .createStashAndDelegate([pondTokenId, mpondTokenId], [pondToUse.toString(), mpondToUse.toString()], clusterAddress);
};

const new_order_of_weights = (existingWeights: BN[], existingClusters: string[], new_order_of_clusters: string[]): BN[] => {
  existingClusters = existingClusters.map((a) => a.toLowerCase());
  new_order_of_clusters = new_order_of_clusters.map((a) => a.toLowerCase());

  let record = new Map<string, BN>();

  for (let index = 0; index < existingClusters.length; index++) {
    const element = existingClusters[index];
    record.set(element, existingWeights[index]);
  }

  const new_weights: BN[] = [];

  for (let index = 0; index < new_order_of_clusters.length; index++) {
    const element = new_order_of_clusters[index];

    const weight = record.get(element);
    if (weight) {
      new_weights.push(weight);
    }else{
      new_weights.push(BIG_ZERO);
    }
  }

  // console.log({existingClusters, existingWeights, new_order_of_clusters, new_weights});

  return new_weights;
};

const issueTicketsForClusters = async (
  clusterSelectorInstance: ClusterSelector,
  rewardDelegatorsInstance: RewardDelegators,
  clusterRegistryInstance: ClusterRegistry,
  pondInstance: Pond,
  receiver: Signer,
  networkIds: string[],
  clustersToIssueTicketsTo: string[],
  weights: BN[],
  currentEpoch: string,
  clusterSelectorAdmin: Signer,
  skipEpochFunc: () => Promise<void>,
  clusterRewardsInstance: ClusterRewards,
  anyRandomSigner: Signer,
  pondTokenId: string,
  mpondTokenId: string
): Promise<[BN[], BN[], BN[], string[], BN[]]> => {
  const ethRewardResults = await Promise.all(
    clustersToIssueTicketsTo.map(async (a) => {
      let data = await clusterRegistryInstance.callStatic.getRewardInfo(a);
      return {
        cluster: a,
        commission: data[0].toString(),
        rewardAddress: data[1],
        clusterRegistryAddress: clusterRegistryInstance.address,
      };
    })
  );
    
  let currentPlusOne = BN.from(currentEpoch).add(1).toString();
  await clusterSelectorInstance.connect(clusterSelectorAdmin).selectClusters({gasLimit: "20000000"}); // these clusters are selected in currentPlusOne epoch
  
  // console.log({
  //   currentPlusOne,
  //   networkIds,
  //   weights: weights.map((a) => a.toString()),
  //   clustersToIssueTicketsTo,
  //   selectedClusters: await clusterSelectorInstance.getClusters(currentPlusOne),
  // });

  const clusterRewardBalancesBefore: BN[] = [];
  for (let index = 0; index < clustersToIssueTicketsTo.length; index++) {
    const element = ethRewardResults[index];
    const clusterOldBalance = await pondInstance.balanceOf(element.rewardAddress);
    clusterRewardBalancesBefore.push(clusterOldBalance);
  }
  // console.log(
  //   "clusterRewardBalancesBefore",
  //   clusterRewardBalancesBefore.map((a) => a.toString())
  // );

  await skipEpochFunc(); // this should not effect other operations
  await skipEpochFunc(); // this should not effect other operations

  // weights array has to re-arranged in order of selected clusters
  const orderOfSelectedClusters = await clusterSelectorInstance.getClusters(currentPlusOne)
  const new_weights = new_order_of_weights(weights, clustersToIssueTicketsTo, orderOfSelectedClusters);
  // console.log(new_weights)
  for (let index = 0; index < networkIds.length; index++) {
    const networkId = networkIds[index];
    await clusterRewardsInstance.connect(receiver)["issueTickets(bytes32,uint24,uint16[])"](networkId, currentPlusOne, new_weights);
  }

  const pondRewardsPerShare: BN[] = [];
  const mpondRewardsPerShare: BN[] = [];

  for (let index = 0; index < clustersToIssueTicketsTo.length; index++) {
    const cluster = clustersToIssueTicketsTo[index];
    // console.log({msg: `manually updating rewards for cluster after receiver ${await receiver.getAddress()} issues tickets`, cluster});
    await rewardDelegatorsInstance.connect(anyRandomSigner)._updateRewards(cluster); // any singer can be used here
    pondRewardsPerShare.push(await rewardDelegatorsInstance.getAccRewardPerShare(cluster, pondTokenId));
    mpondRewardsPerShare.push(await rewardDelegatorsInstance.getAccRewardPerShare(cluster, mpondTokenId));
  }

  const clusterRewardBalancesAfter: BN[] = [];
  for (let index = 0; index < clustersToIssueTicketsTo.length; index++) {
    const element = ethRewardResults[index];
    const clusterNewBalance = await pondInstance.balanceOf(element.rewardAddress);
    clusterRewardBalancesAfter.push(clusterNewBalance);
  }

  // console.log(
  //   "clusterRewardBalancesAfter",
  //   clusterRewardBalancesAfter.map((a) => a.toString())
  // );
  const commissionReceived = clusterRewardBalancesAfter.map((a, index) => a.sub(clusterRewardBalancesBefore[index]));

  // console.log(
  //   "commission received",
  //   commissionReceived.map((a) => a.toString())
  // );
  return [pondRewardsPerShare, mpondRewardsPerShare, commissionReceived, orderOfSelectedClusters, new_weights];
};

const withdrawRewards = async (
  pondInstance: Pond,
  rewardDelegatorsInstance: RewardDelegators,
  delegatorsList: string[],
  clustersToClaimRewardFrom: string[]
): Promise<BN[]> => {
  const delegatorRewardsRecevied: BN[] = [];

  for (let index = 0; index < delegatorsList.length; index++) {
    const delegatorAddress = delegatorsList[index];
    const balanceBefore = await pondInstance.balanceOf(delegatorAddress);
    await rewardDelegatorsInstance["withdrawRewards(address,address[])"](delegatorAddress, clustersToClaimRewardFrom);
    const balanceAfter = await pondInstance.balanceOf(delegatorAddress);
    delegatorRewardsRecevied.push(balanceAfter.sub(balanceBefore));
  }

  return delegatorRewardsRecevied;
};

const populateBalances = async (
  mpondInstance: MPond,
  pondInstance: Pond,
  mpondWhiteListedAddress: Signer,
  pondHoldingAddress: Signer,
  ethClusterAddresses: string[],
  dotClusterAddresses: string[],
  maticClusterAddresses: string[],
  minMPondToUse: BN | string,
  maxMPondToUse: BN | string,
  minPondToUse: BN | string,
  maxPondToUse: BN | string,
  delegatorAddresss: string[],
  receiverAddresses: string[],
  minPondToUseByReceiver: BN | string,
  maxPondToUseByReeiver: BN | string
) => {
  await mpondInstance.grantRole(ethers.utils.id("WHITELIST_ROLE"), await mpondWhiteListedAddress.getAddress());

  const clusterAddresses: string[] = [...ethClusterAddresses, ...dotClusterAddresses, ...maticClusterAddresses];
  for (let index = 0; index < clusterAddresses.length; index++) {
    const clusterAddress = clusterAddresses[index];
    await mpondInstance.connect(mpondWhiteListedAddress).transfer(clusterAddress, random(minMPondToUse, maxMPondToUse));
    await pondInstance.connect(pondHoldingAddress).transfer(clusterAddress, random(minPondToUse, maxPondToUse));
  }

  for (let index = 0; index < delegatorAddresss.length; index++) {
    const delegatorAddress = delegatorAddresss[index];
    await mpondInstance.connect(mpondWhiteListedAddress).transfer(delegatorAddress, random(minMPondToUse, maxMPondToUse));
    await pondInstance.connect(pondHoldingAddress).transfer(delegatorAddress, random(minPondToUse, maxPondToUse));
  }

  for (let index = 0; index < receiverAddresses.length; index++) {
    const receiver = receiverAddresses[index];
    await pondInstance.connect(pondHoldingAddress).transfer(receiver, random(minPondToUseByReceiver, maxPondToUseByReeiver));
  }
};
