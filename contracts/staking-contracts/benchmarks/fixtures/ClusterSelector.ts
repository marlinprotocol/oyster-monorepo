import { ethers, upgrades } from "hardhat";
import { BigNumber, BigNumberish, Signer, utils, Wallet } from "ethers";
import { deployMockContract } from "@ethereum-waffle/mock-contract";
import { deploy as deployClusterSelector } from "../../deployments/staking/ClusterSelector";
import { ClusterSelector__factory } from "../../typechain-types";

const EPOCH_LENGTH = 15*60;

export async function deployFixture() {
    const signers = await ethers.getSigners();
    const addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const blockNum = await ethers.provider.getBlockNumber();
    const blockData = await ethers.provider.getBlock(blockNum);

    // TODO: mock arbGasInfo precompile might skew gas estimate for precompile call slightly
    const arbGasInfoMock = await deployMockContract(signers[0], ["function getPricesInArbGas() view returns (uint, uint, uint)"]);
    await arbGasInfoMock.mock.getPricesInArbGas.returns(223148, 1593, 21000);
    const clusterSelectorInstance = await deployClusterSelector(
        "ETH", // network
        addrs[1], // rewardDelegators
        arbGasInfoMock.address, // arbGasInfo
        addrs[2], // admin
        blockData.timestamp, // startTime
        EPOCH_LENGTH, // epochLength
        "0", // gas refund,
        ethers.utils.parseEther("0.0001").toString(), // max reward
        true
    );


    return {
        arbGasInfoMock,
        clusterSelector: ClusterSelector__factory.connect(clusterSelectorInstance.address, signers[0]),
        admin: signers[2],
        rewardDelegatorsMock: signers[1]
    };
}

export async function initDataFixture() {
    if(!process.env.NO_OF_CLUSTERS) throw new Error("NO_OF_CLUSTERS not set");
    const noOfClusters: number = parseInt(process.env.NO_OF_CLUSTERS);

    const signers = await ethers.getSigners();
    const preAllocEthSigner = signers[8];

    const {
        arbGasInfoMock,
        clusterSelector,
        admin,
        rewardDelegatorsMock
    } = await deployFixture();

    await preAllocEthSigner.sendTransaction({to: clusterSelector.address, value: ethers.utils.parseEther("100")});

    const tokenSupply: BigNumber = BigNumber.from(10).pow(28);

    const clusters: string[] = [];
    const balances: BigNumberish[] = [];

    // generate clusters and balance data
    for(let i=0; i < noOfClusters; i++) {
        const address = Wallet.createRandom().address;
        clusters.push(address);
        balances.push(BigNumber.from(ethers.utils.randomBytes(32)).mod(tokenSupply.div(utils.parseEther(noOfClusters+""))));
    }

    // insert clusterData into selector
    for(let i=0; i < clusters.length; i+=100) {
        await clusterSelector.connect(rewardDelegatorsMock).upsertMultiple(clusters.slice(i, i+100), balances.slice(i, i+100));
    }

    return {
        arbGasInfoMock,
        clusterSelector,
        admin,
        rewardDelegatorsMock,
        nodesInserted: noOfClusters
    };
}