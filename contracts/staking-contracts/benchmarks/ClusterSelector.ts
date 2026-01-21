import { ethers } from "hardhat";
import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { benchmark as benchmarkDeployment } from "./helpers/deployment";
import { initDataFixture } from "./fixtures/ClusterSelector";
import { BigNumber, BigNumberish, constants, PopulatedTransaction, Signer, utils } from "ethers";
import { randomlyDivideInXPieces, skipTime } from "./helpers/util";
import { MockContract } from "@ethereum-waffle/mock-contract";
import { FuzzedNumber } from "../utils/fuzzer";
import { ArbGasInfo__factory, ClusterSelector } from "../typechain-types";

const estimator = new ethers.Contract("0x000000000000000000000000000000000000006c", [
    "function getPricesInArbGas() view returns(uint256 gasPerL2Tx, uint256 gasPerL1CallDataByte, uint256)"
]);
const mainnetProvider = new ethers.providers.JsonRpcProvider("https://arb1.arbitrum.io/rpc");

describe("Cluster Rewards", async () => {
    const arbGasInfo = await new ArbGasInfo__factory().deploy()
    const gasResult = await estimator.getPricesInArbGas()
    await arbGasInfo.setPrices(gasResult[0], gasResult[1], gasResult[2])
    
    benchmarkDeployment('ClusterSelector', [parseInt(Date.now()/1000 + ""), 900, arbGasInfo.address, 1000, 200000], [
        "0x000000000000000000000000000000000000dEaD",
        "0x000000000000000000000000000000000000dEaD",
    ]);

    describe("Select Clusters", async () => {
        let arbGasInfoMock: MockContract;
        let clusterSelector: ClusterSelector;
        let admin: Signer;
        let rewardDelegatorsMock: Signer;
        let nodesInserted: number;
        let EPOCH_LENGTH: BigNumber;
        let l1GasDetails: any;

        beforeEach(async function() {
            this.timeout(1000000);
            process.env.NO_OF_CLUSTERS = "200";
            ({
                arbGasInfoMock,
                clusterSelector,
                admin,
                rewardDelegatorsMock,
                nodesInserted,
            } = await loadFixture(initDataFixture));

            l1GasDetails = await estimator.connect(mainnetProvider).getPricesInArbGas();
            EPOCH_LENGTH = await clusterSelector.EPOCH_LENGTH();
            console.log("********************config***********************")
            console.log(`Clusters Inserted: ${nodesInserted}`);
            console.log(`L1 Gas details, Base L1 gas/tx: ${l1GasDetails[0]}, L1 Gas/calldataByte: ${l1GasDetails[1]} `);
            console.log("*************************************************")
        });

        it("Select clusters 1000 times", async function() {
            this.timeout(1000000);
            const iterations = 1000;
            let totalGas = BigNumber.from(0);
            let maxGas = BigNumber.from(0);

            console.log(`No of iterations: ${iterations}`);

            for(let i=0; i < iterations; i++) {
                await skipTime(FuzzedNumber.randomInRange(EPOCH_LENGTH, EPOCH_LENGTH.mul(3)).toNumber());
                const tx = await clusterSelector.selectClusters({gasLimit: 1000000});
                const receipt = await tx.wait();
                totalGas = totalGas.add(receipt.gasUsed);
                if(maxGas.lt(receipt.gasUsed)) maxGas = receipt.gasUsed;
            }

            console.log(`Average gas used: ${totalGas.div(iterations).toNumber()}`);
            console.log(`Max gas used: ${maxGas.toNumber()}`);
        });
    })
});