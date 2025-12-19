import { verify as verifyClusterRegistry } from "./ClusterRegistry";
import { verify as verifyClusterRewards } from "./ClusterRewards";
import { verify as verifyClusterSelector } from "./ClusterSelector";
import { verify as verifyReceiverStaking } from "./ReceiverStaking";
import { verify as verifyRewardDelegators } from "./RewardDelegators";
import { verify as verifyStakeManager } from "./StakeManager";

async function verifyAll() {
    await verifyClusterRegistry();
    await verifyClusterRewards();
    await verifyClusterSelector("ETH");
    await verifyReceiverStaking();
    await verifyRewardDelegators();
    await verifyStakeManager();
}

verifyAll();