import { Contract } from 'ethers';
import { ethers } from 'hardhat';
import { deploy as deployClusterRegistry } from './ClusterRegistry';
import { deploy as deployClusterRewards } from './ClusterRewards';
import { deploy as deployClusterSelector } from './ClusterSelector';
import { deploy as deployReceiverStaking } from './ReceiverStaking';
import { deployNoInit as deployRewardDelegators } from './RewardDelegators';
import { init as initRewardDelegators } from './RewardDelegatorsInit';
import { deploy as deployStakeManager } from './StakeManager';

const config = require('./config');

async function deployStaking() {
    let chainId = (await ethers.provider.getNetwork()).chainId;
    console.log("Chain Id:", chainId);

    const chainConfig = config[chainId];

    const rewardDelegators: Contract = await deployRewardDelegators();
    const stakeManager: Contract = await deployStakeManager(rewardDelegators.address);
    const clusterRegistry: Contract = await deployClusterRegistry(rewardDelegators.address);
    const clusterSelectorMap = Object();
    for(let network in chainConfig.staking.rewardWeights) {
        const clusterSelector = await deployClusterSelector(network, rewardDelegators.address);
        clusterSelectorMap[network] = clusterSelector.address;
    }
    const receiverStaking: Contract = await deployReceiverStaking();
    const clusterRewards: Contract = await deployClusterRewards(rewardDelegators.address, receiverStaking.address, clusterSelectorMap);
    await initRewardDelegators(rewardDelegators.address, stakeManager.address, clusterRewards.address, clusterRegistry.address);
}

deployStaking()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
