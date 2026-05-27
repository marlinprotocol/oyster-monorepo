import { Signer } from "ethers";
import {
  MPond__factory,
  Pond__factory,
  MPond,
  Pond,
  Bridge,
  Bridge__factory,
  Timelock,
  Timelock__factory,
  GovernorAlpha,
  GovernorAlpha__factory,
  ReceiverStaking,
  ReceiverStaking__factory,
  ClusterRegistry,
  ClusterRegistry__factory,
  RewardDelegators,
  RewardDelegators__factory,
  StakeManager,
  StakeManager__factory,
  ClusterRewards,
  ClusterRewards__factory,
  ClusterSelector,
  ClusterSelector__factory,
  MarketV1,
  MarketV1__factory,
  AttestationVerifier__factory,
  AttestationVerifier,
  AttestationAutherUpgradeable__factory,
  AttestationAutherUpgradeable,
  AttestationAutherSample__factory,
  AttestationAutherSample,
  Credit__factory,
  Credit,
} from "../typechain-types";

export function getMpond(contractAddress: string, signer: Signer): MPond {
  return new MPond__factory(signer).attach(contractAddress);
}

export function getPond(contractAddress: string, signer: Signer): Pond {
  return new Pond__factory(signer).attach(contractAddress);
}

export function getBridge(contractAddress: string, signer: Signer): Bridge {
  return new Bridge__factory(signer).attach(contractAddress);
}

export function getTimelock(contractAddress: string, signer: Signer): Timelock {
  return new Timelock__factory(signer).attach(contractAddress);
}

export function getGovernorAlpha(contractAddress: string, signer: Signer): GovernorAlpha {
  return new GovernorAlpha__factory(signer).attach(contractAddress);
}

export function getReceiverStaking(contractAddress: string, signer: Signer): ReceiverStaking {
  return new ReceiverStaking__factory(signer).attach(contractAddress);
}

export function getClusterRegistry(contractAddress: string, signer: Signer): ClusterRegistry {
  return new ClusterRegistry__factory(signer).attach(contractAddress);
}

export function getRewardDelegators(contractAddress: string, signer: Signer): RewardDelegators {
  return new RewardDelegators__factory(signer).attach(contractAddress);
}

export function getStakeManager(contractAddress: string, signer: Signer): StakeManager {
  return new StakeManager__factory(signer).attach(contractAddress);
}

export function getClusterSelector(contractAddress: string, signer: Signer): ClusterSelector {
  return new ClusterSelector__factory(signer).attach(contractAddress);
}

export function getClusterRewards(contractAddress: string, signer: Signer): ClusterRewards {
  return new ClusterRewards__factory(signer).attach(contractAddress);
}

export function getCredit(contractAddress: string, signer: Signer): Credit {
  return new Credit__factory(signer).attach(contractAddress);
}

export function getMarketV1(contractAddress: string, signer: Signer): MarketV1 {
  return new MarketV1__factory(signer).attach(contractAddress);
}

export function getAttestationVerifier(contractAddress: string, signer: Signer): AttestationVerifier {
  return new AttestationVerifier__factory(signer).attach(contractAddress);
}

export function getAttestationAutherUpgradeable(contractAddress: string, signer: Signer): AttestationAutherUpgradeable {
  return new AttestationAutherUpgradeable__factory(signer).attach(contractAddress);
}

export function getAttestationAutherSample(contractAddress: string, signer: Signer): AttestationAutherSample {
  return new AttestationAutherSample__factory(signer).attach(contractAddress);
}
