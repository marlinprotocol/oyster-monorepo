import { BigNumber as BN } from "ethers";
import { ethers as ethersForType } from "hardhat";

export async function skipBlocks(ethers: typeof ethersForType, n: number) {
  await Promise.all([...Array(n)].map(async (x) => await ethers.provider.send("evm_mine", [])));
}

export async function skipTime(ethers: typeof ethersForType, t: number) {
  await ethers.provider.send("evm_increaseTime", [t]);
  await skipBlocks(ethers, 1);
}

export async function skipToTimestamp(ethers: typeof ethersForType, t: number) {
  await ethers.provider.send("evm_mine", [t]);
}

export async function impersonate(ethers: typeof ethersForType, account: string) {
  await ethers.provider.send("hardhat_impersonateAccount", [account]);
  return ethers.getSigner(account);
}

export async function setBalance(ethers: typeof ethersForType, account: string, balance: BN) {
  await ethers.provider.send("hardhat_setBalance", [account, balance.toHexString().replace("0x0", "0x")]);
}

export async function increaseBalance(ethers: typeof ethersForType, account: string, amount: BN) {
  const balance = await ethers.provider.getBalance(account);
  await ethers.provider.send("hardhat_setBalance", [account, balance.add(amount).toHexString().replace("0x0", "0x")]);
}

export const random = (min: BN | string, max: BN | string): string => {
  const randomizer = ethersForType.BigNumber.from(ethersForType.utils.randomBytes(32));
  return randomizer.mod(BN.from(max).sub(min)).add(min).toString();
};

export const getRandomElementsFromArray = <T>(array: T[], noOfElements: number): T[] => {
  if (array.length < noOfElements) {
    throw Error("Insuff Elements in array");
  }

  return array.sort(() => 0.5 - Math.random()).slice(0, noOfElements);
};

export const BIG_ZERO = BN.from(0);
