import { ethers } from "hardhat";
import { BigNumber, constants, utils } from "ethers";

// pick Y numbers less than X
export async function pickYLtX(y: number, x: number, callback): Promise<any[]> {
    const results: Promise<any>[] = [];
    const picked: number[] = [];

    while(picked.length < y) {
        const index = Math.floor(Math.random() * x);
        if(!picked.includes(index)) {
            picked.push(index)
            results.push(callback(index));
        };
    }

    return await Promise.all(results);
}

export function randomlyDivideInXPieces(amount: BigNumber, X: number): BigNumber[] {
    let total: BigNumber = constants.Zero;
    let pieces: BigNumber[] = [];

    for(let i=0; i < X-1; i++) {
        pieces[i] = getRandomNumber(amount.div(X));
        total = total.add(pieces[i]);
    }
    pieces[X - 1] = amount.sub(total);

    return pieces;
}

export function getRandomNumber(max: BigNumber = constants.MaxUint256, maxLoss: number = 10): BigNumber {
    const min = max.mul(100 - maxLoss).div(100);
    const rand = BigNumber.from(utils.randomBytes(32)).mod(max.sub(min)).add(min);
    return rand;
}

export async function skipBlocks(n: number) {
    await Promise.all([...Array(n)].map(async (x) => await ethers.provider.send("evm_mine", [])));
}
  
export async function skipTime(t: number) {
    await ethers.provider.send("evm_increaseTime", [t]);
    await skipBlocks(1);
}

export const gasConsumedInYear = (gasEstimate: BigNumber, l1GasInL2: BigNumber): BigNumber => {
    return gasEstimate.add(l1GasInL2).mul(1600).mul(50).mul(365).div(BigNumber.from(10).pow(10))
}