import { BigNumber, BigNumberish, utils } from "ethers";
import { keccak256, randomBytes } from "ethers/lib/utils";

export class FuzzedNumber {
  static random(): BigNumber {
    const bytes = randomBytes(32);
    return BigNumber.from(bytes);
  }

  static randomInRange(min: BigNumberish, max: BigNumberish): BigNumber {
    if (BigNumber.from(max).lte(min)) {
      throw new Error("max should be more than min");
    }
    const bytes = randomBytes(32);
    const diff = BigNumber.from(max).sub(min);
    return BigNumber.from(bytes).mod(diff).add(min);
  }
}

export class FuzzedAddress {
  static random(rand = "123"): string {
    let address = keccak256(Buffer.from(rand + new Date().valueOf().toString()))
      .toString()
      .slice(0, 42);
    return utils.getAddress(address);
  }
}
