import { ethers } from "hardhat";
async function main() {
    const F = await ethers.getContractFactory("contracts/serverless-v2/OysterServerlessCodeContract.sol:OysterServerlessCodeContract");
    const c = await F.deploy();
    await c.waitForDeployment();
    console.log("CodeContract:", c.target);
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
