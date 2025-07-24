import { ethers } from "hardhat";
import { StakeManager, StakeManager__factory } from "../typechain-types";
import { getPond, getStakeManager } from "../utils/typechainConvertor";

async function main() {
    const signer = await ethers.getSigner("0xB38e8c17e38363aF6EbdCb3dAE12e0243582891D");
    const StakeManager = getStakeManager("0xf90490186f370f324def2871f077668455f65253", signer);
    const Pond = getPond("0xdA0a57B710768ae17941a9Fa33f8B720c8bD9ddD", signer);

    await Pond.approve("0xf90490186f370f324def2871f077668455f65253", ethers.utils.parseEther("100000"));

    const tx = await StakeManager.createStashAndDelegate(
        ["0x5802add45f8ec0a524470683e7295faacc853f97cf4a8d3ffbaaf25ce0fd87c4"], 
        [ethers.utils.parseEther("1")],
        "0x6017b5df98118730e4c31b17c5a7438ecaa8887b"
    );

    const receipt = await tx.wait();
    console.log(JSON.stringify(receipt, null, 2))
}

main();