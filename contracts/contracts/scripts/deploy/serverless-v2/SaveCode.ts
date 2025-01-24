import { ethers } from "hardhat";

async function main() {
    const SaveCode = await ethers.getContractFactory("OysterServerlessCodeContract");
    console.log("Deploying SaveCode Contract...");
    let saveCode = await SaveCode.deploy();
    await saveCode.waitForDeployment();
    console.log("SaveCode Contract deployed to:", saveCode.target);

}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });