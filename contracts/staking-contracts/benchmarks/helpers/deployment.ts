import { ethers, upgrades } from "hardhat";

export function benchmark(name: string, constructorArgs: any[], initArgs: any[]) {
    describe(`${name} Deployment`, async () => {
        it('deploy logic', async function () {
            const ContractFactory = await ethers.getContractFactory(name);
            let contract = await ContractFactory.deploy(...constructorArgs);

            let receipt = await contract.deployTransaction.wait();

            console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
        });
        
        it('deploy proxy without initialize', async function () {
            const ContractFactory = await ethers.getContractFactory(name);
            let contract = await upgrades.deployProxy(ContractFactory, { 
              kind: "uups", 
              initializer: false,
              constructorArgs
            });

            let receipt = await contract.deployTransaction.wait();

            console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
        });
        
        it('initialize', async function () {
            const ContractFactory = await ethers.getContractFactory(name);
            let contract = await upgrades.deployProxy(ContractFactory, { 
                kind: "uups", 
                initializer: false,
                constructorArgs
            });

            let tx = await contract.initialize(...initArgs);
            let receipt = await tx.wait();

            console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
        });
        
        it('deploy proxy with initialize', async function () {
            const ContractFactory = await ethers.getContractFactory(name);
            let contract = await upgrades.deployProxy(ContractFactory, initArgs,
            { 
                kind: "uups",
                constructorArgs
            });

            let receipt = await contract.deployTransaction.wait();

            console.log("Gas used: ", receipt.gasUsed.sub(21000).toNumber());
        });
    })
}