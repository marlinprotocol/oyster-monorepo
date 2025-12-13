import { ethers, upgrades, run } from 'hardhat';
import { Contract } from 'ethers';
import * as fs from 'fs';
import { AttestationVerifier } from "../../typechain-types";
import { upgrade as upgradeUtil } from '../utils/Upgrade';
const config = require('./config');

export async function deploy(enclaveImages?: AttestationVerifier.EnclaveImageStruct[], enclaveKeys?: string[], noLog?: boolean): Promise<Contract> {
    let chainId = (await ethers.provider.getNetwork()).chainId;

    const chainConfig = config[chainId];

    const AttestationVerifier = await ethers.getContractFactory('AttestationVerifier');

    var addresses: { [key: string]: { [key: string]: string } } = {};
    if (!noLog) {
        console.log("Chain Id:", chainId);

        if (fs.existsSync('address.json')) {
            addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
        }

        if (addresses[chainId] === undefined) {
            addresses[chainId] = {};
        }

        if (addresses[chainId]['AttestationVerifier'] !== undefined) {
            console.log("Existing deployment:", addresses[chainId]['AttestationVerifier']);
            return AttestationVerifier.attach(addresses[chainId]['AttestationVerifier']);
        }
    }

    if (enclaveImages === undefined) {
        enclaveImages = [];
        for (let i = 0; i < chainConfig.enclaves.whitelistedImages.length; i++) {
            if (chainConfig.enclaves.whitelistedImages[i].PCR === undefined) {
                throw new Error(`Image ${i}: PCR not defined for image`);
            }
            if (chainConfig.enclaves.whitelistedImages[i].PCR.PCR0.length !== 96) {
                throw new Error(`Image ${i}: PCR0 length is not 96`);
            }
            if (chainConfig.enclaves.whitelistedImages[i].PCR.PCR1.length !== 96) {
                throw new Error(`Image ${i}: PCR1 length is not 96`);
            }
            if (chainConfig.enclaves.whitelistedImages[i].PCR.PCR2.length !== 96) {
                throw new Error(`Image ${i}: PCR2 length is not 96`);
            }
            const image = {
                PCR0: "0x" + chainConfig.enclaves.whitelistedImages[i].PCR.PCR0,
                PCR1: "0x" + chainConfig.enclaves.whitelistedImages[i].PCR.PCR1,
                PCR2: "0x" + chainConfig.enclaves.whitelistedImages[i].PCR.PCR2,
            };
            enclaveImages.push(image);
        }
    }

    if (enclaveKeys === undefined) {
        enclaveKeys = [];
        for (let i = 0; i < chainConfig.enclaves.whitelistedImages.length; i++) {
            if (chainConfig.enclaves.whitelistedImages[i].enclaveKey === undefined) {
                throw new Error(`Image ${i}: Enclave key not defined for image`);
            }
            enclaveKeys.push(chainConfig.enclaves.whitelistedImages[i].enclaveKey);
        }
    }

    let admin = chainConfig.admin;

    let attestationVerifier = await upgrades.deployProxy(AttestationVerifier, [enclaveImages, enclaveKeys, admin], { kind: "uups" });

    if (!noLog) {
        console.log("Deployed addr:", attestationVerifier.address);

        addresses[chainId]['AttestationVerifier'] = attestationVerifier.address;

        fs.writeFileSync('address.json', JSON.stringify(addresses, null, 2), 'utf8');
    }

    return attestationVerifier;
}

export async function upgrade() {
    await upgradeUtil('AttestationVerifier', 'AttestationVerifier', []);
}

export async function verify() {
    let chainId = (await ethers.provider.getNetwork()).chainId;
    console.log("Chain Id:", chainId);

    var addresses: { [key: string]: { [key: string]: string } } = {};
    if (fs.existsSync('address.json')) {
        addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
    }

    if (addresses[chainId] === undefined || addresses[chainId]['AttestationVerifier'] === undefined) {
        throw new Error("Attestation Verifier not deployed");
    }

    const implAddress = await upgrades.erc1967.getImplementationAddress(addresses[chainId]['AttestationVerifier']);

    await run("verify:verify", {
        address: implAddress,
        constructorArguments: []
    });

    console.log("Attestation Verifier verified");
}
