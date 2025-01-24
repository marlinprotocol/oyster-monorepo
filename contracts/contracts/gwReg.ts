import { getBytes } from "ethers";
import { ethers } from "hardhat";

async function main() {
    let stakeAmount = 10n**19n;
    let gc = (await ethers.getContractFactory("Gateways")).attach("0x9e35c784A5dAcC49E11abd9B509536B99D05A182");
    let rc = (await ethers.getContractFactory("Relay")).attach("0xD28179711eeCe385bc2096c5D199E15e6415A4f5");

    let chain_id = 42161;
    // TODO: fill attestation details
    let enclavePubkey = "0xd65376e52193942d2cd38100bafe1790b1876c74ddadd7f313f562e4c60642a3ef5c105035f6d6208932dac9ac2806e9f69d241b0dd4481d6f51ac5de1a01347";
    let attestationSignature = "0xcfe8b1c1103b0cab932ee04c1b1deaa9c486dd227de2efe34012a03c9de9c85d79f9fb2c51b772160938760a0a4d5fe7e1995e6569ee91ce21818af72b404b631c";
    let attestationTimestamp = 1737636200928;
    const gw_img = {
        PCR0 : getBytes("0x9d99bb615d48ca83aac007e3ecd50b465c1c2acf4c64787f6fb397b817dec6fe5672301e81bfd24b9c294fcb57afac93"),
        PCR1 : getBytes("0x3c9d303f89856ec3410913381c328350c32d14d2f86a2b4a7787998bd6d76d8f60fc88fea094bf5a02b2c2df1b7ad832"),
        PCR2 : getBytes("0x894db61812949a4719242c0c456e4f4f38b96e5d54b37d8cbc651ad284fe3fc641d9b07ec37af6bcf6d2e50966410f6b"),
    };
    // const gw_img = {
    //     PCR0 : getBytes("0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
    //     PCR1 : getBytes("0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
    //     PCR2 : getBytes("0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
    // };
    let attestation = {
            enclavePubKey: enclavePubkey,
            PCR0: gw_img.PCR0,
            PCR1: gw_img.PCR1,
            PCR2: gw_img.PCR2,
            timestampInMilliseconds: attestationTimestamp,
    };

    const relaySignature = "0x"+"843dec3db97b21124491ed76ce525e821853a489573e24d068c2d78e7881427f779b04b17f4cac353949d3e63bb65a2bda265b0cb2883d900862cee38bdb23b51b";
    const signatureTimestamp = 1737636228;

    try {
        const rcRegister = await rc.registerGateway(
            attestationSignature,
            attestation,
            relaySignature,
            signatureTimestamp
        );
        
        console.log("Relay registered: ", rcRegister);
    } catch (error) {
        if (error.data) {
            console.error('Error relay registration', error.data);
        }
        console.error('Error relay registration', error);
        process.exit(1);
    }
    
    
    let gatewaySignature = '0x'+'a88c3d096a87d30d50d2c107d12e90cfa26f55fa15290d7d28413349fae3e2f02151f641d49fb2837f90a2d931c06ed7691e0a22bba24bda38101e347adb16b51b';
    const gcRegister = await gc.registerGateway(
        attestationSignature,
        attestation,
        [chain_id],
        gatewaySignature,
        stakeAmount,
        signatureTimestamp
    );
    
    console.log("Gateway registered: ", gcRegister);

    const address = ethers.computeAddress(enclavePubkey);
    console.log(address);
}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });
