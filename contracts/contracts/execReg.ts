import { getBytes } from "ethers";
import { ethers } from "hardhat";

async function main() {
    let stakeAmount = 10n**19n;
    let ec= (await ethers.getContractFactory("Executors")).attach("0x2fCB1F84491A84B719143959730A1237AE6E55a6");
    // TODO: fill attestation details
    let enclavePubkey = "0x78f5e71f2374187be9052094aaae807c3da16a3db22a87a66ab26b9863926af4028bc14b5c44ccfee07409372e55bf434670ca968d5892893889b2cd86132999";
    let attestationSignature = "0x6af33c862b11ac6f23fc5758e6d712da4a377e7653b82e691ee65ee655ff1bb575313e18a7e072386594667bc809b6e0deb72997901d82d923f4309692ed2ba91c";
    let attestationTimestamp = 1737612625907;
    const exec_img = {
        PCR0 : getBytes("0x3d94326f8a889e12b8a603174334ffc77b81a4515418aef341827015a4002f844e8c7b6a02f5609ccbc47f18bac7df0c"),
        PCR1 : getBytes("0x34c9578ce5105b9de453fe1ed082b09cc5a7587f6b1dd3304b4b2e159004b8f35d1ff2376593a2e9322b118fec3fa06f"),
        PCR2 : getBytes("0xb6546c776a76b94285c0124a1658b90fd9eaf2676efe2070ef46486b51755e76c76239755fdde5c9b0e9a6d81fc39330"),
    };
    let attestation = {
            enclavePubKey: enclavePubkey,
            PCR0: exec_img.PCR0,
            PCR1: exec_img.PCR1,
            PCR2: exec_img.PCR2,
            timestampInMilliseconds: attestationTimestamp,
    };

    let env = 1;
    let job_capacity = 20;
    let sign_timestamp = 1737612747;
    let exec_signature = "0x0ad44c79e3d3a92c72e724766f54154e29924bc774b6238e32be2bfc0f91baa2589b5d70adaf1dbc6c93c26de4dc9cb382f04d5518d2787a1e117f03964d507d1c";
    const registerTx = await ec.registerExecutor(
        attestationSignature,
        attestation,
        job_capacity,
        sign_timestamp,
        exec_signature,
        stakeAmount,
        env
    );
    const address = ethers.computeAddress(enclavePubkey);
  
    console.log("Executor registered successfully: ", address);
}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });
