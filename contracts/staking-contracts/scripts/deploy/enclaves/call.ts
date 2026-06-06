import { ethers } from "hardhat";

import { IERC20Upgradeable__factory } from "../../../typechain-types";
import { getConfig } from "../../helper/helper";

const SEND_TO = "0x47d40316867853189E1e04dc1eb53Dc71C8eb946";

async function main() {
  const { addresses, signers } = await getConfig();

  const admin = signers[0];
  console.log(admin);

  const credit = await ethers.getContractAt("Credit", addresses.proxy.credit);

  // // grant `MINTER_ROLE` to admin
  // const minter_tx = await credit.connect(admin).grantRole(await credit.MINTER_ROLE(), admin.address);
  // console.log(minter_tx);

  // // grant `TRANSFER_ALLOWED_ROLE` to `SEND_TO`
  // const transfer_allowed_tx = await credit.connect(admin).grantRole(await credit.TRANSFER_ALLOWED_ROLE(), SEND_TO);
  // console.log(transfer_allowed_tx);

  // // mint 500 credits to `SEND_TO`
  // const credit_mint_tx = await credit.connect(admin).mint(SEND_TO, ethers.utils.parseUnits("500", 6));
  // console.log(credit_mint_tx);

  // // const usdc = AccessControlEnumerableUpgradeable__factory.connect(addresses.proxy.usdc, admin);
  
  // transfer 1000 usdc to credit
  const usdc = IERC20Upgradeable__factory.connect(addresses.proxy.usdc, admin);
  await usdc.transfer(addresses.proxy.credit, ethers.utils.parseUnits("1000", 6));

  // grant `TRANSFER_ALLOWED_ROLE` to address(0)
  const transfer_allowed_tx = await credit.connect(admin).grantRole(await credit.TRANSFER_ALLOWED_ROLE(), addresses.proxy.marketV1);
  console.log(transfer_allowed_tx);
}

main();