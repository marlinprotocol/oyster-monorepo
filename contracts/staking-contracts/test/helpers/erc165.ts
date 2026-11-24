import { expect } from "chai";
import { Contract, Signer } from "ethers";
import { ethers, network } from "hardhat";

export function testERC165(
  name: string,
  deployer: (signers: Signer[], addrs: string[]) => Promise<Contract>,
  interfaces: { [key: string]: string[] } = {}
) {
  describe(name, function () {
    let signers: Signer[];
    let addrs: string[];
    let contract: Contract;

    let snapshot: any;

    before(async function () {
      signers = await ethers.getSigners();
      addrs = await Promise.all(signers.map((a) => a.getAddress()));
      contract = await deployer(signers, addrs);
    });

    beforeEach(async function () {
      snapshot = await network.provider.request({
        method: "evm_snapshot",
        params: [],
      });
    });

    afterEach(async function () {
      await network.provider.request({
        method: "evm_revert",
        params: [snapshot],
      });
    });

    function makeInterfaceId(interfaces: string[]): string {
      return ethers.utils.hexlify(
        interfaces.map((i) => ethers.utils.arrayify(ethers.utils.id(i).substr(0, 10))).reduce((i1, i2) => i1.map((i, idx) => i ^ i2[idx]))
      );
    }

    it("supports ERC165", async function () {
      let interfaces = ["supportsInterface(bytes4)"];
      const iid = makeInterfaceId(interfaces);
      expect(await contract.supportsInterface(iid)).to.be.true;
    });

    it("does not support 0xffffffff", async function () {
      expect(await contract.supportsInterface("0xffffffff")).to.be.false;
    });

    Object.keys(interfaces).map((iname) => {
      it(`supports ${iname}`, async function () {
        const iid = makeInterfaceId(interfaces[iname]);
        expect(await contract.supportsInterface(iid)).to.be.true;
      });
    });
  });
}
