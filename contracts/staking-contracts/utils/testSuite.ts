import { network } from "hardhat";
import * as helpers from "@nomicfoundation/hardhat-network-helpers";

export function takeSnapshotBeforeAndAfterEveryTest(pre_req: () => Promise<any>) {
  let localsnapshot: any;

  beforeEach(async function() {
    localsnapshot = await helpers.takeSnapshot();

    await pre_req();
  });

  afterEach(async function() {
    await localsnapshot.restore()
  });
}

export function saveAndRestoreStateToParent(pre_req: () => Promise<any>) {
  let localsnapshot: any;

  before(async function() {
    localsnapshot = await network.provider.request({
      method: "evm_snapshot",
      params: [],
    });
    this.timeout(400000);

    await pre_req();
  });

  after(async function() {
    await network.provider.request({
      method: "evm_revert",
      params: [localsnapshot],
    });
  });
}
