import { ethers } from "hardhat";
import * as fs from "fs";
import fetch from "node-fetch";

import { RewardDelegators__factory, RewardDelegators } from "../typechain-types";

const subraphUrl = "https://api.thegraph.com/subgraphs/name/marlinprotocol/staking-kovan";
const networkId = "0x0000";

async function main() {
  let signers = await ethers.getSigners();
  let admin = signers[0];
  let chainId = (await ethers.provider.getNetwork()).chainId;
  console.log("Chain Id:", chainId);

  var addresses: { [key: string]: { [key: string]: string } } = {};
  if (fs.existsSync("address.json")) {
    addresses = JSON.parse(fs.readFileSync("address.json", "utf8"));
  }

  const relevantContractAddresses = addresses[chainId];
  const clusters = (await getClusters(subraphUrl)).map((a) => a.id) as string[];

  const rewardDelegators = RewardDelegators__factory.connect(relevantContractAddresses.RewardDelegators, admin);
  const tx = await rewardDelegators.refreshClusterDelegation(networkId, clusters);
  return { relevantContractAddresses, clusters, receipt: await tx.wait() };
}

main().then(console.log);

async function getClusters(url: string): Promise<any[]> {
  let skip = 0;
  const countPerQuery = 999;
  const allData = [];
  for (;;) {
    const data = JSON.stringify({
      query: `{
            clusters(first: ${countPerQuery}, skip: ${countPerQuery * skip}) {
              id
            }
          }`,
    });

    const options = {
      url,
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: data,
    };

    const result = await (await fetchData(options)).json();
    if (result.errors) {
      throw new Error("Error while fetching data from subgraph");
    } else if (result.data.clusters.length === 0) {
      return allData;
    } else {
      skip++;
      allData.push(...result.data.clusters);
    }
  }
}

export async function fetchData(requestData: any): Promise<any> {
  const data = await fetch(requestData.url, { headers: requestData.headers, method: requestData.method, body: requestData.body });
  return data;
}
