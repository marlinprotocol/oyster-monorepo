use alloy::sol;

// Multicall3, deployed at the same address on most chains, see https://www.multicall3.com
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IMulticall3 {
        struct Call3 {
            address target;
            bool allowFailure;
            bytes callData;
        }

        struct Call3Result {
            bool success;
            bytes returnData;
        }

        function aggregate3(Call3[] calldata calls)
            external
            payable
            returns (Call3Result[] memory returnData);
    }
);
