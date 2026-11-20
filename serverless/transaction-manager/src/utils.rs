use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::reqwest::Url;
use alloy::transports::{RpcError, TransportErrorKind};

use crate::errors::TxnManagerSendError;

/// Classifies an error returned by the RPC for a transaction send or a gas estimate.
///
/// Only an error response from the node (a JSON-RPC error object) can say something about the
/// transaction. Transport failures, empty or unreadable responses and local errors are never
/// treated as a contract revert, they are retried.
///
/// A revert is recognised by the JSON-RPC error code 3 (execution reverted, with the revert
/// data). The other cases are recognised by the error message of the node, there is no common
/// error code for them: geth based nodes use -32000 for all of them, other clients and
/// providers use -32003, -32010 or -32603. Only the message is read, not the error data.
pub(crate) fn parse_send_error(error: &RpcError<TransportErrorKind>) -> TxnManagerSendError {
    let error_string = error.to_string();

    let payload = match error {
        RpcError::ErrorResp(payload) => payload,
        RpcError::Transport(_) | RpcError::NullResp | RpcError::DeserError { .. } => {
            return TxnManagerSendError::NetworkConnectivity(error_string);
        }
        _ => return TxnManagerSendError::OtherRetryable(error_string),
    };

    // Rate limits and load balancer errors of common providers
    if payload.is_retry_err() {
        return TxnManagerSendError::NetworkConnectivity(error_string);
    }

    if payload.code == 3 {
        return TxnManagerSendError::ContractExecution(error_string);
    }

    let message = payload.message.to_lowercase();

    if message.contains("revert") || message.contains("vm execution error") {
        return TxnManagerSendError::ContractExecution(error_string);
    }

    if message.contains("nonce too low") || message.contains("nonce is too low") {
        return TxnManagerSendError::NonceTooLow(error_string);
    }

    if message.contains("nonce too high") || message.contains("too many pending transactions") {
        return TxnManagerSendError::NonceTooHigh(error_string);
    }

    if message.contains("already known")
        || message.contains("known transaction")
        || message.contains("alreadyknown")
        || message.contains("already imported")
    {
        return TxnManagerSendError::AlreadyKnown(error_string);
    }

    if message.contains("insufficient funds")
        || message.contains("insufficientfunds")
        || message.contains("sender doesn't have enough funds to send")
        || (message.contains("transaction requires at least") && message.contains("gas but got"))
    {
        return TxnManagerSendError::InsufficientBalance(error_string);
    }

    if message.contains("out of gas") || message.contains("gas too low") {
        return TxnManagerSendError::OutOfGas(error_string);
    }

    if message.contains("gas limit too high")
        || message.contains("exceeds block gas limit")
        || message.contains("intrinsic gas too high")
    {
        return TxnManagerSendError::GasTooHigh(error_string);
    }

    if message.contains("underpriced")
        || message.contains("gas price too low")
        || message.contains("less than block base fee")
    {
        return TxnManagerSendError::GasPriceLow(error_string);
    }

    TxnManagerSendError::OtherRetryable(error_string)
}

pub(crate) fn verify_rpc_url(rpc_url: &str) -> Result<(), TxnManagerSendError> {
    let url = Url::parse(rpc_url);
    if url.is_err() {
        return Err(TxnManagerSendError::InvalidRpcUrl(
            url.err().unwrap().to_string(),
        ));
    }
    let url = url.unwrap();
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(TxnManagerSendError::InvalidRpcUrl(format!(
            "Invalid RPC URL: {:?}. URL must start with http or https",
            rpc_url
        )));
    }
    Ok(())
}

pub(crate) fn verify_private_signer(
    private_signer: String,
) -> Result<PrivateKeySigner, TxnManagerSendError> {
    let private_signer = private_signer.parse::<PrivateKeySigner>();
    if private_signer.is_err() {
        return Err(TxnManagerSendError::InvalidPrivateSigner(
            private_signer.err().unwrap().to_string(),
        ));
    }
    Ok(private_signer.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::transports::TransportError;

    fn error_response(json: &str) -> RpcError<TransportErrorKind> {
        RpcError::ErrorResp(serde_json::from_str(json).unwrap())
    }

    fn classify(json: &str) -> TxnManagerSendError {
        parse_send_error(&error_response(json))
    }

    #[test]
    fn revert_is_contract_execution() {
        // anvil and geth, eth_estimateGas on a contract reverting without and with a reason
        for json in [
            r#"{"code":3,"message":"execution reverted","data":"0x"}"#,
            r#"{"code":3,"message":"execution reverted: no","data":"0x08c379a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000026e6f000000000000000000000000000000000000000000000000000000000000"}"#,
            // older geth, revert without data
            r#"{"code":-32000,"message":"execution reverted"}"#,
            // hardhat
            r#"{"code":-32603,"message":"Error: VM Exception while processing transaction: reverted with reason string 'no'"}"#,
            // nethermind
            r#"{"code":-32015,"message":"VM execution error.","data":"revert"}"#,
        ] {
            assert!(
                matches!(classify(json), TxnManagerSendError::ContractExecution(_)),
                "{json}"
            );
        }
    }

    #[test]
    fn insufficient_funds_is_insufficient_balance() {
        for json in [
            // anvil
            r#"{"code":-32003,"message":"Insufficient funds for gas * price + value"}"#,
            // geth
            r#"{"code":-32000,"message":"insufficient funds for gas * price + value: address 0x0123456789012345678901234567890123456789 have 0 want 21000000000000"}"#,
            r#"{"code":-32000,"message":"insufficient funds for transfer"}"#,
            // nethermind
            r#"{"code":-32010,"message":"InsufficientFunds, Balance is 0 less than sending value + gas 21000"}"#,
            // openethereum
            r#"{"code":-32010,"message":"Insufficient funds. The account you tried to send transaction from does not have enough funds. Required 21000 and got: 0."}"#,
        ] {
            assert!(
                matches!(classify(json), TxnManagerSendError::InsufficientBalance(_)),
                "{json}"
            );
        }
    }

    #[test]
    fn known_send_errors() {
        // anvil
        assert!(matches!(
            classify(r#"{"code":-32003,"message":"nonce too low"}"#),
            TxnManagerSendError::NonceTooLow(_)
        ));
        // geth
        assert!(matches!(
            classify(r#"{"code":-32000,"message":"nonce too low: next nonce 5, tx nonce 4"}"#),
            TxnManagerSendError::NonceTooLow(_)
        ));
        // anvil
        assert!(matches!(
            classify(r#"{"code":-32003,"message":"transaction already imported"}"#),
            TxnManagerSendError::AlreadyKnown(_)
        ));
        // geth
        assert!(matches!(
            classify(r#"{"code":-32000,"message":"already known"}"#),
            TxnManagerSendError::AlreadyKnown(_)
        ));
        assert!(matches!(
            classify(r#"{"code":-32000,"message":"replacement transaction underpriced"}"#),
            TxnManagerSendError::GasPriceLow(_)
        ));
        assert!(matches!(
            classify(
                r#"{"code":-32000,"message":"transaction underpriced: tip needed 1, tip permitted 0"}"#
            ),
            TxnManagerSendError::GasPriceLow(_)
        ));
        // anvil
        assert!(matches!(
            classify(r#"{"code":-32003,"message":"max fee per gas less than block base fee"}"#),
            TxnManagerSendError::GasPriceLow(_)
        ));
        assert!(matches!(
            classify(r#"{"code":-32000,"message":"intrinsic gas too low"}"#),
            TxnManagerSendError::OutOfGas(_)
        ));
        assert!(matches!(
            classify(
                r#"{"code":-32000,"message":"intrinsic gas too high -- tx.gas_limit > env.block.gas_limit"}"#
            ),
            TxnManagerSendError::GasTooHigh(_)
        ));
        // geth
        assert!(matches!(
            classify(r#"{"code":-32000,"message":"exceeds block gas limit"}"#),
            TxnManagerSendError::GasTooHigh(_)
        ));
    }

    #[test]
    fn rpc_and_network_failures_are_not_reverts() {
        // Error responses of the node or provider that are not about the transaction
        for json in [
            // arbitrum nitro, sequencer not reachable
            r#"{"code":-32000,"message":"failed to forward tx to sequencer, please try again. Error message from the sequencer: context deadline exceeded"}"#,
            // infura
            r#"{"code":-32005,"message":"daily request count exceeded, request rate limited"}"#,
            r#"{"code":-32000,"message":"header not found"}"#,
            // alchemy
            r#"{"code":429,"message":"Your app has exceeded its compute units per second capacity."}"#,
            r#"{"code":-32603,"message":"Internal error: request failed"}"#,
            // revert data in the error data does not make it a revert
            r#"{"code":-32000,"message":"internal error","data":"execution reverted"}"#,
        ] {
            let err = classify(json);
            assert!(
                matches!(
                    err,
                    TxnManagerSendError::NetworkConnectivity(_)
                        | TxnManagerSendError::OtherRetryable(_)
                ),
                "{json}: {err:?}"
            );
        }

        for err in [
            // what alloy returns when the RPC is not reachable
            TransportErrorKind::custom_str(
                "error sending request for url (http://127.0.0.1:1/): client error (Connect): \
                 tcp connect error: Connection refused (os error 111): failed",
            ),
            TransportErrorKind::http_error(502, "upstream request failed: reverted".to_string()),
            RpcError::NullResp,
            TransportError::deser_err(
                serde_json::from_str::<u64>("x").unwrap_err(),
                "<html>execution reverted</html>",
            ),
        ] {
            assert!(
                matches!(
                    parse_send_error(&err),
                    TxnManagerSendError::NetworkConnectivity(_)
                ),
                "{err:?}"
            );
        }
    }
}
