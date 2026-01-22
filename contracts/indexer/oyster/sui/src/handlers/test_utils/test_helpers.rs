// Test helper utilities for creating mock Sui events and alloy Log structures
// These helpers are used across all handler tests to create consistent test data
// Tests go through handle_log for comprehensive testing of the full event dispatch flow

use alloy::primitives::{Address as AlloyAddress, Bytes};
use alloy::rpc::types::Log;
use sui_sdk_types::Address;

// ============================================================================
// BCS Encoding Helpers for Provider Events
// ============================================================================

/// BCS-encode a ProviderAdded event
/// Event structure: { provider: Address, cp: String }
pub fn encode_provider_added_event(provider: &Address, cp: &str) -> Vec<u8> {
    let mut data = Vec::new();
    // Address is 32 bytes, written directly
    data.extend_from_slice(provider.as_bytes());
    // String is encoded as length (ULEB128) + bytes
    encode_string(&mut data, cp);
    data
}

/// BCS-encode a ProviderRemoved event
/// Event structure: { provider: Address }
pub fn encode_provider_removed_event(provider: &Address) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(provider.as_bytes());
    data
}

/// BCS-encode a ProviderUpdatedWithCp event
/// Event structure: { provider: Address, cp: String }
pub fn encode_provider_updated_with_cp_event(provider: &Address, cp: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(provider.as_bytes());
    encode_string(&mut data, cp);
    data
}

// ============================================================================
// BCS Encoding Helpers for Job Events
// ============================================================================

/// BCS-encode a JobOpened event
/// Event structure: { job_id: u128, owner: Address, provider: Address, metadata: String, rate: u64, balance: u64, timestamp: u64 }
pub fn encode_job_opened_event(
    job_id: u128,
    owner: &Address,
    provider: &Address,
    metadata: &str,
    rate: u64,
    balance: u64,
    timestamp: u64,
) -> Vec<u8> {
    let mut data = Vec::new();
    // u128 is 16 bytes little-endian
    data.extend_from_slice(&job_id.to_le_bytes());
    data.extend_from_slice(owner.as_bytes());
    data.extend_from_slice(provider.as_bytes());
    encode_string(&mut data, metadata);
    data.extend_from_slice(&rate.to_le_bytes());
    data.extend_from_slice(&balance.to_le_bytes());
    data.extend_from_slice(&timestamp.to_le_bytes());
    data
}

/// BCS-encode a JobClosed event
/// Event structure: { job_id: u128 }
pub fn encode_job_closed_event(job_id: u128) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&job_id.to_le_bytes());
    data
}

/// BCS-encode a JobDeposited event
/// Event structure: { job_id: u128, owner: Address, amount: u64 }
pub fn encode_job_deposited_event(job_id: u128, owner: &Address, amount: u64) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&job_id.to_le_bytes());
    data.extend_from_slice(owner.as_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

/// BCS-encode a JobWithdrew event
/// Event structure: { job_id: u128, owner: Address, amount: u64 }
pub fn encode_job_withdrew_event(job_id: u128, owner: &Address, amount: u64) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&job_id.to_le_bytes());
    data.extend_from_slice(owner.as_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

/// BCS-encode a JobSettled event
/// Event structure: { job_id: u128, amount: u64, settled_until: u64 }
pub fn encode_job_settled_event(job_id: u128, amount: u64, settled_until: u64) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&job_id.to_le_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&settled_until.to_le_bytes());
    data
}

/// BCS-encode a JobMetadataUpdated event
/// Event structure: { job_id: u128, new_metadata: String }
pub fn encode_job_metadata_updated_event(job_id: u128, new_metadata: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&job_id.to_le_bytes());
    encode_string(&mut data, new_metadata);
    data
}

/// BCS-encode a JobReviseRateFinalized event
/// Event structure: { job_id: u128, new_rate: u64 }
pub fn encode_job_revise_rate_finalized_event(job_id: u128, new_rate: u64) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&job_id.to_le_bytes());
    data.extend_from_slice(&new_rate.to_le_bytes());
    data
}

// ============================================================================
// BCS Encoding Helpers for Lock Events
// ============================================================================

/// BCS-encode a LockCreated event
/// Event structure: { selector: Vec<u8>, key: Vec<u8>, i_value: [u8; 32], unlock_time: u64 }
pub fn encode_lock_created_event(
    selector: &[u8],
    key: &[u8],
    i_value: [u8; 32],
    unlock_time: u64,
) -> Vec<u8> {
    let mut data = Vec::new();
    encode_bytes(&mut data, selector);
    encode_bytes(&mut data, key);
    // i_value is a fixed 32-byte array
    data.extend_from_slice(&i_value);
    data.extend_from_slice(&unlock_time.to_le_bytes());
    data
}

/// BCS-encode a LockDeleted event
/// Event structure: { selector: Vec<u8>, key: Vec<u8>, i_value: [u8; 32] }
pub fn encode_lock_deleted_event(selector: &[u8], key: &[u8], i_value: [u8; 32]) -> Vec<u8> {
    let mut data = Vec::new();
    encode_bytes(&mut data, selector);
    encode_bytes(&mut data, key);
    data.extend_from_slice(&i_value);
    data
}

// ============================================================================
// BCS Primitive Encoding Helpers
// ============================================================================

/// Encode a string in BCS format (ULEB128 length + UTF-8 bytes)
fn encode_string(data: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    encode_uleb128(data, bytes.len() as u64);
    data.extend_from_slice(bytes);
}

/// Encode a byte vector in BCS format (ULEB128 length + bytes)
fn encode_bytes(data: &mut Vec<u8>, bytes: &[u8]) {
    encode_uleb128(data, bytes.len() as u64);
    data.extend_from_slice(bytes);
}

/// Encode a u64 as ULEB128 (variable-length encoding)
fn encode_uleb128(data: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            data.push(byte);
            break;
        } else {
            data.push(byte | 0x80);
        }
    }
}

/// Convert a u64 rate value to a 32-byte little-endian array (for i_value in lock events)
pub fn rate_to_i_value(rate: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&rate.to_le_bytes());
    bytes
}

// ============================================================================
// Alloy Log Test Helper
// ============================================================================

/// A helper struct that creates alloy Logs for testing through handle_log
///
/// This mirrors the format created by sui_log_to_alloy_log in provider.rs:
/// Data format: [event_type_len (4 bytes LE), event_type_bytes, tx_digest_len (4 bytes LE), tx_digest_bytes, bcs_contents]
pub struct TestSuiLog {
    pub event_name: String,
    pub tx_digest: String,
    pub checkpoint: u64,
    pub bcs_contents: Vec<u8>,
}

impl TestSuiLog {
    /// Create a new TestSuiLog
    ///
    /// The event_name should be just the event name (e.g., "ProviderAdded"),
    /// which will be prefixed with a mock package path for the full event type.
    pub fn new(event_name: &str, tx_digest: &str, checkpoint: u64, bcs_contents: Vec<u8>) -> Self {
        Self {
            event_name: event_name.to_string(),
            tx_digest: tx_digest.to_string(),
            checkpoint,
            bcs_contents,
        }
    }

    /// Convert to an alloy Log that can be passed to handle_log
    ///
    /// This creates a Log in the exact format expected by parse_sui_log:
    /// - block_number = checkpoint
    /// - log_index = 0 (or provided)
    /// - data = encoded event_type, tx_digest, and bcs_contents
    pub fn to_alloy_log(&self) -> Log {
        self.to_alloy_log_with_index(0)
    }

    /// Convert to an alloy Log with a specific log index
    pub fn to_alloy_log_with_index(&self, log_index: u64) -> Log {
        // Create full event type path (matching Sui format)
        let event_type = format!("0x0::test_module::{}", self.event_name);
        let event_type_bytes = event_type.as_bytes();
        let event_type_len = (event_type_bytes.len() as u32).to_le_bytes();

        let tx_digest_bytes = self.tx_digest.as_bytes();
        let tx_digest_len = (tx_digest_bytes.len() as u32).to_le_bytes();

        // Build data in the format expected by parse_sui_log
        let mut data = Vec::with_capacity(
            4 + event_type_bytes.len() + 4 + tx_digest_bytes.len() + self.bcs_contents.len(),
        );
        data.extend_from_slice(&event_type_len);
        data.extend_from_slice(event_type_bytes);
        data.extend_from_slice(&tx_digest_len);
        data.extend_from_slice(tx_digest_bytes);
        data.extend_from_slice(&self.bcs_contents);

        Log {
            block_hash: None,
            block_number: Some(self.checkpoint),
            block_timestamp: None,
            log_index: Some(log_index),
            transaction_hash: None,
            transaction_index: None,
            removed: false,
            inner: alloy::primitives::Log {
                address: AlloyAddress::ZERO,
                data: alloy::primitives::LogData::new_unchecked(vec![], Bytes::from(data)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uleb128_encoding() {
        // Test small values
        let mut data = Vec::new();
        encode_uleb128(&mut data, 0);
        assert_eq!(data, vec![0]);

        data.clear();
        encode_uleb128(&mut data, 1);
        assert_eq!(data, vec![1]);

        data.clear();
        encode_uleb128(&mut data, 127);
        assert_eq!(data, vec![127]);

        // Test values that need multiple bytes
        data.clear();
        encode_uleb128(&mut data, 128);
        assert_eq!(data, vec![0x80, 0x01]);

        data.clear();
        encode_uleb128(&mut data, 300);
        assert_eq!(data, vec![0xac, 0x02]);
    }

    #[test]
    fn test_string_encoding() {
        let mut data = Vec::new();
        encode_string(&mut data, "hello");
        // 5 (length) + "hello"
        assert_eq!(data, vec![5, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn test_rate_to_i_value() {
        let value = rate_to_i_value(100);
        assert_eq!(value[0], 100);
        assert_eq!(value[1..], [0u8; 31]);
    }
}
