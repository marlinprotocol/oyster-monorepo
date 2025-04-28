use alloy::primitives::Address;
use std::sync::Once;

static USDC_ADDRESS: Once = Once::new();
static mut USDC_ADDRESS_VALUE: Option<Address> = None;

static CONTRACT_UPGRADE_BLOCK: Once = Once::new();
static mut CONTRACT_UPGRADE_BLOCK_VALUE: Option<u64> = None;

// Set the USDC token address. This should be called once at startup.
pub fn set_usdc_address(address: Address) {
    unsafe {
        USDC_ADDRESS.call_once(|| {
            USDC_ADDRESS_VALUE = Some(address);
        });
    }
}

// Get the USDC token address. Panics if not initialized.
pub fn get_usdc_address() -> Address {
    unsafe { USDC_ADDRESS_VALUE.expect("USDC address not initialized") }
}

// Set the contract upgrade block number. This should be called once at startup.
pub fn set_contract_upgrade_block(block: u64) {
    unsafe {
        CONTRACT_UPGRADE_BLOCK.call_once(|| {
            CONTRACT_UPGRADE_BLOCK_VALUE = Some(block);
        });
    }
}

// Get the contract upgrade block number. Returns None if not initialized.
pub fn get_contract_upgrade_block() -> Option<u64> {
    unsafe { CONTRACT_UPGRADE_BLOCK_VALUE }
}
