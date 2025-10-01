use alloy::primitives::Address;
use std::sync::Once;

static GOVERNANCE_CONTRACT: Once = Once::new();
static mut GOVERNANCE_CONTRACT_VALUE: Option<Address> = None;

static MARKET_CONTRACT: Once = Once::new();
static mut MARKET_CONTRACT_VALUE: Option<Address> = None;

pub fn set_governance_contract(address: Address) {
    unsafe {
        GOVERNANCE_CONTRACT.call_once(|| {
            GOVERNANCE_CONTRACT_VALUE = Some(address);
        });
    }
}

pub fn set_market_contract(address: Address) {
    unsafe {
        MARKET_CONTRACT.call_once(|| {
            MARKET_CONTRACT_VALUE = Some(address);
        });
    }
}

pub fn get_governance_contract() -> Address {
    unsafe { GOVERNANCE_CONTRACT_VALUE.expect("GOVERNANCE_CONTRACT not set") }
}

pub fn get_market_contract() -> Address {
    unsafe { MARKET_CONTRACT_VALUE.expect("MARKET_CONTRACT not set") }
}
