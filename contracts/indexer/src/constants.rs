use alloy::primitives::Address;
use std::sync::Once;

static USDC_ADDRESS: Once = Once::new();
static mut USDC_ADDRESS_VALUE: Option<Address> = None;

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
