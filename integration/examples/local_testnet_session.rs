//! Run a full Vitārit local "testnet" session (simulated ledger).
//!
//! Usage: `cargo run -p vitarit-integration --example local_testnet_session`

use vitarit_integration::{LocalSession, SessionParams};

fn main() {
    let session = LocalSession::new(SessionParams::default()).expect("session");
    let report = session.run_simulated().expect("e2e");
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
