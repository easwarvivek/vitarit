//! Quick timings for Bitcoin-layer steps.
//!
//!   cargo run --release --example timings

use std::time::{Duration, Instant};
use vitarit_bitcoin::keys::SessionKeys;
use vitarit_bitcoin::network::BtcNetwork;
use vitarit_bitcoin::protocol::{Fig7Params, Fig7Session};
use vitarit_bitcoin::transactions::{fake_outpoint, PaymentPlan, SetupPlan};

fn mean(iters: u32, mut f: impl FnMut()) -> Duration {
    for _ in 0..3 {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    t.elapsed() / iters
}

fn fmt(d: Duration) -> String {
    let us = d.as_secs_f64() * 1e6;
    if us >= 1000.0 {
        format!("{:.3} ms", us / 1000.0)
    } else {
        format!("{us:.1} µs")
    }
}

fn main() {
    let iters = 50u32;
    println!("Bitcoin-layer timings (iters={iters})\n");
    println!("{:<40} {:>12}", "Step", "Mean");
    println!("{}", "-".repeat(54));

    println!(
        "{:<40} {:>12}",
        "SessionKeys::generate(t=1,n=3)",
        fmt(mean(iters, || {
            let _ = SessionKeys::generate(BtcNetwork::Regtest, 1, 3).unwrap();
        }))
    );

    let keys = SessionKeys::generate(BtcNetwork::Regtest, 1, 3).unwrap();
    println!(
        "{:<40} {:>12}",
        "SetupPlan::from_keys",
        fmt(mean(iters, || {
            let _ = SetupPlan::from_keys(&keys, 100_000, 500).unwrap();
        }))
    );

    let setup = SetupPlan::from_keys(&keys, 100_000, 500).unwrap();
    println!(
        "{:<40} {:>12}",
        "SetupPlan::build_unsigned",
        fmt(mean(iters, || {
            let _ = setup
                .build_unsigned(
                    fake_outpoint(1),
                    setup.total_funded_sats() + 10_000,
                    keys.client_funding.p2wpkh.script_pubkey(),
                )
                .unwrap();
        }))
    );

    println!(
        "{:<40} {:>12}",
        "PaymentPlan::build_unsigned",
        fmt(mean(iters, || {
            let pay = PaymentPlan::from_session(&keys, &setup, 1, 1, 294, 400).unwrap();
            let _ = pay.build_unsigned(fake_outpoint(2), fake_outpoint(3)).unwrap();
        }))
    );

    println!(
        "{:<40} {:>12}",
        "Fig7Session::simulate_offline",
        fmt(mean(20, || {
            let s = Fig7Session::new(Fig7Params::default()).unwrap();
            let _ = s.simulate_offline().unwrap();
        }))
    );

    println!("\nCriterion: cargo bench --bench tx_bench");
}
