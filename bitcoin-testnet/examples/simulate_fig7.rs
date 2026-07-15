use vitarit_bitcoin::protocol::{Fig7Params, Fig7Session};

fn main() {
    let session = Fig7Session::new(Fig7Params::default()).expect("session");
    let report = session.simulate_offline().expect("sim");
    println!("Vitārit Fig 7 Bitcoin simulation");
    println!("network={}", report.params.network);
    println!("deposits={}", report.deposit_addresses.len());
    println!("payments={}", report.payments.len());
    println!("aux_value_sats={} ({})", report.aux_value_used_sats, report.aux_note);
    for (i, addr) in report.deposit_addresses.iter().enumerate() {
        println!("  deposit[{}] {}  {}", i + 1, addr, report.deposit_descriptors[i]);
    }
    for p in &report.payments {
        println!(
            "  payment server={} deposit={} → {} ({} sats)",
            p.server_index, p.deposit_index, p.receive_address, p.payout_sats
        );
    }
    for n in &report.notes {
        println!("note: {n}");
    }
    println!("\n{}", session.bitcoin_cli_playbook());
}
