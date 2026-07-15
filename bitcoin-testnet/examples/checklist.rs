use vitarit_bitcoin::checklist::full_report;
use vitarit_bitcoin::network::BtcNetwork;

fn main() {
    for net in [BtcNetwork::Regtest, BtcNetwork::Testnet, BtcNetwork::Signet] {
        let args: &[&str] = match net {
            BtcNetwork::Regtest => &["-regtest"],
            BtcNetwork::Testnet => &["-testnet"],
            BtcNetwork::Signet => &["-signet"],
            BtcNetwork::Bitcoin => &[],
        };
        let report = full_report(net, args);
        println!("=== {} ===", net.name());
        println!("{}", report.summary);
        for item in &report.items {
            println!(
                "[{:?}] {}{} — {}",
                item.status,
                item.id,
                if item.required { " (required)" } else { "" },
                item.detail
            );
        }
        println!();
    }
}
