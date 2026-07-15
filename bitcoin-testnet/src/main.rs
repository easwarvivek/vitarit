//! CLI for Vitārit Bitcoin tooling.

use std::env;
use vitarit_bitcoin::checklist::full_report;
use vitarit_bitcoin::network::BtcNetwork;
use vitarit_bitcoin::protocol::{Fig7Params, Fig7Session};

fn usage() {
    eprintln!(
        "Usage:
  vitarit-btc checklist [--network regtest|testnet|signet]
  vitarit-btc simulate  [--network regtest] [--t N] [--n N]
  vitarit-btc playbook  [--network regtest]

Examples:
  vitarit-btc checklist --network testnet
  vitarit-btc simulate --t 1 --n 3
"
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        std::process::exit(1);
    }
    let mut network = BtcNetwork::Regtest;
    let mut t = 1usize;
    let mut n = 3usize;
    let cmd = args[0].as_str();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--network" => {
                i += 1;
                network = BtcNetwork::parse(&args[i]).expect("network");
            }
            "--t" => {
                i += 1;
                t = args[i].parse().expect("t");
            }
            "--n" => {
                i += 1;
                n = args[i].parse().expect("n");
            }
            _ => {}
        }
        i += 1;
    }

    match cmd {
        "checklist" => {
            let report = full_report(network, &cli_flags(network));
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
            println!("\n{}", report.summary);
        }
        "simulate" => {
            let params = Fig7Params {
                network: network.name().into(),
                t,
                n,
                ..Fig7Params::default()
            };
            let session = Fig7Session::new(params).expect("session");
            let report = session.simulate_offline().expect("simulate");
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        "playbook" => {
            let params = Fig7Params {
                network: network.name().into(),
                t,
                n,
                ..Fig7Params::default()
            };
            let session = Fig7Session::new(params).expect("session");
            print!("{}", session.bitcoin_cli_playbook());
        }
        _ => {
            usage();
            std::process::exit(1);
        }
    }
}

fn cli_flags(network: BtcNetwork) -> Vec<&'static str> {
    match network {
        BtcNetwork::Regtest => vec!["-regtest"],
        BtcNetwork::Testnet => vec!["-testnet"],
        BtcNetwork::Signet => vec!["-signet"],
        BtcNetwork::Bitcoin => vec![],
    }
}
