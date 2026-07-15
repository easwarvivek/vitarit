//! Criterion benches for Bitcoin-layer operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vitarit_bitcoin::keys::SessionKeys;
use vitarit_bitcoin::ledger::SimulatedLedger;
use vitarit_bitcoin::network::BtcNetwork;
use vitarit_bitcoin::protocol::{Fig7Params, Fig7Session};
use vitarit_bitcoin::transactions::{fake_outpoint, AuxPlan, PaymentPlan, SetupPlan};
use bitcoin::{Amount, TxOut};

fn bench_keys_and_plans(c: &mut Criterion) {
    let mut g = c.benchmark_group("btc_keys_plans");
    g.bench_function("session_keys_t1_n3", |b| {
        b.iter(|| SessionKeys::generate(BtcNetwork::Regtest, 1, 3).unwrap())
    });
    let keys = SessionKeys::generate(BtcNetwork::Regtest, 1, 3).unwrap();
    g.bench_function("setup_plan", |b| {
        b.iter(|| SetupPlan::from_keys(black_box(&keys), 100_000, 500).unwrap())
    });
    let setup = SetupPlan::from_keys(&keys, 100_000, 500).unwrap();
    g.bench_function("build_setup_tx", |b| {
        b.iter(|| {
            setup
                .build_unsigned(
                    fake_outpoint(1),
                    setup.total_funded_sats() + 10_000,
                    keys.client_funding.p2wpkh.script_pubkey(),
                )
                .unwrap()
        })
    });
    g.bench_function("build_payment_tx", |b| {
        b.iter(|| {
            let pay = PaymentPlan::from_session(&keys, &setup, 1, 1, 294, 400).unwrap();
            pay.build_unsigned(fake_outpoint(2), fake_outpoint(3)).unwrap()
        })
    });
    g.finish();
}

fn bench_simulate(c: &mut Criterion) {
    let mut g = c.benchmark_group("btc_fig7_simulate");
    g.sample_size(30);
    g.bench_function("simulate_offline_t1_n3", |b| {
        b.iter(|| {
            let s = Fig7Session::new(Fig7Params::default()).unwrap();
            s.simulate_offline().unwrap()
        })
    });
    g.finish();
}

fn bench_ledger(c: &mut Criterion) {
    let mut g = c.benchmark_group("btc_ledger");
    let keys = SessionKeys::generate(BtcNetwork::Regtest, 1, 3).unwrap();
    let setup = SetupPlan::from_keys(&keys, 10_000, 200).unwrap();
    g.bench_function("apply_payment", |b| {
        b.iter_batched(
            || {
                let mut led = SimulatedLedger::new();
                let dep = fake_outpoint(10);
                let aux = fake_outpoint(11);
                led.credit(
                    dep,
                    TxOut {
                        value: Amount::from_sat(10_000),
                        script_pubkey: setup.deposits[0].script_pubkey.clone(),
                    },
                );
                led.credit(
                    aux,
                    TxOut {
                        value: Amount::from_sat(294),
                        script_pubkey: keys.server_aux[0].p2wpkh.script_pubkey(),
                    },
                );
                let pay = PaymentPlan::from_session(&keys, &setup, 1, 1, 294, 200).unwrap();
                let tx = pay.build_unsigned(dep, aux).unwrap();
                (led, tx)
            },
            |(mut led, tx)| {
                led.apply(&tx).unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });
    let _ = AuxPlan::from_keys(&keys, 1, 1);
    g.finish();
}

criterion_group!(benches, bench_keys_and_plans, bench_simulate, bench_ledger);
criterion_main!(benches);
