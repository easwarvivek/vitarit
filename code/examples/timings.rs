//! Quick wall-clock timings for each protocol step (paper Table 1 style).
//!
//! ```bash
//! cargo run --release --example timings
//! cargo run --release --example timings -- --lambda-s 32 --iters 50
//! ```

use std::env;
use std::time::{Duration, Instant};

use rand::thread_rng;
use vitarit::adaptor::AdaptorSig;
use vitarit::dvrf::Dvts;
use vitarit::gamma2pc::{ClientInput, CommonInput, Gamma2pc, ServerInput};
use vitarit::nizk::{NizkLPrime, WitLPrime};
use vitarit::pkenc::PkEnc;
use vitarit::schnorr::Ds;
use vitarit::tx::{self, Address, Ledger};
use vitarit::vne::{Instance, Vne};
use vitarit::vitarit::{Params, VitaritProtocol};

const MSG: &[u8] = b"timing-benchmark";

fn mean_duration(iters: u32, mut f: impl FnMut()) -> Duration {
    for _ in 0..3 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed() / iters
}

fn fmt_dur(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns >= 1_000_000_000 {
        format!("{:.3} s", d.as_secs_f64())
    } else if ns >= 1_000_000 {
        format!("{:.3} ms", d.as_secs_f64() * 1e3)
    } else if ns >= 1_000 {
        format!("{:.1} µs", d.as_secs_f64() * 1e6)
    } else {
        format!("{ns} ns")
    }
}

fn print_row(party: &str, step: &str, d: Duration) {
    println!("{:<8} {:<44} {:>12}", party, step, fmt_dur(d));
}

fn main() {
    let mut lambda_s: usize = 8;
    let mut iters: u32 = 30;
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--lambda-s" => lambda_s = args.next().unwrap().parse().expect("lambda-s"),
            "--iters" => iters = args.next().unwrap().parse().expect("iters"),
            "-h" | "--help" => {
                eprintln!("Usage: timings [--lambda-s N] [--iters N]");
                return;
            }
            other => panic!("unknown arg {other}"),
        }
    }

    let release = !cfg!(debug_assertions);
    println!(
        "Vitārit micro-timings  (λ_s={lambda_s}, iters={iters}, --release={release})"
    );
    if !release {
        println!("WARNING: debug build — timings are not meaningful; use --release\n");
    }
    println!("{:<8} {:<44} {:>12}", "Party", "Step", "Mean");
    println!("{}", "-".repeat(68));

    let mut rng = thread_rng();

    // PKEnc
    let (ek, dk) = PkEnc::kgen(&mut rng);
    let msg48 = [7u8; 48];
    let (ct, _) = PkEnc::enc(&ek, &msg48, &mut rng);
    print_row("—", "PKEnc.KGen", mean_duration(iters, || {
        let _ = PkEnc::kgen(&mut thread_rng());
    }));
    print_row("Server", "PKEnc.Enc", mean_duration(iters, || {
        let _ = PkEnc::enc(&ek, &msg48, &mut thread_rng());
    }));
    print_row("Client", "PKEnc.Dec", mean_duration(iters, || {
        let _ = PkEnc::dec(&dk, &ct).unwrap();
    }));

    // DVRF
    let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
    let (v, pi) = Dvts::part_eval(&keys.partial_sks[0], MSG);
    let shares: Vec<_> = (1..=2)
        .map(|i| {
            let (vv, pp) = Dvts::part_eval(&keys.partial_sks[i - 1], MSG);
            (i, vv, pp)
        })
        .collect();
    let (full, proof) = Dvts::combine(&keys.vk, &keys.partial_vks, MSG, &shares).unwrap();

    print_row("Setup", "DVRF.DKgen(t=1,n=3)", mean_duration(iters.max(10), || {
        let _ = Dvts::dkgen(1, 3, &mut thread_rng()).unwrap();
    }));
    print_row("Server", "DVRF.PartEval", mean_duration(iters, || {
        let _ = Dvts::part_eval(&keys.partial_sks[0], MSG);
    }));
    print_row("—", "DVRF.PartVerify", mean_duration(iters, || {
        assert!(Dvts::part_verify(1, &keys.vk, &keys.partial_vks, MSG, &v, &pi));
    }));
    print_row("Client", "DVRF.Combine", mean_duration(iters, || {
        let _ = Dvts::combine(&keys.vk, &keys.partial_vks, MSG, &shares).unwrap();
    }));
    print_row("Client", "DVRF.Verify", mean_duration(iters, || {
        assert!(Dvts::verify(&keys.vk, &keys.partial_vks, MSG, &full, &proof));
    }));

    // Schnorr / Adaptor
    let (sk, vk) = Ds::kgen(&mut rng);
    let tx_msg = b"payment-tx-bytes";
    let (y, wit) = AdaptorSig::gen_statement(&mut rng);
    let pre = AdaptorSig::p_sign(&sk, tx_msg, &y);
    let adapted = AdaptorSig::adapt(&vk, tx_msg, &y, &pre, &wit).unwrap();

    print_row("Server", "DS.Sign", mean_duration(iters, || {
        let _ = Ds::sign(&sk, tx_msg);
    }));
    print_row("Client", "AS.pSign (pre-signature)", mean_duration(iters, || {
        let _ = AdaptorSig::p_sign(&sk, tx_msg, &y);
    }));
    print_row("Server", "AS.pVf", mean_duration(iters, || {
        assert!(AdaptorSig::p_vf(&vk, tx_msg, &y, &pre));
    }));
    print_row("Server", "AS.Adapt", mean_duration(iters, || {
        let _ = AdaptorSig::adapt(&vk, tx_msg, &y, &pre, &wit).unwrap();
    }));
    print_row("Client", "AS.Ext", mean_duration(iters, || {
        let _ = AdaptorSig::ext(&vk, tx_msg, &y, &pre, &adapted).unwrap();
    }));

    // L′
    let bsc = vitarit::group::bls::random_scalar(&mut rng);
    let a = vitarit::group::bls::g1_generator() * vitarit::group::bls::random_scalar(&mut rng);
    let b_pt = vitarit::group::bls::g1_generator() * bsc;
    let z = a * bsc + v.0;
    let stmt = NizkLPrime::make_stmt(1, a, b_pt, z, &keys.partial_vks[0], MSG);
    let wit_j = WitLPrime {
        b: bsc,
        sk_i: keys.partial_sks[0].0,
    };
    let crs = NizkLPrime::setup();
    let proof_l = NizkLPrime::prove(&crs, &stmt, &wit_j);

    print_row("Server", "NIZK L′ Prove (per unopened)", mean_duration(iters, || {
        let _ = NizkLPrime::prove(&crs, &stmt, &wit_j);
    }));
    print_row("Client", "NIZK L′ Verify (per unopened)", mean_duration(iters, || {
        assert!(NizkLPrime::verify(&crs, &stmt, &proof_l));
    }));

    // VNE
    let inst = Instance::new(1, keys.vk.clone(), keys.partial_vks.clone(), MSG);
    let z_aux = keys.partial_sks[0].clone();
    let (vek, vdk) = Vne::kgen(&mut rng);
    let vct = Vne::enc(&vek, &inst, &v, &z_aux, lambda_s, &crs, &mut rng).unwrap();
    let vne_iters = iters.max(10).min(40);

    print_row(
        "Server",
        &format!("VNE.Enc (λ_s={lambda_s})"),
        mean_duration(vne_iters, || {
            let _ = Vne::enc(&vek, &inst, &v, &z_aux, lambda_s, &crs, &mut thread_rng()).unwrap();
        }),
    );
    print_row(
        "Client",
        &format!("VNE.VfEnc (λ_s={lambda_s})"),
        mean_duration(vne_iters, || {
            assert!(Vne::vf_enc(&vek, &inst, &vct, &crs));
        }),
    );
    print_row("Client", "VNE.Dec", mean_duration(iters, || {
        let _ = Vne::dec(&vdk, &inst, &vct).unwrap();
    }));

    // Γ²ᵖᶜ
    let gamma_iters = iters.max(5).min(20);
    print_row(
        "Both",
        &format!("Γ²ᵖᶜ.run (λ_s={lambda_s})"),
        mean_duration(gamma_iters, || {
            let mut rng = thread_rng();
            let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
            let (v_i, pi_i) = Dvts::part_eval(&keys.partial_sks[0], MSG);
            let (sk_a, pk_a) = Ds::kgen(&mut rng);
            let (sk_s, pk_s) = Ds::kgen(&mut rng);
            let (sk_aux, pk_aux) = Ds::kgen(&mut rng);
            let ledger = Ledger::new();
            let deposit = Address::from_multisig(&pk_a, &pk_s);
            let aux = Address::from_vk(&pk_aux);
            let recv = Address::from_vk(&pk_s);
            ledger.credit(&deposit, 100_000);
            ledger.credit(&aux, 1);
            let funding = Address([0x22; 32]);
            ledger.credit(&funding, 100_000);
            let setup = tx::make_setup_tx(&funding, 100_000, &[(deposit.clone(), 100_000)]);
            ledger.publish_setup(&setup).unwrap();
            let tx_pay = tx::make_payment_tx(&deposit, 100_000, &aux, 1, &recv);
            let inst = Instance::new(1, keys.vk.clone(), keys.partial_vks.clone(), MSG);
            let cinp = CommonInput {
                pk_a_j: pk_a,
                inst,
                tx_pay,
            };
            let client = ClientInput { sk_a_j: sk_a };
            let server = ServerInput {
                sk_dvts_i: keys.partial_sks[0].clone(),
                v_i,
                pi_i,
                sk_s_j: sk_s,
                sk_aux_i: sk_aux,
                server_index: 1,
                deposit_index: 1,
            };
            Gamma2pc::new(lambda_s)
                .run(&cinp, &client, &server, &pk_s, &pk_aux, &ledger, &mut rng)
                .unwrap();
        }),
    );

    let full_iters = iters.max(3).min(10);
    print_row(
        "Both",
        &format!("Fig7 end-to-end (t=1,n=3,λ_s={lambda_s})"),
        mean_duration(full_iters, || {
            VitaritProtocol::new(Params {
                t: 1,
                n: 3,
                deposit_value: 50_000,
                aux_value: 1,
                lambda_s,
            })
            .run(MSG, &mut thread_rng())
            .unwrap();
        }),
    );

    println!();
    println!("Criterion benches (HTML under target/criterion/):");
    println!("  cargo bench --bench protocol_bench");
    println!("  cargo bench --bench lambda_s_sweep");
}
