//! Criterion micro-benchmarks for each Vitārit crypto step (paper Table 1).
//!
//! Run:
//!   cargo bench --bench protocol_bench
//!   cargo bench --bench protocol_bench -- --warm-up-time 1 --measurement-time 3

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;
use vitarit::adaptor::AdaptorSig;
use vitarit::dvrf::Dvts;
use vitarit::nizk::{NizkLPrime, WitLPrime};
use vitarit::pkenc::PkEnc;
use vitarit::schnorr::Ds;
use vitarit::vne::{Instance, Vne};
use vitarit::vitarit::{Params, VitaritProtocol};

const MSG: &[u8] = b"benchmark-m-star";
const LAMBDA_S: usize = 8; // paper default 32; smaller keeps benches practical

fn bench_pkenc(c: &mut Criterion) {
    let mut group = c.benchmark_group("01_pkenc");
    let mut rng = thread_rng();
    let (ek, dk) = PkEnc::kgen(&mut rng);
    let msg = [7u8; 48];
    let (ct, _) = PkEnc::enc(&ek, &msg, &mut rng);

    group.bench_function("kgen", |b| {
        b.iter(|| PkEnc::kgen(&mut thread_rng()))
    });
    group.bench_function("enc", |b| {
        b.iter(|| PkEnc::enc(black_box(&ek), black_box(&msg), &mut thread_rng()))
    });
    group.bench_function("dec", |b| {
        b.iter(|| PkEnc::dec(black_box(&dk), black_box(&ct)).unwrap())
    });
    group.finish();
}

fn bench_dvrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("02_dvrf");
    let mut rng = thread_rng();
    let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
    let (v, pi) = Dvts::part_eval(&keys.partial_sks[0], MSG);
    let shares: Vec<_> = (1..=2)
        .map(|i| {
            let (vv, pp) = Dvts::part_eval(&keys.partial_sks[i - 1], MSG);
            (i, vv, pp)
        })
        .collect();
    let (full, proof) = Dvts::combine(&keys.vk, &keys.partial_vks, MSG, &shares).unwrap();

    group.bench_function("dkgen_t1_n3", |b| {
        b.iter(|| Dvts::dkgen(1, 3, &mut thread_rng()).unwrap())
    });
    group.bench_function("part_eval", |b| {
        b.iter(|| Dvts::part_eval(black_box(&keys.partial_sks[0]), black_box(MSG)))
    });
    group.bench_function("part_verify", |b| {
        b.iter(|| {
            Dvts::part_verify(
                1,
                black_box(&keys.vk),
                black_box(&keys.partial_vks),
                black_box(MSG),
                black_box(&v),
                black_box(&pi),
            )
        })
    });
    group.bench_function("combine_2", |b| {
        b.iter(|| {
            Dvts::combine(
                black_box(&keys.vk),
                black_box(&keys.partial_vks),
                black_box(MSG),
                black_box(&shares),
            )
            .unwrap()
        })
    });
    group.bench_function("verify", |b| {
        b.iter(|| {
            Dvts::verify(
                black_box(&keys.vk),
                black_box(&keys.partial_vks),
                black_box(MSG),
                black_box(&full),
                black_box(&proof),
            )
        })
    });
    group.finish();
}

fn bench_schnorr_adaptor(c: &mut Criterion) {
    let mut group = c.benchmark_group("03_schnorr_adaptor");
    let mut rng = thread_rng();
    let (sk, vk) = Ds::kgen(&mut rng);
    let msg = b"tx_pay_bytes";
    let sig = Ds::sign(&sk, msg);
    let (y, wit) = AdaptorSig::gen_statement(&mut rng);
    let pre = AdaptorSig::p_sign(&sk, msg, &y);
    let adapted = AdaptorSig::adapt(&vk, msg, &y, &pre, &wit).unwrap();

    group.bench_function("ds_sign", |b| {
        b.iter(|| Ds::sign(black_box(&sk), black_box(msg)))
    });
    group.bench_function("ds_vf", |b| {
        b.iter(|| Ds::vf(black_box(&vk), black_box(msg), black_box(&sig)))
    });
    group.bench_function("as_p_sign", |b| {
        b.iter(|| AdaptorSig::p_sign(black_box(&sk), black_box(msg), black_box(&y)))
    });
    group.bench_function("as_p_vf", |b| {
        b.iter(|| {
            AdaptorSig::p_vf(
                black_box(&vk),
                black_box(msg),
                black_box(&y),
                black_box(&pre),
            )
        })
    });
    group.bench_function("as_adapt", |b| {
        b.iter(|| {
            AdaptorSig::adapt(
                black_box(&vk),
                black_box(msg),
                black_box(&y),
                black_box(&pre),
                black_box(&wit),
            )
            .unwrap()
        })
    });
    group.bench_function("as_ext", |b| {
        b.iter(|| {
            AdaptorSig::ext(
                black_box(&vk),
                black_box(msg),
                black_box(&y),
                black_box(&pre),
                black_box(&adapted),
            )
            .unwrap()
        })
    });
    group.finish();
}

fn bench_nizk_lprime(c: &mut Criterion) {
    let mut group = c.benchmark_group("04_nizk_lprime");
    let mut rng = thread_rng();
    let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
    let (v_i, _) = Dvts::part_eval(&keys.partial_sks[0], MSG);
    let b = vitarit::group::bls::random_scalar(&mut rng);
    let a = vitarit::group::bls::g1_generator() * vitarit::group::bls::random_scalar(&mut rng);
    let b_pt = vitarit::group::bls::g1_generator() * b;
    let z = a * b + v_i.0;
    let stmt = NizkLPrime::make_stmt(1, a, b_pt, z, &keys.partial_vks[0], MSG);
    let wit = WitLPrime {
        b,
        sk_i: keys.partial_sks[0].0,
    };
    let crs = NizkLPrime::setup();
    let proof = NizkLPrime::prove(&crs, &stmt, &wit);

    group.bench_function("prove", |bch| {
        bch.iter(|| NizkLPrime::prove(black_box(&crs), black_box(&stmt), black_box(&wit)))
    });
    group.bench_function("verify", |bch| {
        bch.iter(|| {
            NizkLPrime::verify(black_box(&crs), black_box(&stmt), black_box(&proof))
        })
    });
    group.finish();
}

fn bench_vne(c: &mut Criterion) {
    let mut group = c.benchmark_group("05_vne");
    let mut rng = thread_rng();
    let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
    let (wit, _) = Dvts::part_eval(&keys.partial_sks[0], MSG);
    let inst = Instance::new(1, keys.vk.clone(), keys.partial_vks.clone(), MSG);
    let z_aux = keys.partial_sks[0].clone();
    let (ek, dk) = Vne::kgen(&mut rng);
    let crs = NizkLPrime::setup();
    let ct = Vne::enc(&ek, &inst, &wit, &z_aux, LAMBDA_S, &crs, &mut rng).unwrap();

    group.bench_function("kgen", |b| {
        b.iter(|| Vne::kgen(&mut thread_rng()))
    });
    group.bench_function(BenchmarkId::new("enc", format!("lambda_s={LAMBDA_S}")), |b| {
        b.iter(|| {
            Vne::enc(
                black_box(&ek),
                black_box(&inst),
                black_box(&wit),
                black_box(&z_aux),
                LAMBDA_S,
                black_box(&crs),
                &mut thread_rng(),
            )
            .unwrap()
        })
    });
    group.bench_function(BenchmarkId::new("vf_enc", format!("lambda_s={LAMBDA_S}")), |b| {
        b.iter(|| {
            Vne::vf_enc(
                black_box(&ek),
                black_box(&inst),
                black_box(&ct),
                black_box(&crs),
            )
        })
    });
    group.bench_function("dec", |b| {
        b.iter(|| Vne::dec(black_box(&dk), black_box(&inst), black_box(&ct)).unwrap())
    });
    group.finish();
}

fn bench_gamma2pc_and_protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("06_protocol");
    group.sample_size(20);

    group.bench_function(BenchmarkId::new("gamma2pc_run", format!("lambda_s={LAMBDA_S}")), |b| {
        b.iter_batched(
            || {
                let mut rng = thread_rng();
                let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
                let (v_i, pi_i) = Dvts::part_eval(&keys.partial_sks[0], MSG);
                let (sk_a, pk_a) = Ds::kgen(&mut rng);
                let (sk_s, pk_s) = Ds::kgen(&mut rng);
                let (sk_aux, pk_aux) = Ds::kgen(&mut rng);
                let ledger = vitarit::tx::Ledger::new();
                let deposit = vitarit::tx::Address::from_multisig(&pk_a, &pk_s);
                let aux = vitarit::tx::Address::from_vk(&pk_aux);
                let recv = vitarit::tx::Address::from_vk(&pk_s);
                ledger.credit(&deposit, 100_000);
                ledger.credit(&aux, 1);
                let funding = vitarit::tx::Address([0x11; 32]);
                ledger.credit(&funding, 100_000);
                let setup = vitarit::tx::make_setup_tx(&funding, 100_000, &[(deposit.clone(), 100_000)]);
                ledger.publish_setup(&setup).unwrap();
                let tx_pay = vitarit::tx::make_payment_tx(&deposit, 100_000, &aux, 1, &recv);
                let inst = Instance::new(1, keys.vk.clone(), keys.partial_vks.clone(), MSG);
                let cinp = vitarit::gamma2pc::CommonInput {
                    pk_a_j: pk_a,
                    inst,
                    tx_pay,
                };
                let client = vitarit::gamma2pc::ClientInput { sk_a_j: sk_a };
                let server = vitarit::gamma2pc::ServerInput {
                    sk_dvts_i: keys.partial_sks[0].clone(),
                    v_i,
                    pi_i,
                    sk_s_j: sk_s,
                    sk_aux_i: sk_aux,
                    server_index: 1,
                    deposit_index: 1,
                };
                (cinp, client, server, pk_s, pk_aux, ledger)
            },
            |(cinp, client, server, pk_s, pk_aux, ledger)| {
                let gamma = vitarit::gamma2pc::Gamma2pc::new(LAMBDA_S);
                gamma
                    .run(
                        &cinp,
                        &client,
                        &server,
                        &pk_s,
                        &pk_aux,
                        &ledger,
                        &mut thread_rng(),
                    )
                    .unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function(
        BenchmarkId::new("vitarit_fig7_end_to_end", format!("t=1,n=3,lambda_s={LAMBDA_S}")),
        |b| {
            b.iter(|| {
                let proto = VitaritProtocol::new(Params {
                    t: 1,
                    n: 3,
                    deposit_value: 50_000,
                    aux_value: 1,
                    lambda_s: LAMBDA_S,
                });
                proto.run(black_box(MSG), &mut thread_rng()).unwrap()
            })
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_pkenc,
    bench_dvrf,
    bench_schnorr_adaptor,
    bench_nizk_lprime,
    bench_vne,
    bench_gamma2pc_and_protocol,
);
criterion_main!(benches);
