//! Sweep VNE / Γ²ᵖᶜ cost vs cut-and-choose parameter λ_s (paper Figure 10).
//!
//!   cargo bench --bench lambda_s_sweep

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;
use vitarit::dvrf::Dvts;
use vitarit::nizk::NizkLPrime;
use vitarit::vne::{Instance, Vne};

const MSG: &[u8] = b"lambda-sweep";

fn bench_vne_lambda_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("vne_lambda_s_sweep");
    group.sample_size(15);

    let mut rng = thread_rng();
    let keys = Dvts::dkgen(1, 3, &mut rng).unwrap();
    let (wit, _) = Dvts::part_eval(&keys.partial_sks[0], MSG);
    let inst = Instance::new(1, keys.vk.clone(), keys.partial_vks.clone(), MSG);
    let z_aux = keys.partial_sks[0].clone();
    let (ek, dk) = Vne::kgen(&mut rng);
    let crs = NizkLPrime::setup();

    for lambda_s in [2usize, 4, 8, 16, 32] {
        let ct = Vne::enc(&ek, &inst, &wit, &z_aux, lambda_s, &crs, &mut rng).unwrap();

        group.bench_with_input(BenchmarkId::new("enc", lambda_s), &lambda_s, |b, &ls| {
            b.iter(|| {
                Vne::enc(
                    black_box(&ek),
                    black_box(&inst),
                    black_box(&wit),
                    black_box(&z_aux),
                    ls,
                    black_box(&crs),
                    &mut thread_rng(),
                )
                .unwrap()
            })
        });

        group.bench_with_input(BenchmarkId::new("vf_enc", lambda_s), &lambda_s, |b, _| {
            b.iter(|| {
                Vne::vf_enc(
                    black_box(&ek),
                    black_box(&inst),
                    black_box(&ct),
                    black_box(&crs),
                )
            })
        });

        group.bench_with_input(BenchmarkId::new("dec", lambda_s), &lambda_s, |b, _| {
            b.iter(|| Vne::dec(black_box(&dk), black_box(&inst), black_box(&ct)).unwrap())
        });
    }
    group.finish();
}

criterion_group!(benches, bench_vne_lambda_sweep);
criterion_main!(benches);
