use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main, Throughput};
use criterion::BatchSize::SmallInput;
use criterion::measurement::Measurement;
use miracl_core_ed25519::ed25519::ecp::ECP;
use crypto::rng::RAND_ChaCha20;
use crypto::scalar::rand_scalar_ed25519;

criterion_main!(benches);
criterion_group!(benches, bench_ed25519_ops);

fn bench_ed25519_ops(criterion: &mut Criterion) {
    let group_name = "crypto_bls_ops";
    let group = &mut criterion.benchmark_group(group_name);
    group.sample_size(20);

    bench_ed25519_ecp_add(group);
    bench_ed25519_ecp_mul(group);
}

fn bench_ed25519_ecp_add<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    group.throughput(Throughput::Elements(1));

    group.bench_function("ecp_add", |bench| {
        bench.iter_batched(
            || {
                let g = ECP::generator();
                let rng = &mut RAND_ChaCha20::new([42; 32]);
                let e = rand_scalar_ed25519(rng);
                let pp = g.mul(&e);
                let f = rand_scalar_ed25519(rng);
                let qq = g.mul(&f);
                (pp, qq)
            },
            |(pp, qq)| {
                pp.clone().add(&qq);
            },
            SmallInput,
        )
    });
}

fn bench_ed25519_ecp_mul<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    group.throughput(Throughput::Elements(1));

    group.bench_function("ecp_mul", |bench| {
        bench.iter_batched(
            || {
                let g = ECP::generator();
                let rng = &mut RAND_ChaCha20::new([42; 32]);
                let e = rand_scalar_ed25519(rng);
                let pp = g.mul(&e);
                let f = rand_scalar_ed25519(rng);
                (pp, f)
            },
            |(pp, f)| {
                pp.mul(&f);
            },
            SmallInput,
        )
    });
}
