use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main, Throughput};
use criterion::BatchSize::SmallInput;
use criterion::measurement::Measurement;
use miracl_core_bls12381::bls12381::{ecp2::ECP2, ecp::ECP, pair};
use miracl_core_bls12381::bls12381::ecp::G2_TABLE;
use miracl_core_bls12381::bls12381::fp4::FP4;
use crypto::scalar::rand_scalar_bls12381;
use crypto::rng::RAND_ChaCha20;

criterion_main!(benches);
criterion_group!(benches, bench_bls12381_ops);

fn bench_bls12381_ops(criterion: &mut Criterion) {
    let group_name = "crypto_bls_ops";
    let group = &mut criterion.benchmark_group(group_name);
    group.sample_size(20);

    bench_bls12381_ecp_add(group);
    bench_bls12381_ecp2_add(group);
    bench_bls12381_ecp_mul(group);
    bench_bls12381_ecp2_mul(group);
    bench_bls12381_pairing(group);
    bench_bls12381_pairing_with_precomp(group);
}

fn bench_bls12381_ecp_add<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    group.throughput(Throughput::Elements(1));

    group.bench_function("ecp_add", |bench| {
        bench.iter_batched(
            || {
                let g = ECP::generator();
                let rng = &mut RAND_ChaCha20::new([42; 32]);
                let e = rand_scalar_bls12381(rng);
                let pp = pair::g1mul(&g, &e);
                let f = rand_scalar_bls12381(rng);
                let qq = pair::g1mul(&g,&f);
                (pp, qq)
            },
            |(pp, qq)| {
                pp.clone().add(&qq);
            },
            SmallInput,
        )
    });
}

fn bench_bls12381_ecp2_add<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    group.throughput(Throughput::Elements(1)); // each iteration signs one message

    group.bench_function("ecp2_add", |bench| {
        bench.iter_batched(
            || {
                let g = ECP2::generator();
                let rng = &mut RAND_ChaCha20::new([42; 32]);
                let e = rand_scalar_bls12381(rng);
                let pp = pair::g2mul(&g, &e);
                let f = rand_scalar_bls12381(rng);
                let qq = pair::g2mul(&g,&f);
                (pp, qq)
            },
            |(pp, qq)| {
                pp.clone().add(&qq);
            },
            SmallInput,
        )
    });
}

fn bench_bls12381_ecp_mul<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    group.throughput(Throughput::Elements(1));

    group.bench_function("ecp_mul", |bench| {
        bench.iter_batched(
            || {
                let g = ECP::generator();
                let rng = &mut RAND_ChaCha20::new([42; 32]);
                let e = rand_scalar_bls12381(rng);
                let pp = pair::g1mul(&g, &e);
                let f = rand_scalar_bls12381(rng);
                (pp, f)
            },
            |(pp, f)| {
                pair::g1mul(&pp, &f);
            },
            SmallInput,
        )
    });
}

fn bench_bls12381_ecp2_mul<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    group.throughput(Throughput::Elements(1));

    group.bench_function("ecp2_mul", |bench| {
        bench.iter_batched(
            || {
                let g = ECP2::generator();
                let rng = &mut RAND_ChaCha20::new([42; 32]);
                let e = rand_scalar_bls12381(rng);
                let pp = pair::g2mul(&g, &e);
                let f = rand_scalar_bls12381(rng);
                (pp, f)
            },
            |(pp, f)| {
                pair::g2mul(&pp, &f);
            },
            SmallInput,
        )
    });
}

fn bench_bls12381_pairing<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    group.throughput(Throughput::Elements(1));

    group.bench_function("pairing", |bench| {
        bench.iter_batched(
            || {
                let g1 = ECP::generator();
                let g2 = ECP2::generator();
                let rng = &mut RAND_ChaCha20::new([42; 32]);
                let e = rand_scalar_bls12381(rng);
                let pp = pair::g1mul(&g1, &e);
                let f = rand_scalar_bls12381(rng);
                let qq = pair::g2mul(&g2,&f);
                (pp, qq)
            },
            |(pp, qq)| {
                pair::fexp(&pair::ate(&qq, &pp));
            },
            SmallInput,
        )
    });
}

fn bench_bls12381_pairing_with_precomp<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    group.throughput(Throughput::Elements(1));

    group.bench_function("pairing_precompute", |bench| {
        bench.iter_batched(
            || {
                let g1 = ECP::generator();
                let g2 = ECP2::generator();
                let rng = &mut RAND_ChaCha20::new([42; 32]);
                let e = rand_scalar_bls12381(rng);
                let pp = pair::g1mul(&g1, &e);
                let f = rand_scalar_bls12381(rng);
                let mut qq = pair::g2mul(&g2, &f);
                qq.affine();

                let mut qq_table = [FP4::new(); G2_TABLE];
                pair::precomp(&mut qq_table, &qq);

                let mut r = pair::initmp();
                pair::another_pc(&mut r, &qq_table[..], &pp);
                let x = pair::fexp(&pair::miller(&mut r));
                let y = pair::fexp(&pair::ate(&qq, &pp));
                assert!(x.equals(&y));

                (pp, qq_table)
            },
            |(pp, qq_table)| {
                let mut r = pair::initmp();
                pair::another_pc(&mut r, &qq_table[..], &pp);
                pair::fexp(&pair::miller(&mut r));
            },
            SmallInput,
        )
    });
}
