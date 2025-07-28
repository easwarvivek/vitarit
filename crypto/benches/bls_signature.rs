use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main, Throughput};
use criterion::BatchSize::SmallInput;
use criterion::measurement::Measurement;
use miracl_core_bls12381::bls12381::{
    big::BIG,
    ecp2::ECP2,
};
use rand::{Rng, thread_rng};
use crypto::bls_signature::{create_pop_sig, keypair_from_seed, sign_message, verify_message_signature, verify_pop_sig};
use crypto::key_pop_zk::{create_pop_zk_ecp2, PopZkInstanceEcp2, verify_pop_zk_ecp2};
use crypto::rng::RAND_ChaCha20;

criterion_main!(benches);
criterion_group!(benches, bench_bls_sig);

pub struct SigTestEnvironment {
    pub secret_key: BIG,
    pub public_key: ECP2,
}

impl SigTestEnvironment {
    pub fn new() -> Self {
        let seed = [42; 32];
        let (secret_key, public_key) = keypair_from_seed(&seed);
        Self {secret_key, public_key }
    }
}

fn bench_bls_sig(criterion: &mut Criterion) {
    let group_name = "crypto_bls_sig";
    let group = &mut criterion.benchmark_group(group_name);

    let env = SigTestEnvironment::new();

    bench_bls_sig_sign(group, &env);
    bench_bls_sig_verify(group, &env);
    bench_bls_create_pop_sig(group, &env);
    bench_bls_verify_pop_sig(group, &env);
    bench_bls_create_pop_zk(group, &env);
    bench_bls_verify_pop_zk(group, &env);
}

fn bench_bls_sig_sign<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &SigTestEnvironment,
) {
    group.throughput(Throughput::Elements(1)); // each iteration signs one message

    group.bench_function("sign", |bench| {
        bench.iter_batched(
            || {
                let mut rng = thread_rng();
                let message_len = rng.gen::<usize>() % 256;
                let message: Vec<_> = (0..message_len).map(|_| rng.gen::<u8>()).collect();
                (message, env.secret_key)
            },
            |(message, secret_key)| {
                sign_message(&message[..], &secret_key);
            },
            SmallInput,
        )
    });
}

fn bench_bls_sig_verify<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &SigTestEnvironment,
) {
    group.throughput(Throughput::Elements(1)); // each iteration verifies one signature share

    group.bench_function("verify_sig", |bench| {
        bench.iter_batched(
            || {
                let mut rng = thread_rng();
                let message_len = rng.gen::<usize>() % 256;
                let message: Vec<_> = (0..message_len).map(|_| rng.gen::<u8>()).collect();
                let sig = sign_message(&message[..], &env.secret_key);
                (message, sig, env.public_key.clone())
            },
            |(message, sig, public_key)| {
                assert!(verify_message_signature(&message, &sig, &public_key));
            },
            SmallInput,
        )
    });
}

fn bench_bls_create_pop_sig<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &SigTestEnvironment,
) {
    group.throughput(Throughput::Elements(1)); // each iteration signs one message

    group.bench_function("create_pop_sig", |bench| {
        bench.iter_batched(
            || {
                (env.public_key.clone(), env.secret_key)
            },
            |(public_key, secret_key)| {
                create_pop_sig(&public_key, &secret_key);
            },
            SmallInput,
        )
    });
}

fn bench_bls_verify_pop_sig<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &SigTestEnvironment,
) {
    group.throughput(Throughput::Elements(1)); // each iteration verifies one signature share

    group.bench_function("verify_pop_sig", |bench| {
        bench.iter_batched(
            || {
                let pop = create_pop_sig(&env.public_key, &env.secret_key);
                (pop, env.public_key.clone())
            },
            |(pop, public_key)| {
                assert!(verify_pop_sig(&pop, &public_key));
            },
            SmallInput,
        )
    });
}

fn bench_bls_create_pop_zk<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &SigTestEnvironment,
) {
    group.throughput(Throughput::Elements(1)); // each iteration signs one message

    group.bench_function("create_pop_zk", |bench| {
        bench.iter_batched(
            || {
                let mut rng = thread_rng();
                let associated_data: Vec<_> = (0..10).map(|_| rng.gen::<u8>()).collect();

                let instance = PopZkInstanceEcp2 {
                    gen: ECP2::generator(),
                    public_key: env.public_key.clone(),
                    associated_data,
                };

                (instance, env.secret_key)
            },
            |(instance, secret_key)| {
                let rng = &mut RAND_ChaCha20::new([74; 32]);
                let _ = create_pop_zk_ecp2(&instance, &secret_key, rng);
            },
            SmallInput,
        )
    });
}

fn bench_bls_verify_pop_zk<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &SigTestEnvironment,
) {
    group.throughput(Throughput::Elements(1)); // each iteration verifies one signature share

    group.bench_function("verify_pop_zk", |bench| {
        bench.iter_batched(
            || {
                let mut rng = thread_rng();
                let associated_data: Vec<_> = (0..10).map(|_| rng.gen::<u8>()).collect();

                let instance = PopZkInstanceEcp2 {
                    gen: ECP2::generator(),
                    public_key: env.public_key.clone(),
                    associated_data,
                };

                let pop = create_pop_zk_ecp2(
                    &instance,
                    &env.secret_key,
                    &mut RAND_ChaCha20::new([74; 32]));

                (instance, pop.unwrap())
            },
            |(instance, pop)| {
                assert!(verify_pop_zk_ecp2(&instance, &pop).is_ok());
            },
            SmallInput,
        )
    });
}
