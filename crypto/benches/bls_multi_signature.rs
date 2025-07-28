use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main, Throughput};
use criterion::BatchSize::SmallInput;
use criterion::measurement::Measurement;
use miracl_core_bls12381::bls12381::{
    big::BIG,
    ecp2::ECP2,
};
use rand::{Rng, thread_rng};
use crypto::bls_signature::{
    combine_signatures, keypair_from_seed, sign_message, verify_combined_message_signature,
};

criterion_main!(benches);
criterion_group!(benches, bench_multi_sig);

pub struct MultiSigTestEnvironment {
    pub num_of_nodes: usize,
    pub secret_keys: Vec<BIG>,
    pub public_keys: Vec<ECP2>,
}

impl MultiSigTestEnvironment {
    /// Creates a new test environment with the given number of nodes.
    pub fn new(num_of_nodes: usize) -> Self {
        let mut secret_keys = vec![BIG::new(); num_of_nodes];
        let mut public_keys = vec![ECP2::new(); num_of_nodes];

        for i in 0..num_of_nodes {
            let seed_value = (42 + i) as u8;
            let seed = [seed_value; 32];
            let (sk, pk) = keypair_from_seed(&seed);
            secret_keys[i] = sk;
            public_keys[i] = pk;
        }

        let env = Self { num_of_nodes, secret_keys, public_keys };
        env
    }
}

fn bench_multi_sig(criterion: &mut Criterion) {
    let signer_counts = vec![10, 50, 100];

    for num_of_signers in signer_counts {
        bench_multi_sig_n_signers(criterion, num_of_signers);
    }
}

fn bench_multi_sig_n_signers(criterion: &mut Criterion, num_of_signers: usize) {
    let group_name = format!("crypto_multi_sig_{}_signers", num_of_signers);
    let group = &mut criterion.benchmark_group(group_name);

    let env = MultiSigTestEnvironment::new(num_of_signers);

    assert!(num_of_signers > 2);
    bench_multi_sig_combine(group, &env);
    bench_multi_sig_verify_combined(group, &env);
}

fn bench_multi_sig_combine<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &MultiSigTestEnvironment,
) {
    group.throughput(Throughput::Elements((env.num_of_nodes-1) as u64)); // each iteration combines num_of_signers-1 signature shares

    group.bench_function("combine_multi_sig_individuals", |bench| {
        bench.iter_batched(
            || {
                let mut rng = thread_rng();
                let combiner_id = rng.gen::<usize>() % env.num_of_nodes;
                let message_len = rng.gen::<usize>() % 256;
                let message: Vec<_> = (0..message_len).map(|_| rng.gen::<u8>()).collect();
                let sigs: Vec<_> = (0..env.num_of_nodes)
                    .filter(|&signer_id| {
                        signer_id != combiner_id
                    })
                    .map(|signer_id| {
                        let sig = sign_message(&message[..], &env.secret_keys[signer_id]);
                        sig
                    })
                    .collect();
                assert_eq!(sigs.len(), env.num_of_nodes - 1);
                sigs
            },
            |signatures| {
                combine_signatures(&signatures[..]);
            },
            SmallInput,
        )
    });
}

fn bench_multi_sig_verify_combined<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &MultiSigTestEnvironment,
) {
    group.throughput(Throughput::Elements(1)); // each iteration verifies one combined signature

    group.bench_function("verify_multi_sig_combined", |bench| {
        bench.iter_batched(
            || {
                let mut rng = thread_rng();
                let combiner_id = rng.gen::<usize>() % env.num_of_nodes;
                let verifier_id = rng.gen::<usize>() % env.num_of_nodes;
                let message_len = rng.gen::<usize>() % 256;
                let message: Vec<_> = (0..message_len).map(|_| rng.gen::<u8>()).collect();
                let sigs: Vec<_> = (0..env.num_of_nodes)
                    .filter(|&signer_id| {
                        signer_id != combiner_id && signer_id != verifier_id
                    })
                    .map(|signer_id| {
                        sign_message(&message[..], &env.secret_keys[signer_id])
                    })
                    .collect();
                assert!((sigs.len() == env.num_of_nodes - 2)
                    || (sigs.len() == env.num_of_nodes - 1 && combiner_id == verifier_id));
                let combined_sig = combine_signatures(&sigs[..]);
                let public_keys: Vec<_> = (0..env.num_of_nodes)
                    .filter(|&signer_id| {
                        signer_id != combiner_id && signer_id != verifier_id
                    })
                    .map(|signer_id| {
                        env.public_keys[signer_id].clone()
                    })
                    .collect();

                (message, combined_sig, public_keys)
            },
            |(message, combined_sig, public_keys)| {
                assert!(verify_combined_message_signature(&message[..], &combined_sig, &public_keys[..]));
            },
            SmallInput,
        )
    });
}
