//! End-to-end demo of Vitārit (Figure 7) with a small cut-and-choose parameter.

use rand::thread_rng;
use vitarit::dvrf::Dvts;
use vitarit::vitarit::{Params, VitaritProtocol};

fn main() {
    let mut rng = thread_rng();
    let params = Params {
        t: 1,
        n: 3,
        deposit_value: 100_000,
        aux_value: 1,
        // Paper uses λ_s = 32 (2λ_s = 64). Use 8 here for a snappy demo.
        lambda_s: 8,
    };
    println!("Vitārit demo — t={}, n={}, λ_s={}", params.t, params.n, params.lambda_s);

    let proto = VitaritProtocol::new(params);
    let m = b"hello-vitarit";
    let (v, pi, public) = proto.run(m, &mut rng).expect("protocol run");

    assert!(Dvts::verify(
        &public.keys.vk,
        &public.keys.partial_vks,
        m,
        &v,
        &pi
    ));
    println!(
        "OK — reconstructed VRF ({} bytes), {} payments on ledger",
        v.to_bytes().len(),
        proto.ledger.payments().len()
    );
}
