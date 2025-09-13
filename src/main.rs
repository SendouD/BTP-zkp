mod utils;
mod master;
mod child;
mod proof;
mod verify;

use ark_bn254::{Fr, G1Projective, G2Projective};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use std::time::Instant;

fn main() {
    // deterministic RNG for reproducible demo
    let mut rng = StdRng::seed_from_u64(42u64);

    let version: u64 = 1;

    // 1. Master key generation (for one company T)
    let t0 = Instant::now();
    let master = master::MasterKey::gen(&mut rng);
    println!("Master key generated in: {:?}", t0.elapsed());

    // 2. Derive child keys for a set of company identifiers S
    let labels = vec!["A", "B", "C"]; // example company ids
    let mut child_sks: Vec<Fr> = Vec::new();
    let mut child_pks: Vec<G1Projective> = Vec::new();

    for lab in &labels {
        let ck = child::derive_child(&master, lab, version);
        child_sks.push(ck.sk_child);
        child_pks.push(ck.pk_child);
    }
    let mac = "F2:DC:55:DE:FB:A2";
    // 3. Generate single proofs ΠT,λ = h^{sk_{T,λ}}
    let h=utils::hash_to_g1(mac);
    let mut proofs: Vec<G2Projective> = Vec::new();
    for sk in &child_sks {
        proofs.push(proof::single_proof(sk,&h));
    }

    // 4. Aggregate proofs by summing exponents and computing h^{sum}
    let agg_proof = proof::aggregate_proofs(&proofs);

    // 5. Aggregate public keys
    let agg_pk = verify::aggregate_pks(&child_pks);

    // 6. Verify pairing equation
    let ok = verify::verify(&h, &agg_proof, &agg_pk);

    println!("Verification result: {}", ok);
}
