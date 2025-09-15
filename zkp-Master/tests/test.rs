use ark_std::rand::{rngs::StdRng, SeedableRng};
use rand::Rng;
use zk_master::{utils, master, child, proof, verify};
use std::{fs::OpenOptions, time::Instant};
use std::io::Write;

fn setup() -> (master::MasterKey, String) {
    let mut rng = StdRng::seed_from_u64(42u64);
    let ta = master::MasterKey::gen(&mut rng);
    let mac = "F2:DC:55:DE:FB:A2".to_string();
    (ta, mac)
}
fn log_time(crate_name: &str, duration: std::time::Duration) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("../bench_results.csv")
        .unwrap();

    writeln!(file, "{},{}", crate_name, duration.as_millis()).unwrap();
}
fn generate_companies(n: usize) -> Vec<String> {
    let mut rng = StdRng::seed_from_u64(42); // local RNG
    (0..n)
        .map(|i| {
            // random letter A–Z
            let c = (b'A' + (rng.gen_range(0..26) as u8)) as char;
            format!("{}{}", c, i) // ensures uniqueness
        })
        .collect()
}
#[test]
fn test_process_time_excl_master() {
    let (ta, mac) = setup();
    let version: u64 = 1;
    let n = 10; // number of companies
    let labels = generate_companies(n);

    // start measuring after master is ready

    let start = Instant::now();
    // --- Child key derivation ---
    let mut child_sks = Vec::new();
    let mut child_pks = Vec::new();
    for lab in &labels {
        let ck = child::derive_child(&ta, lab, version);
        child_sks.push(ck.sk_child);
        child_pks.push(ck.pk_child);
    }

    // --- Proof generation ---
    let h: ark_bn254::G1Projective = utils::hash_to_g1(&mac);
    let mut proofs: Vec<ark_bn254::G1Projective> = Vec::new();
    for sk in &child_sks {
        proofs.push(proof::single_proof(sk, &h));
    }
    
    // --- Aggregation ---
    let agg_proof = proof::aggregate_proofs(&proofs);
    let agg_pk = verify::aggregate_pks(&child_pks);

    // --- Verification ---
    let result = verify::verify(&h, &agg_proof, &agg_pk);

    let duration = start.elapsed();
    log_time("zkp-master", duration);

    println!("\n== Process Timing Report ==");
    println!("Labels: {:?}", labels);
    println!("Verification result: {}", result);
    println!("Total time (child keygen + proof gen + aggregation + verification): {:?}", duration);

    assert!(result);
}
