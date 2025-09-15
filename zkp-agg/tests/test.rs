use ark_std::rand::Rng;
use zkp_agg::*; // assumes your crate is named zkp_base in Cargo.toml
use ark_std::rand::{rngs::StdRng, SeedableRng};
use std::path::PathBuf;
use std::time::Instant;
use std::fs::OpenOptions;
use std::io::Write;
fn log_time(crate_name: &str, duration: std::time::Duration) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // go up one level to the workspace root
    path.push("bench_results.csv");

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
fn protocol_timing_excluding_setup() {
    let mac = "F2:DC:55:DE:FB:A2";
    let n = 10; // number of companies
    let companies = generate_companies(n);
    let mut rng = StdRng::seed_from_u64(42);

    // ---- Setup (excluded from timing) ----
    let company_refs: Vec<&str> = companies.iter().map(|s| s.as_str()).collect();
    let (sks, pks, _) = generate_keys(&company_refs, &mut rng);
    let h = hash_to_g1(mac);

    // ---- Start timing here ----
    let start = Instant::now();

    // ZKP generation
    let sigmas= generate_zkps(&h, &sks, &company_refs);

    // Aggregation
    let sigma_agg= aggregate_proof(&sigmas);
    let pk_agg = aggregate_verification_keys(&pks);

    // Verification
    let verify_time = verify_zkp(&h, &sigma_agg, &pk_agg);

    let total_time = start.elapsed();
    log_time("zkp-agg", total_time);

    println!("\n== Protocol Timing Report (excl. key setup) ==");
    println!("Verification time: {:?}", verify_time);
    println!("Total protocol time (ZKP gen + aggregation + verification): {:?}", total_time);
}
