use zkp_agg::*; // assumes your crate is named zkp_base in Cargo.toml
use ark_std::rand::{rngs::StdRng, SeedableRng};
use std::time::Instant;
use std::fs::OpenOptions;
use std::io::Write;
fn log_time(crate_name: &str, duration: std::time::Duration) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("bench_results.csv")
        .unwrap();

    writeln!(file, "{},{}", crate_name, duration.as_millis()).unwrap();
}
#[test]
fn protocol_timing_excluding_setup() {
    let mac = "F2:DC:55:DE:FB:A2";
    let companies = ["A", "B", "C"];
    let mut rng = StdRng::seed_from_u64(42);

    // ---- Setup (excluded from timing) ----
    let (sks, pks, _) = generate_keys(&companies, &mut rng);
    let h = hash_to_g1(mac);

    // ---- Start timing here ----
    let start = Instant::now();

    // ZKP generation
    let sigmas= generate_zkps(&h, &sks, &companies);

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
