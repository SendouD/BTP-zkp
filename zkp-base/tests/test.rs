use ark_std::rand::SeedableRng;
use zkp_base::*; // re-use your crate’s public API
use std::{fs::OpenOptions, time::{Duration, Instant}};
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
fn protocol_timing() {
    let mac = "F2:DC:55:DE:FB:A2";
    let companies = ["A", "B", "C"];
    let revoked = "A"; // example: company A is revoked
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);

    // setup hash
    let h = hash_to_g1(mac);

    // key generation
    let (sks, pks) = generate_keys(&companies, &mut rng);

    // measure total protocol time
    let start = Instant::now();
    let mut all_verified = true;
    let mut total_verification_time = Duration::ZERO;

    for (i, company) in companies.iter().enumerate() {
        if *company == revoked {
            continue;
        }

        // proof generation
        let sigma = generate_zkp(&h, &sks[i], company);

        // timed verification
        let (verified, v_dur) = verify_zkp(&h, &sigma, &pks[i], company);

        assert!(verified, "Verification failed for {}", company);
        total_verification_time += v_dur;
        all_verified &= verified;
    }

    let total_duration = start.elapsed();
    log_time("zkp-base", total_duration);
    println!("\n== Protocol Timing Report ==");
    println!("Total protocol runtime (excl. setup): {:.6?}", total_duration);
    println!("Total verification time: {:.6?}", total_verification_time);
    println!("All verifications successful: {}", all_verified);
}
