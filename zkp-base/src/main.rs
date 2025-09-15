use zkp_base::*;
use ark_std::rand::{rngs::StdRng, SeedableRng};

fn main() {
    let mac = "F2:DC:55:DE:FB:A2";
    let all_companies = ["A", "B", "C"];
    let revoked = "A"; // pretend A is revoked
    let mut rng = StdRng::seed_from_u64(42);

    let h = hash_to_g1(mac);

    let (sks, pks) = generate_keys(&all_companies, &mut rng);

    println!("\n2. Proofs & Verification (excluding revoked company: {})", revoked);
let mut all_verified = true;
let mut total_verification_time = std::time::Duration::ZERO;

for (i, company) in all_companies.iter().enumerate() {
    if *company == revoked {
        continue; // skip revoked
    }
    let sigma = generate_zkp(&h, &sks[i], company);
    let (verified, duration) = verify_zkp(&h, &sigma, &pks[i], company);
    all_verified &= verified;
    total_verification_time += duration;
}

println!(
    "\n=> Final result: verification {} (total verification time: {:.6?})",
    if all_verified { "SUCCESSFUL" } else { "FAILED" },
    total_verification_time
);

}
