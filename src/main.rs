use ark_bn254::{Bn254, Fr, G1Projective, G2Projective, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_ff::UniformRand;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};
use ark_std::ops::Mul;
use ark_ff::PrimeField;
// === Hash MAC address to scalar ===
fn hash_mac_to_scalar(mac: &str) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(mac.as_bytes());
    let hash = hasher.finalize();
    Fr::from_le_bytes_mod_order(&hash)
}

// === Hash MAC address to G1 (simulate for simplicity) ===
fn hash_to_g1(mac: &str) -> G1Projective {
    let scalar = hash_mac_to_scalar(mac);
    G1Projective::generator().mul(scalar)
}

// === Main ZKP Aggregation + Verification ===
fn main() {
    let mut rng = StdRng::seed_from_u64(42);

    // === Step 1: Simulate truck T1 and 3 sks (for A, B, C) ===
    let sk_a = Fr::rand(&mut rng);
    let sk_b = Fr::rand(&mut rng);
    let sk_c = Fr::rand(&mut rng);

    // let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    // === Step 2: Public keys pk = g^sk (in G2) ===
    let pk_a = g2.mul(sk_a).into_affine();
    let pk_b = g2.mul(sk_b).into_affine();
    let pk_c = g2.mul(sk_c).into_affine();

    // === Step 3: Aggregate pk ===
    let pk_agg = G2Affine::from(pk_a + pk_b + pk_c);

    // === Step 4: Hash identity to G1 ===
    let mac = "F2:DC:55:DE:FB:A2";
    let h = hash_to_g1(mac);
    let h_affine = G1Affine::from(h);

    // === Step 5: Compute per-company proofs σ = h^sk ===
    let sigma_a = h.mul(sk_a);
    let sigma_b = h.mul(sk_b);
    let sigma_c = h.mul(sk_c);

    // === Step 6: Aggregate proof ===
    let sigma = G1Affine::from(sigma_a + sigma_b + sigma_c);

    // === Step 7: Verify e(σ, g) == e(h, pk_agg) ===

    let lhs = Bn254::pairing(sigma, G2Affine::from(G2Projective::generator()));
    let rhs = Bn254::pairing(h_affine, pk_agg);             // e(h, pk_agg)

    println!("LHS (e(sigma, g)):  {:?}", lhs);
    println!("RHS (e(h, pk_agg)): {:?}", rhs);

    if lhs == rhs {
        println!("✅ Proof verified successfully!");
    } else {
        println!("❌ Proof verification failed!");
    }
}
