use ark_bn254::{Bn254, Fr, G1Projective, G2Projective, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, Group};
use ark_ff::{UniformRand, PrimeField};
use ark_std::rand::{rngs::StdRng };
use ark_std::ops::Mul;
use sha2::{Digest, Sha256};
use std::time::Instant;

pub fn hash_mac_to_scalar(mac: &str) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(mac.as_bytes());
    let hash = hasher.finalize();
    Fr::from_le_bytes_mod_order(&hash)
}

pub fn hash_to_g1(mac: &str) -> G1Projective {
    let scalar = hash_mac_to_scalar(mac);
    G1Projective::generator().mul(scalar)
}

pub fn generate_keys(companies: &[&str], rng: &mut StdRng) -> (Vec<Fr>, Vec<G2Affine>) {
    println!("\n1. Key Generation:");
    let mut sks = Vec::new();
    let mut pks = Vec::new();

    for company in companies {
        let sk = Fr::rand(rng);
        let pk = G2Affine::from(G2Projective::generator().mul(sk));
        println!("=> Key pair for company {} generated.", company);
        sks.push(sk);
        pks.push(pk);
    }
    (sks, pks)
}

pub fn generate_zkp(h: &G1Projective, sk: &Fr, company: &str) -> G1Affine {
    println!("=> Generating ZKP for company {}...", company);
    let sigma = h.mul(*sk);
    G1Affine::from(sigma)
}

pub fn verify_zkp(h: &G1Projective, sigma: &G1Affine, pk: &G2Affine, company: &str) -> (bool, std::time::Duration) {
    println!("=> Verifying ZKP for company {}...", company);
    let start = Instant::now();

    let h_affine = G1Affine::from(*h);
    let g2 = G2Affine::from(G2Projective::generator());
    let lhs = Bn254::pairing( *sigma,g2);
    let rhs = Bn254::pairing(h_affine, *pk);
    let result = lhs == rhs;

    let duration = start.elapsed();
    println!("   Verification result for {}: {} (took {:.6?})", company, result, duration);
    (result, duration)
}
