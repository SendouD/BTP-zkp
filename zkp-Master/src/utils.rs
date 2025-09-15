use ark_bn254::{Fr, G1Projective};
use sha2::{Digest, Sha256};
use ark_ff::PrimeField;
use ark_ec::Group;
use ark_std::ops::Mul;

/// Hash a label + version into a field element
pub fn hash_to_fr(label: &str, version: u64) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(&version.to_le_bytes());
    let digest = hasher.finalize();
    Fr::from_le_bytes_mod_order(&digest)
}
fn hash_mac_to_scalar(mac: &str) -> Fr {
        let mut hasher = Sha256::new();
        hasher.update(mac.as_bytes());
        let hash = hasher.finalize();
        Fr::from_le_bytes_mod_order(&hash)
}
   
pub fn hash_to_g1(mac: &str) -> G1Projective {
        let scalar = hash_mac_to_scalar(mac);
        G1Projective::generator().mul(scalar)
    }