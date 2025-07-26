use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::Group;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use std::collections::HashMap;
// === Types ===
type TruckId = String;
type CompanyId = String;

#[derive(Debug, Clone)]
struct KeyPair {
    sk: Fr,
    pk: G1Affine,
}

#[derive(Debug)]
struct CertificateAuthority {
    // Mapping from (truck_id, company_id) -> KeyPair
    keys: HashMap<(TruckId, CompanyId), KeyPair>,
    rng: StdRng,
}

impl CertificateAuthority {
    fn new(seed: u64) -> Self {
        Self {
            keys: HashMap::new(),
            rng: StdRng::seed_from_u64(seed),
        }
    }

    fn register_truck_for_company(&mut self, truck_id: &str, company_id: &str) {
        // Generate random secret key sk
        let sk = Fr::rand(&mut self.rng);
        // Generator
        let g = G1Projective::generator();
        // Public key: pk = g^sk
        let pk = G1Affine::from(g.mul(sk));

        // Store keypair
        self.keys.insert(
            (truck_id.to_string(), company_id.to_string()),
            KeyPair { sk, pk },
        );
    }

    fn print_keys(&self) {
        for ((truck_id, company_id), keypair) in &self.keys {
            println!(
                "Truck [{}] - Company [{}] → sk: {:?}, pk: {:?}",
                truck_id, company_id, keypair.sk, keypair.pk
            );
        }
    }
}

// === Main Demo ===
fn main() {
    // Define trucks and companies
    let trucks = vec!["T1", "T2", "T3", "T4", "T5"];
    let companies = vec!["A", "B", "C"];

    // Create a certificate authority
    let mut ca = CertificateAuthority::new(42);

    // Register each truck under each company
    for truck in &trucks {
        for company in &companies {
            ca.register_truck_for_company(truck, company);
        }
    }

    // Output the keys
    ca.print_keys();
}
