    use ark_bn254::{Bn254, Fr, G1Projective, G2Projective, G1Affine, G2Affine};
    use ark_ec::{pairing::Pairing, Group};
    use ark_ff::{UniformRand, PrimeField};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::ops::Mul;
    use sha2::{Digest, Sha256};
    use std::time::Instant;
    
    fn hash_mac_to_scalar(mac: &str) -> Fr {
        let mut hasher = Sha256::new();
        hasher.update(mac.as_bytes());
        let hash = hasher.finalize();
        Fr::from_le_bytes_mod_order(&hash)
    }
    
    fn hash_to_g1(mac: &str) -> G1Projective {
        let scalar = hash_mac_to_scalar(mac);
        G1Projective::generator().mul(scalar)
    }
    
    fn instantiate_truck(mac: &str, companies: &[&str]) {
        println!("\n1. Instantiation:");
        println!("=> Instantiate the autonomous truck with the \"MAC address\": {}", mac);
        for company in companies {
            println!("=> Instantiate the truck company {};", company);
        }
    }
    
    fn generate_keys(companies: &[&str], rng: &mut StdRng) -> (Vec<Fr>, Vec<G2Affine>, std::time::Duration) {
        println!("\n2. Key Generation:");
        let start = Instant::now();
        let mut sks = Vec::new();
        let mut pks = Vec::new();
    
        for company in companies {
            let sk = Fr::rand(rng);
            let pk = G2Affine::from(G2Projective::generator().mul(sk));
            println!("=> Generate key pair between the truck and company {} for the \"MAC address\";", company);
            sks.push(sk);
            pks.push(pk);
        }
    
        let duration = start.elapsed();
        println!("=> Average runtime for generating all prover keys: {:.6?}", duration);
        (sks, pks, duration)
    }
    
    fn generate_zkps(h: &G1Projective, sks: &[Fr], companies: &[&str]) -> (Vec<G1Projective>, std::time::Duration) {
        println!("\n3. ZKP Generation:");
        let start = Instant::now();
        let mut sigmas = Vec::new();
    
        for (i, sk) in sks.iter().enumerate() {
            let sigma = h.mul(*sk);
            println!("=> Generate ZKP based on the \"MAC address\" for company {};", companies[i]);
            sigmas.push(sigma);
        }
    
        let duration = start.elapsed();
        println!("=> Average runtime for generating individual ZKPs: {:.6?}", duration);
        (sigmas, duration)
    }
    
    fn aggregate_proof(sigmas: &[G1Projective]) -> (G1Affine, std::time::Duration) {
        println!("\n4. Proof Aggregation:");
        let start = Instant::now();
        let mut agg = G1Projective::from(sigmas[0]);
        for sigma in sigmas.iter().skip(1) {
            agg += sigma;
        }
        let result = G1Affine::from(agg);
        let duration = start.elapsed();
        println!("=> Aggregate the individual ZKPs into one ZKP;");
        println!("=> Average runtime for aggregating the ZKPs: {:.6?}", duration);
        (result, duration)
    }
    
    fn aggregate_verification_keys(pks: &[G2Affine]) -> (G2Affine, std::time::Duration) {
        println!("\n5. Verification Key Aggregation:");
        let start = Instant::now();
        let mut agg = G2Projective::from(pks[0]);
        for pk in pks.iter().skip(1) {
            agg += pk;
        }
        let result = G2Affine::from(agg);
        let duration = start.elapsed();
        println!("=> Generate and aggregate verification keys for the \"MAC address\";");
        println!("=> Average runtime for generating the verification keys: {:.6?}", duration);
        (result, duration)
    }
    
    fn verify_zkp(h: &G1Projective, sigma: &G1Affine, pk_agg: &G2Affine) -> std::time::Duration {
        println!("\n6. ZKP Verification:");
        let start = Instant::now();
        let h_affine = G1Affine::from(*h);
        let g2 = G2Affine::from(G2Projective::generator());
        let lhs = Bn254::pairing(*sigma, g2);
        let rhs = Bn254::pairing(h_affine, *pk_agg);
        let result = lhs == rhs;
        let duration = start.elapsed();
        println!("=> Verify the aggregated ZKP for the \"MAC address\" : {};", result);
        println!("=> Runtime for verifying the aggregated ZKP: {:.6?}", duration);
        duration
    }
    
    fn main() {
        let mac = "F2:DC:55:DE:FB:A2";
        let companies = ["A", "B", "C"];
        let mut rng = StdRng::seed_from_u64(42);
    
        instantiate_truck(mac, &companies);
    
        let (sks, pks, _) = generate_keys(&companies, &mut rng);
    
        let h = hash_to_g1(mac);
        let (sigmas, _) = generate_zkps(&h, &sks, &companies);
    
        let (sigma_agg, _) = aggregate_proof(&sigmas);
        let (pk_agg, _) = aggregate_verification_keys(&pks);
    
        let _ = verify_zkp(&h, &sigma_agg, &pk_agg);
    }
