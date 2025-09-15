    use ark_bn254::{Bn254, Fr, G1Projective, G2Projective, G1Affine, G2Affine};
    use ark_ec::{pairing::Pairing, Group};
    use ark_ff::{UniformRand, PrimeField};
    use ark_std::rand::{rngs::StdRng};
    use ark_std::ops::Mul;
    use sha2::{Digest, Sha256};
    use std::time::Instant;
    
    pub fn hash_mac_to_scalar(mac: &str) -> Fr {
        let mut hasher = Sha256::new();
        hasher.update(mac.as_bytes());
        let hash = hasher.finalize();
        Fr::from_le_bytes_mod_order(&hash)
    }
    
    pub fn hash_to_g1(mac: &str) -> G2Projective {
        let scalar = hash_mac_to_scalar(mac);
        G2Projective::generator().mul(scalar)
    }
    
    pub fn instantiate_truck(mac: &str, companies: &[&str]) {
        println!("\n1. Instantiation:");
        println!("=> Instantiate the autonomous truck with the \"MAC address\": {}", mac);
        for company in companies {
            println!("=> Instantiate the truck company {};", company);
        }
    }
    
    pub fn generate_keys(companies: &[&str], rng: &mut StdRng) -> (Vec<Fr>, Vec<G1Affine>, std::time::Duration) {
        println!("\n2. Key Generation:");
        let start = Instant::now();
        let mut sks = Vec::new();
        let mut pks = Vec::new();
    
        for company in companies {
            let sk = Fr::rand(rng);
            let pk = G1Affine::from(G1Projective::generator().mul(sk));
            println!("=> Generate key pair between the truck and company {} for the \"MAC address\";", company);
            sks.push(sk);
            pks.push(pk);
        }
    
        let duration = start.elapsed();
        println!("=> Average runtime for generating all prover keys: {:.6?}", duration);
        (sks, pks, duration)
    }

    pub fn generate_zkps(h: &G2Projective, sks: &[Fr], companies: &[&str]) -> Vec<G2Projective> {
        println!("\n3. ZKP Generation:");
        let mut sigmas = Vec::new();
    
        for (i, sk) in sks.iter().enumerate() {
            let sigma = h.mul(*sk);
            sigmas.push(sigma);
        }
    
        sigmas
    }


    pub fn aggregate_proof(sigmas: &[G2Projective]) -> G2Affine {
        println!("\n4. Proof Aggregation:");
        let mut agg = G2Projective::from(sigmas[0]);
        for sigma in sigmas.iter().skip(1) {
            agg += sigma;
        }
        let result = G2Affine::from(agg);
        println!("=> Aggregate the individual ZKPs into one ZKP;");
        result
    }
    
    pub fn aggregate_verification_keys(pks: &[G1Affine]) -> G1Affine {
        println!("\n5. Verification Key Aggregation:");
        let mut agg = G1Projective::from(pks[0]);
        for pk in pks.iter().skip(1) {
            agg += pk;
        }
        let result = G1Affine::from(agg);
        println!("=> Generate and aggregate verification keys for the \"MAC address\";");
        result
    }
    
    pub fn verify_zkp(h: &G2Projective, sigma: &G2Affine, pk_agg: &G1Affine) -> bool {
        println!("\n6. ZKP Verification:");
        let h_affine = G2Affine::from(*h);
        let g1 = G1Affine::from(G1Projective::generator());
        let lhs = Bn254::pairing(g1, *sigma);
        let rhs = Bn254::pairing(*pk_agg, h_affine);
        let result = lhs == rhs;
        println!("=> Verify the aggregated ZKP for the \"MAC address\" : {}", result);
        result
    }