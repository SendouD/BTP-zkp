
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use zkp_agg::*;
    fn main() {
        let mac = "F2:DC:55:DE:FB:A2";
        let companies = ["A", "B", "C"];
        let mut rng = StdRng::seed_from_u64(42);
    
        instantiate_truck(mac, &companies);
    
        let (sks, pks, _) = generate_keys(&companies, &mut rng);
    
        let h = hash_to_g1(mac);
        let sigmas = generate_zkps(&h, &sks, &companies);

        let sigma_agg = aggregate_proof(&sigmas);
        let pk_agg = aggregate_verification_keys(&pks);

        let _ = verify_zkp(&h, &sigma_agg, &pk_agg);
    }