use ark_bn254::{Fr, G1Projective};
use ark_ec::Group;
use ark_ff::UniformRand;
use ark_std::rand::rngs::StdRng;

pub struct MasterKey {
    pub sk: Fr,
    pub pk: G1Projective,
}

impl MasterKey {
    pub fn gen(rng: &mut StdRng) -> Self {
        let sk = Fr::rand(rng);
        let pk = G1Projective::generator() * sk;
        MasterKey { sk, pk }
    }
}
