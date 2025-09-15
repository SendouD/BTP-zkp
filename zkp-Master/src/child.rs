use crate::master::MasterKey;
use crate::utils::hash_to_fr;
use ark_bn254::{Fr, G1Projective};
use ark_ec::Group;

pub struct ChildKeys {
    pub sk_child: Fr,
    pub pk_child: G1Projective,
}

/// Derive child secret and pubkey for a given master key and company identifier
pub fn derive_child(master: &MasterKey, label: &str, version: u64) -> ChildKeys {
    let t = hash_to_fr(label, version);

    let mut sk_child = master.sk;
    sk_child += &t; // sk_child = sk + t

    // pk_child = pk_master + g^{t}
    let g_t = G1Projective::generator() * t;
    let pk_child = master.pk + g_t;

    ChildKeys { sk_child, pk_child }
}
