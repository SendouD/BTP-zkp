use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, Group};
use ark_ff::Zero;

/// Aggregate public keys: sum of child public keys
pub fn aggregate_pks(pks: &[G1Projective]) -> G1Projective {
    let mut acc = G1Projective::zero();
    for pk in pks {
        acc += pk;
    }
    acc
}

/// Verify pairing: e(g, Πagg) == e(pkagg, h)
pub fn verify(h:&G2Projective,agg_proof: &G2Projective, agg_pk: &G1Projective) -> bool {
    let a_proof = G2Affine::from(*agg_proof);
    let a_g = G1Affine::from(G1Projective::generator());
    let a_h = G2Affine::from(*h);
    let a_pk = G1Affine::from(*agg_pk);

    let left = Bn254::pairing(&a_g, &a_proof);
    let right = Bn254::pairing(&a_pk, &a_h);

    left == right
}
