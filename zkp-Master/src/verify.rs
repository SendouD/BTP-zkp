use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, Group};
use ark_ff::Zero;

/// Aggregate public keys: sum of child public keys
pub fn aggregate_pks(pks: &[G2Projective]) -> G2Projective {
    let mut acc = G2Projective::zero();
    for pk in pks {
        acc += pk;
    }
    acc
}

/// Verify pairing: e(g, Πagg) == e(pkagg, h)
pub fn verify(h:&G1Projective,agg_proof: &G1Projective, agg_pk: &G2Projective) -> bool {
    let a_proof = G1Affine::from(*agg_proof);
    let a_g = G2Affine::from(G2Projective::generator());
    let a_h = G1Affine::from(*h);
    let a_pk = G2Affine::from(*agg_pk);

    let left = Bn254::pairing( &a_proof, &a_g);
    let right = Bn254::pairing( &a_h, &a_pk);

    left == right
}
