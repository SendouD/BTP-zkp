use ark_bn254::{Fr, G2Projective};
use ark_std::ops::Mul;
   
/// Single proof: Π_{T,λ} = h^{sk_{T,λ}}  (we use G2 generator h)
pub fn single_proof(sk_child: &Fr,h: &G2Projective) -> G2Projective {
    h.mul(sk_child)
}

/// Aggregate proofs by simply summing the exponents and computing h^{sum}
pub fn aggregate_proofs(proofs: &[G2Projective]) -> G2Projective {
    let mut agg = G2Projective::from(proofs[0]);
    for sigma in proofs.iter().skip(1) {
        agg += sigma;
    }
    agg
}