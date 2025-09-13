// tests/ta_revocation.rs
use ark_bn254::{G1Projective, G2Projective, Fr};
use ark_std::rand::{rngs::StdRng, SeedableRng};
// Bring your modules into scope (path depends on crate structure).
// If your crate root is `lib.rs` with `pub mod master;` etc., this will work.
use zk_agg::{ 
    utils,
    master,
    child,
    proof,
    verify,
};

#[test]
fn ta_issuance_and_revocation_simulation() {
    // deterministic RNG for reproducibility
    let mut rng = StdRng::seed_from_u64(42u64);
    let version: u64 = 1;

    // --- TA master key generation ---
    let ta = master::MasterKey::gen(&mut rng);
    // --- Company labels (initial set includes A) ---
    let labels_all = vec!["A", "B", "C"];

    // Each company derives child keys from TA master key
    let mut child_sks: Vec<Fr> = Vec::new();
    let mut child_pks: Vec<G1Projective> = Vec::new();
    for lab in &labels_all {
        let ck = child::derive_child(&ta, lab, version);
        child_sks.push(ck.sk_child);
        child_pks.push(ck.pk_child);
    }

    // Message (MAC or truck id) bound to a point h in G2
    let mac = "F2:DC:55:DE:FB:A2";
    let h = utils::hash_to_g1(mac); // I use G2 here so verify pairing order is (G1, G2)

    // --- Valid case: aggregate over A,B,C ---
    // Each company produces its proof Pi_{T,λ} = h^{sk_{T,λ}}
    let mut proofs_all: Vec<G2Projective> = Vec::new();
    for sk in &child_sks {
        let sigma = proof::single_proof(sk, &h);
        proofs_all.push(sigma);
    }

    // Aggregate proofs and aggregate public keys for labels_all
    let agg_proof_all = proof::aggregate_proofs(&proofs_all);
    let agg_pk_all = verify::aggregate_pks(&child_pks);

    // Verify should succeed for full set
    let ok_all = verify::verify(&h, &agg_proof_all, &agg_pk_all);
    assert!(ok_all, "Aggregate proof should verify for full label set [A,B,C]");

    // --- Now revoke A: active set becomes [B, C] ---
    let labels_active = vec!["B", "C"];
    let mut pks_active: Vec<G1Projective> = Vec::new();
    for lab in &labels_active {
        let ck = child::derive_child(&ta, lab, version);
        pks_active.push(ck.pk_child);
    }
    // Aggregate verification keys for active set (omit A)
    // Extract pks for B and C (they were in positions 1 and 2)
    let agg_pk_active = verify::aggregate_pks(&pks_active);
    // If TA/Verifier expects an aggregate proof for active set [B,C],
    // a single A proof should NOT verify against agg_pk_active
    let ok_a_against_active = verify::verify(&h,&agg_proof_all, &agg_pk_active);
    assert!(!ok_a_against_active, "A's proof must NOT verify when A is revoked from active set [B,C]");

}
