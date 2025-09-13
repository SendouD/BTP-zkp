use ark_bn254::{G1Projective, G2Projective, Fr};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use zk_agg::{utils, master, child, proof, verify};

fn setup() -> (master::MasterKey, Vec<Fr>, Vec<G1Projective>, String) {
    let mut rng = StdRng::seed_from_u64(42u64);
    let version: u64 = 1;

    let ta = master::MasterKey::gen(&mut rng);
    let labels = vec!["A", "B", "C"];

    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for lab in &labels {
        let ck = child::derive_child(&ta, lab, version);
        sks.push(ck.sk_child);
        pks.push(ck.pk_child);
    }

    let mac = "F2:DC:55:DE:FB:A2".to_string();
    (ta, sks, pks, mac)
}

#[test]
fn test_full_set_verifies() {
    let (_ta, child_sks, child_pks, mac) = setup();
    let h = utils::hash_to_g1(&mac);

    let mut proofs: Vec<G2Projective> = Vec::new();
    for sk in &child_sks {
        proofs.push(proof::single_proof(sk, &h));
    }

    let agg_proof = proof::aggregate_proofs(&proofs);
    let agg_pk = verify::aggregate_pks(&child_pks);

    assert!(verify::verify(&h, &agg_proof, &agg_pk));
}

#[test]
fn test_revoked_child_does_not_verify() {
    let (ta, child_sks, _child_pks, mac) = setup();
    let version = 1;
    let h = utils::hash_to_g1(&mac);

    // Proofs for all children A,B,C
    let mut proofs: Vec<G2Projective> = Vec::new();
    for sk in &child_sks {
        proofs.push(proof::single_proof(sk, &h));
    }
    let agg_proof_all = proof::aggregate_proofs(&proofs);

    // Active set excludes A → only B, C
    let labels_active = vec!["B", "C"];
    let mut pks_active: Vec<G1Projective> = Vec::new();
    for lab in &labels_active {
        let ck = child::derive_child(&ta, lab, version);
        pks_active.push(ck.pk_child);
    }
    let agg_pk_active = verify::aggregate_pks(&pks_active);

    // Aggregate proof with A included must fail against [B,C]
    assert!(
        !verify::verify(&h, &agg_proof_all, &agg_pk_active),
        "A's proof must NOT verify when A is revoked from active set [B,C]"
    );
}
#[warn(unused_variables)]
#[test]
fn test_add_set_verifies() {
    let (_ta, _child_sks, _child_pks, mac) = setup();
    let h = utils::hash_to_g1(&mac);

    let mut proofs: Vec<G2Projective> = Vec::new();
    let labels = vec!["A", "B", "C", "D"];
    let version = 1;
    let mut pks_active: Vec<G1Projective> = Vec::new();
    for lab in &labels {
        let ck = child::derive_child(&_ta, lab, version);
        pks_active.push(ck.pk_child);
        proofs.push(proof::single_proof(&ck.sk_child, &h));
    }

    let agg_proof = proof::aggregate_proofs(&proofs);
    let agg_pk = verify::aggregate_pks(&pks_active);

    assert!(verify::verify(&h, &agg_proof, &agg_pk));
}