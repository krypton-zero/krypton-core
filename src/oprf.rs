//! VOPRF primitives: RFC 9497 (verifiable OPRF), suite `ristretto255-SHA512`. The foundation of anonymous invite
//! tickets ([`crate::ticket`]).
//!
//! The group operations are done by `voprf` 0.5.0 (facebook/voprf, which follows the final RFC 9497); nothing is
//! hand-rolled here. This module fixes byte formats, lengths and batch limits, and maps crate errors to core errors
//! ([`Error`]). It is stateless: the caller ([`crate::ticket`]) re-derives the blinding scalar from the account key seed
//! each time.
//!
//! Flow (client = this core in the app, server = the issuing service, which implements the same formulas):
//! 1. Blind: `blind * HashToGroup(input)`. Only the blinded element (32 B) goes to the server
//! 2. BlindEvaluate: the server evaluates with its secret scalar and attaches one DLEQ proof (64 B) per batch
//! 3. Finalize: the proof is verified against the server public key **pinned by the app**, then the output (64 B) is unblinded
//! 4. Evaluate: on redemption the server recomputes the output for the input and compares in constant time

use curve25519_dalek::scalar::Scalar;
use voprf::{EvaluationElement, Group, Proof, Ristretto255, VoprfClient};
use zeroize::Zeroizing;

use crate::error::Error;

/// Suite `ristretto255-SHA512` (RFC 9497 §4.1)
pub type Suite = Ristretto255;

/// Group element (blinded element, evaluated element, server public key), compressed ristretto255
pub const ELEMENT_LEN: usize = 32;
/// Scalar, canonical little-endian
pub const SCALAR_LEN: usize = 32;
/// DLEQ proof `c ‖ s`
pub const PROOF_LEN: usize = 2 * SCALAR_LEN;
/// Output, SHA-512
pub const OUTPUT_LEN: usize = 64;
/// DeriveKeyPair seed (RFC 9497 §3.2.1 `seed[Ns]`)
pub const SEED_LEN: usize = 32;
/// Maximum number of elements in one batch
pub const MAX_BATCH: usize = 64;
/// Maximum length of one input. The RFC allows up to 2^16-1, but ticket inputs are 32 B (the RFC vectors use 1 and 17 B)
pub const MAX_INPUT_LEN: usize = 1024;

/// Crate errors → core errors, by RFC 9497 error name: DeserializeError and InputValidationError → `TicketPoint`,
/// VerifyError → `TicketProof`, length and batch errors (`Input`, `Batch`) → `TicketInput`.
fn map_err(e: voprf::Error) -> Error {
    match e {
        voprf::Error::Deserialization => Error::TicketPoint,
        voprf::Error::ProofVerification => Error::TicketProof,
        voprf::Error::Input | voprf::Error::Batch | voprf::Error::Info | voprf::Error::DeriveKeyPair => Error::TicketInput,
        voprf::Error::Protocol => Error::Internal,
    }
}

fn check_input(input: &[u8]) -> Result<(), Error> {
    if input.is_empty() || input.len() > MAX_INPUT_LEN {
        return Err(Error::TicketInput);
    }
    Ok(())
}

/// Parses one element. A non-canonical encoding, an invalid point or the identity gives `TicketPoint` (`deserialize_elem` in voprf group/ristretto.rs rejects all three)
pub fn element(bytes: &[u8; ELEMENT_LEN]) -> Result<<Suite as Group>::Elem, Error> {
    Suite::deserialize_elem(bytes).map_err(|_| Error::TicketPoint)
}

/// One blinding: the crate's client state (holds the blinding scalar, `ZeroizeOnDrop`) and the blinded element
pub(crate) struct Blinded {
    pub client: VoprfClient<Suite>,
    pub element: [u8; ELEMENT_LEN],
}

/// Blinds with a given scalar (deterministic form of RFC 9497 Blind). A zero blind gives `Internal` (callers filter out zero)
pub(crate) fn blind_scalar(input: &[u8], blind: &Scalar) -> Result<Blinded, Error> {
    check_input(input)?;
    if blind == &Scalar::ZERO {
        return Err(Error::Internal);
    }
    let r = VoprfClient::<Suite>::deterministic_blind_unchecked(input, *blind).map_err(map_err)?;
    Ok(Blinded { element: r.message.serialize().into(), client: r.state })
}

/// Blinded element for a given blind (canonical 32 B, non-zero), for RFC vectors and cross-implementation tests. A non-canonical or zero blind gives `TicketInput`
pub fn blind_with(input: &[u8], blind: &[u8; SCALAR_LEN]) -> Result<[u8; ELEMENT_LEN], Error> {
    let s = Zeroizing::new(Suite::deserialize_scalar(blind).map_err(|_| Error::TicketInput)?);
    Ok(blind_scalar(input, &s)?.element)
}

/// Verifies a batch response and unblinds it (outputs in input order). If anything is wrong, no output at all is returned.
///
/// - Mismatched counts, zero elements or more than 64 give `TicketInput`
/// - A non-canonical or identity public key or evaluated element gives `TicketPoint`
/// - A non-canonical proof scalar or a proof that does not verify gives `TicketProof`. Unless it is proven that the secret key
///   of this public key evaluated **exactly these blinded elements**, there is no output (reordered evaluated elements or a response spliced in from another request are caught here)
// Why `&Vec`: voprf's batch_finalize takes `&II` with `II: IntoIterator` as a sized type (a slice does not work)
#[allow(clippy::ptr_arg)]
pub(crate) fn finalize_clients(
    inputs: &Vec<&[u8]>,
    clients: &Vec<VoprfClient<Suite>>,
    evaluated: &[[u8; ELEMENT_LEN]],
    server_pub: &[u8; ELEMENT_LEN],
    proof: &[u8; PROOF_LEN],
) -> Result<Zeroizing<Vec<[u8; OUTPUT_LEN]>>, Error> {
    let n = inputs.len();
    if n == 0 || n > MAX_BATCH || clients.len() != n || evaluated.len() != n {
        return Err(Error::TicketInput);
    }
    let pk = element(server_pub)?;
    let messages = evaluated
        .iter()
        .map(|e| EvaluationElement::<Suite>::deserialize(e))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::TicketPoint)?;
    let proof = Proof::<Suite>::deserialize(proof).map_err(|_| Error::TicketProof)?;
    let outputs = VoprfClient::batch_finalize(inputs, clients, &messages, &proof, pk).map_err(map_err)?;
    let mut out = Zeroizing::new(Vec::with_capacity(n));
    for o in outputs {
        out.push(o.map_err(map_err)?.into());
    }
    Ok(out)
}

/// Finalizes a batch with given blinds, for RFC vectors and cross-implementation tests. `blinded` is recomputed with `blind_with` and compared (`TicketInput` on mismatch)
pub fn finalize_batch(
    inputs: &[&[u8]],
    blinds: &[[u8; SCALAR_LEN]],
    blinded: &[[u8; ELEMENT_LEN]],
    evaluated: &[[u8; ELEMENT_LEN]],
    server_pub: &[u8; ELEMENT_LEN],
    proof: &[u8; PROOF_LEN],
) -> Result<Zeroizing<Vec<[u8; OUTPUT_LEN]>>, Error> {
    if blinds.len() != inputs.len() || blinded.len() != inputs.len() || inputs.len() > MAX_BATCH {
        return Err(Error::TicketInput);
    }
    let mut clients = Vec::with_capacity(inputs.len());
    for ((input, b), want) in inputs.iter().zip(blinds).zip(blinded) {
        let s = Zeroizing::new(Suite::deserialize_scalar(b).map_err(|_| Error::TicketInput)?);
        let x = blind_scalar(input, &s)?;
        if &x.element != want {
            return Err(Error::TicketInput);
        }
        clients.push(x.client);
    }
    finalize_clients(&inputs.to_vec(), &clients, evaluated, server_pub, proof)
}

#[cfg(any(test, feature = "test-server"))]
pub use server::ServerKey;

/// Server-side (issuer) operations. Not compiled into the app binary (`test-server` feature, which the tests enable through their own dev-dependency).
/// The issuing service implements the same formulas; this module is the counterpart for cross-implementation and adversarial tests
#[cfg(any(test, feature = "test-server"))]
mod server {
    use rand_core::{CryptoRng, CryptoRngCore, RngCore};
    use subtle::ConstantTimeEq;
    use voprf::{BlindedElement, Group, VoprfServer};
    use zeroize::Zeroizing;

    use super::{map_err, Suite, ELEMENT_LEN, MAX_BATCH, MAX_INPUT_LEN, OUTPUT_LEN, PROOF_LEN, SCALAR_LEN, SEED_LEN};
    use crate::error::Error;

    /// RNG that yields a fixed proof scalar r. `Scalar::random` reads 64 bytes and reduces them wide, so feeding `r ‖ 0³²` yields r
    struct FixedScalar([u8; 32]);

    impl RngCore for FixedScalar {
        fn next_u32(&mut self) -> u32 {
            unreachable!("proof generation only calls fill_bytes(64), exactly once")
        }
        fn next_u64(&mut self) -> u64 {
            unreachable!("proof generation only calls fill_bytes(64), exactly once")
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            assert_eq!(dest.len(), 64, "proof generation draws exactly one scalar");
            dest.fill(0);
            dest[..32].copy_from_slice(&self.0);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for FixedScalar {}

    /// The server's OPRF key, zeroized on drop (`VoprfServer` is `ZeroizeOnDrop`)
    pub struct ServerKey(VoprfServer<Suite>);

    impl ServerKey {
        /// RFC 9497 §3.2.1 DeriveKeyPair(seed, info)
        pub fn derive(seed: &[u8; SEED_LEN], info: &[u8]) -> Result<ServerKey, Error> {
            VoprfServer::new_from_seed(seed, info).map(ServerKey).map_err(map_err)
        }

        /// From a canonical 32-byte non-zero scalar; otherwise `TicketPoint`
        pub fn from_secret(sk: &[u8; SCALAR_LEN]) -> Result<ServerKey, Error> {
            VoprfServer::new_with_key(sk).map(ServerKey).map_err(|_| Error::TicketPoint)
        }

        pub fn public_key(&self) -> [u8; ELEMENT_LEN] {
            Suite::serialize_elem(self.0.get_public_key()).into()
        }

        /// The secret scalar (for writing cross-implementation vectors; test keys only)
        pub fn secret_bytes(&self) -> Zeroizing<[u8; SCALAR_LEN]> {
            let mut out = Zeroizing::new([0u8; SCALAR_LEN]);
            out.copy_from_slice(&self.0.serialize()[..SCALAR_LEN]);
            out
        }

        /// Evaluates blinded elements, returning (evaluated elements, one batch proof). The proof's random scalar comes from `rng`
        pub fn blind_evaluate(
            &self,
            rng: &mut dyn CryptoRngCore,
            blinded: &[[u8; ELEMENT_LEN]],
        ) -> Result<(Vec<[u8; ELEMENT_LEN]>, [u8; PROOF_LEN]), Error> {
            if blinded.is_empty() || blinded.len() > MAX_BATCH {
                return Err(Error::TicketInput);
            }
            let elements = blinded
                .iter()
                .map(|b| BlindedElement::<Suite>::deserialize(b))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::TicketPoint)?;
            let mut rng = rng;
            let r = self.0.batch_blind_evaluate(&mut rng, &elements).map_err(map_err)?;
            let evaluated = r.messages.iter().map(|m| m.serialize().into()).collect();
            Ok((evaluated, r.proof.serialize().into()))
        }

        /// Evaluates with a fixed proof scalar (ProofRandomScalar in the RFC vectors), for tests
        pub fn blind_evaluate_with(
            &self,
            blinded: &[[u8; ELEMENT_LEN]],
            proof_random: &[u8; SCALAR_LEN],
        ) -> Result<(Vec<[u8; ELEMENT_LEN]>, [u8; PROOF_LEN]), Error> {
            self.blind_evaluate(&mut FixedScalar(*proof_random), blinded)
        }

        /// Unblinded evaluation (RFC 9497 §3.3.2 Evaluate), used to check a redeemed ticket
        pub fn evaluate(&self, input: &[u8]) -> Result<Zeroizing<[u8; OUTPUT_LEN]>, Error> {
            if input.is_empty() || input.len() > MAX_INPUT_LEN {
                return Err(Error::TicketInput);
            }
            let o = self.0.evaluate(input).map_err(map_err)?;
            let mut out = Zeroizing::new([0u8; OUTPUT_LEN]);
            out.copy_from_slice(&o);
            Ok(out)
        }

        /// Whether (input, output) belongs to this key, compared in constant time
        pub fn verify_output(&self, input: &[u8], output: &[u8]) -> bool {
            if output.len() != OUTPUT_LEN {
                return false;
            }
            match self.evaluate(input) {
                Ok(expected) => bool::from(expected.as_slice().ct_eq(output)),
                Err(_) => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Official RFC 9497 Appendix A.1.2 vectors (ristretto255-SHA512, VOPRF) in `tests/vectors/rfc9497-ristretto255-voprf.json`.
    //! The JSON was extracted mechanically from the RFC text, and the JavaScript reference implementation (@noble/curves)
    //! passes the same file
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vector {
        input: Vec<String>,
        blind: Vec<String>,
        blinded_element: Vec<String>,
        evaluation_element: Vec<String>,
        proof: String,
        proof_random_scalar: String,
        output: Vec<String>,
    }

    #[derive(Deserialize)]
    struct File {
        suite: String,
        mode: String,
        seed: String,
        key_info: String,
        sk_sm: String,
        pk_sm: String,
        vectors: Vec<Vector>,
    }

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }
    fn a32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }
    fn a64(s: &str) -> [u8; 64] {
        h(s).try_into().unwrap()
    }

    fn load() -> File {
        serde_json::from_str(include_str!("../tests/vectors/rfc9497-ristretto255-voprf.json")).unwrap()
    }

    #[test]
    fn rfc9497_key_derivation() {
        let f = load();
        assert_eq!((f.suite.as_str(), f.mode.as_str()), ("ristretto255-SHA512", "VOPRF"));
        let key = ServerKey::derive(&a32(&f.seed), &h(&f.key_info)).unwrap();
        assert_eq!(key.public_key(), a32(&f.pk_sm));
        assert_eq!(*key.secret_bytes(), a32(&f.sk_sm));
        assert_eq!(hex::encode(*key.secret_bytes()), "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909");
        assert_eq!(ServerKey::from_secret(&a32(&f.sk_sm)).unwrap().public_key(), a32(&f.pk_sm));
    }

    #[test]
    fn rfc9497_vectors_byte_for_byte() {
        let f = load();
        assert_eq!(f.vectors.len(), 3);
        let key = ServerKey::from_secret(&a32(&f.sk_sm)).unwrap();
        let pk = a32(&f.pk_sm);
        for (i, v) in f.vectors.iter().enumerate() {
            let inputs: Vec<Vec<u8>> = v.input.iter().map(|s| h(s)).collect();
            let refs: Vec<&[u8]> = inputs.iter().map(|x| x.as_slice()).collect();
            let blinds: Vec<[u8; 32]> = v.blind.iter().map(|s| a32(s)).collect();
            let want = |xs: &[String]| xs.iter().map(|s| a32(s)).collect::<Vec<_>>();

            // 1. Blind
            let blinded: Vec<[u8; 32]> = refs.iter().zip(&blinds).map(|(x, b)| blind_with(x, b).unwrap()).collect();
            assert_eq!(blinded, want(&v.blinded_element), "vector {i}: BlindedElement");
            // 2. BlindEvaluate (+ proof) with the fixed random scalar
            let (evaluated, proof) = key.blind_evaluate_with(&blinded, &a32(&v.proof_random_scalar)).unwrap();
            assert_eq!(evaluated, want(&v.evaluation_element), "vector {i}: EvaluationElement");
            assert_eq!(proof, a64(&v.proof), "vector {i}: Proof");
            // 3. Finalize with the RFC's evaluated elements and proof
            let out = finalize_batch(&refs, &blinds, &blinded, &want(&v.evaluation_element), &pk, &a64(&v.proof)).unwrap();
            assert_eq!(*out, v.output.iter().map(|s| a64(s)).collect::<Vec<_>>(), "vector {i}: Output");
            // 4. Evaluate (unblinded)
            for (x, o) in refs.iter().zip(&v.output) {
                assert_eq!(*key.evaluate(x).unwrap(), a64(o), "vector {i}: Evaluate");
                assert!(key.verify_output(x, &h(o)));
            }
        }
    }

    /// Same shape as the Fixture in `tests/oprf.rs`, generated with @noble/curves by the JavaScript reference implementation
    #[derive(Deserialize)]
    struct Dev {
        generator: String,
        suite: String,
        seed: String,
        key_info: String,
        sk_sm: String,
        pk_sm: String,
        inputs: Vec<String>,
        blinds: Vec<String>,
        blinded_elements: Vec<String>,
        proof_random_scalar: String,
        evaluation_elements: Vec<String>,
        proof: String,
        outputs: Vec<String>,
    }

    /// This core reproduces byte for byte the key, blinds, evaluations, proof and outputs produced by the JavaScript reference
    /// implementation (@noble/curves), and accepts its proof
    #[test]
    fn noble_vectors_open_in_rust() {
        let f: Dev = serde_json::from_str(include_str!("../tests/vectors/oprf-dev.json")).unwrap();
        assert!(f.generator.contains("@noble/curves"), "{}", f.generator);
        assert_eq!(f.suite, "ristretto255-SHA512");
        let key = ServerKey::derive(&a32(&f.seed), &h(&f.key_info)).unwrap();
        assert_eq!(key.public_key(), a32(&f.pk_sm));
        assert_eq!(*key.secret_bytes(), a32(&f.sk_sm));

        let inputs: Vec<Vec<u8>> = f.inputs.iter().map(|s| h(s)).collect();
        let refs: Vec<&[u8]> = inputs.iter().map(|x| x.as_slice()).collect();
        let blinds: Vec<[u8; 32]> = f.blinds.iter().map(|s| a32(s)).collect();
        let blinded: Vec<[u8; 32]> = refs.iter().zip(&blinds).map(|(x, b)| blind_with(x, b).unwrap()).collect();
        assert_eq!(blinded, f.blinded_elements.iter().map(|s| a32(s)).collect::<Vec<_>>());
        let (evaluated, proof) = key.blind_evaluate_with(&blinded, &a32(&f.proof_random_scalar)).unwrap();
        assert_eq!(evaluated, f.evaluation_elements.iter().map(|s| a32(s)).collect::<Vec<_>>());
        assert_eq!(proof, a64(&f.proof));
        let out = finalize_batch(&refs, &blinds, &blinded, &evaluated, &a32(&f.pk_sm), &a64(&f.proof)).unwrap();
        assert_eq!(*out, f.outputs.iter().map(|s| a64(s)).collect::<Vec<_>>());
    }
}
