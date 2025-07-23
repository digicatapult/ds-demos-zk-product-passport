// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use base64::prelude::*;
use methods::VERIFY_TOKEN_WITH_SOME_KEY_ELF;
use risc0_zkvm::sha::rust_crypto::Sha256;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;

#[derive(Serialize)]
struct FingerprintableJwk {
    e: String,
    kty: String,
    n: String,
}

pub fn compute_fingerprint(pk: String) -> String {
    let public_key: Value = serde_json::from_str(&pk).expect("Could not parse key");

    let e = public_key
        .get("e")
        .expect("Could not find mandatory field 'e'")
        .to_string()
        .replace("\"", "");

    let kty = public_key
        .get("kty")
        .expect("Could not find mandatory field 'kty'")
        .to_string()
        .replace("\"", "");

    let n = public_key
        .get("n")
        .expect("Could not find mandatory field 'n'")
        .to_string()
        .replace("\"", "");

    let fingerprintable_jwk = FingerprintableJwk { e, kty, n };

    let fingerprintable_jwk_as_str = serde_json::to_string(&fingerprintable_jwk).unwrap();

    let digest = Sha256::digest(fingerprintable_jwk_as_str);

    BASE64_URL_SAFE.encode(digest).replace("=", "")
}

pub fn prove_token_validation(token: String, pks: &Vec<String>) -> (Receipt, String) {
    // Write the JWT
    let mut binding = ExecutorEnv::builder();
    let env = binding.write(&token).expect("failed to write JWT to env");

    // Write the number of public keys
    env.write(&pks.len())
        .expect("Could not write number of public keys to env");

    // Write the public keys
    for pk in pks.iter() {
        env.write(pk).expect("failed to write pk to env");
    }
    let env = env.build().expect("failed to build env");

    let prover = default_prover();

    let receipt = prover
        .prove(env, VERIFY_TOKEN_WITH_SOME_KEY_ELF)
        .expect("failed to prove")
        .receipt;

    /*let output: String = receipt
    .journal
    .decode()
    .expect("Journal should decode to string.");*/
    let output = "".to_string();

    (receipt, output)
}
