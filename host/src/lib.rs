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

use methods::VERIFY_TOKEN_WITH_SOME_KEY_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

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

    let output: String = receipt
        .journal
        .decode()
        .expect("Journal should decode to string.");

    (receipt, output)
}
