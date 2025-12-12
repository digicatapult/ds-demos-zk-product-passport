// Modified from files in RISC Zero example repo
// https://github.com/risc0/risc0/blob/main/examples/jwt-validator/

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

use std::io::Read;

use borsh::de::BorshDeserialize;
use host::compute_fingerprint;
use jwt_core::PublicOutput;
use methods::VERIFY_TOKEN_WITH_SOME_KEY_ID;
use risc0_zkvm::Receipt;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        panic!("Usage: verify /path/to/receipt.bin");
    }

    let mut f = std::fs::File::open(&args[1]).expect("Could not find receipt file");
    let mut receipt = Vec::new();
    f.read_to_end(&mut receipt)
        .expect("Could not parse token from file");

    let receipt =
        Receipt::try_from_slice(&receipt).expect("Could not deserialise bytes as receipt");

    let res = receipt.verify(VERIFY_TOKEN_WITH_SOME_KEY_ID);
    if res.is_ok() {
        println!("Verification succeeded!");
        println!("The prover has proved they hold a product passport that is authenticated by a mining licence that is authenticated by the following national mining authority key:");
        let public_outputs: PublicOutput = receipt
            .journal
            .decode()
            .expect("Could not decode receipt journal");
        let pk_digests: Vec<String> = public_outputs
            .pks
            .into_iter()
            .map(|pk| compute_fingerprint(pk))
            .collect();
        println!("{:#?}", pk_digests);

        println!("\nThe following information was proved about the product passport:");
        println!("{:}", public_outputs.claims.pretty_print());
    } else {
        println!("Verification failed!")
    }
}
