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

use jwt_core::Validator;
use risc0_zkvm::guest::env;

fn main() {
    // read the token input
    let token: String = env::read();
    let num_public_keys: usize = env::read();
    let mut pks: Vec<String> = Vec::new();

    for _i in 0..num_public_keys {
        pks.push(env::read());
    }

    let valid_token = pks
        .iter()
        .filter_map(|pk| {
            pk.parse::<Validator>().ok().and_then(|validator| {
                let status = validator.validate_token_integrity(&token).ok();
                status
            })
        })
        .next()
        .expect("failed to validate token with any key");

    let mut output_strings: Vec<String> = pks.iter().map(|pk| pk.to_string()).collect();
    output_strings.push(valid_token.claims().custom.to_string());
    let data = output_strings.join("||");
    env::commit(&data);
}
