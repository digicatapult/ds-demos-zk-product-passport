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

use clap::Parser;
use jwt_core::{CustomClaims, Issuer};
use std::fs::File;
use std::io::prelude::*;

/// Generate a JWT
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to signing key
    #[arg(short, long)]
    signing_key_file_path: String,

    /// Path to custom claims
    #[arg(short, long)]
    custom_claims_file_path: String,

    /// Path in which to to save output token
    #[arg(short, long)]
    token_file_path: String,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let mut f = std::fs::File::open(&args.signing_key_file_path)
        .expect("Please provide signing key in PEM format as first argument");
    let mut secret_key = "".to_string();
    f.read_to_string(&mut secret_key).unwrap();

    let mut f = std::fs::File::open(&args.custom_claims_file_path)
        .expect("Please provide custom claims in a JSON file");
    let mut claims_string = "".to_string();
    f.read_to_string(&mut claims_string).unwrap();
    let claims: CustomClaims =
        serde_json::from_str(&claims_string).expect("Could not parse custom claims");

    let iss = secret_key
        .parse::<Issuer>()
        .expect("failed to create issuer from secret key");
    let token = iss
        .generate_token(&claims)
        .expect("failed to generate token");

    let mut f = File::create(&args.token_file_path).expect("Could not create JWT file");
    f.write_all(&token.as_bytes())
        .expect("Could not write to file");
}
