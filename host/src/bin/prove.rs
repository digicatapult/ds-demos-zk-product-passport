// This file has been modified from
// https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs
// which has the following licence

// Copyright 2026 RISC Zero, Inc.
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

use borsh::ser::BorshSerialize;
use clap::Parser;
use host::prove_token_validation;
use std::fs::File;
use std::io::prelude::*;

/// Prove a JWT was signed
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to signing key
    #[arg(long)]
    path_to_mining_authority_pk: String,

    /// Path to product passport
    #[arg(long)]
    passport_file_path: String,

    /// Path to licence
    #[arg(short, long)]
    licence_file_path: String,

    /// Path to conflict zones JSON file
    #[arg(short, long)]
    conflict_zones_file_path: String,

    /// Path to receipt file
    #[arg(short, long)]
    receipt_file_path: String,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let mut f = File::open(&args.passport_file_path).expect("Could not find passport file");
    let mut passport = String::new();
    f.read_to_string(&mut passport)
        .expect("Could not parse passport from file");

    let mut f = File::open(&args.licence_file_path).expect("Could not find licence file");
    let mut licence = String::new();
    f.read_to_string(&mut licence)
        .expect("Could not parse licence from file");

    let mut f =
        File::open(&args.path_to_mining_authority_pk).expect("Could not find public key file");
    let mut pk = String::new();
    f.read_to_string(&mut pk)
        .expect("Could not parse public key from file");

    let mut f =
        File::open(&args.conflict_zones_file_path).expect("Could not find conflict zones file");
    let mut conflict_zones = String::new();
    f.read_to_string(&mut conflict_zones)
        .expect("Could not parse conflict zones from file");

    let (receipt, _journal) = prove_token_validation(passport, licence, pk, conflict_zones);

    let mut f =
        std::fs::File::create(&args.receipt_file_path).expect("Could not create receipt file");
    let mut serialized_receipt = Vec::new();
    receipt
        .serialize(&mut serialized_receipt)
        .expect("Could not serialise the receipt");
    f.write_all(&serialized_receipt)
        .expect("Could not write receipt to file");
}
