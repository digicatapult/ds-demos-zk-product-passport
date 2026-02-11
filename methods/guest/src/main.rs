// This file has been modified from
// https://github.com/risc0/risc0/blob/main/examples/jwt-validator/methods/guest/src/main.rs
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

use chrono::{DateTime, Utc};
use jwt_core::{ClaimItem, ConflictZones, CustomClaims, PublicOutput, Validator};
use risc0_zkvm::guest::env;

fn main() {
    // Read the token input
    let product_passport: String = env::read();
    let mining_licence: String = env::read();
    let nma_public_key: String = env::read();
    let conflict_zones_str: String = env::read();

    let validator = nma_public_key
        .parse::<Validator>()
        .expect("Could not parse validator from public key");
    let valid_licence = validator
        .validate_token_integrity(&mining_licence)
        .expect("Licence validation failed");

    let conflict_zones: ConflictZones = serde_json::from_str(&conflict_zones_str).unwrap();

    let country_of_operation = valid_licence
        .claims()
        .custom
        .claims
        .iter()
        .find(|claim| claim.key == "country_of_operation")
        .expect("Could not find country")
        .value
        .to_string();
    let region_of_operation = valid_licence
        .claims()
        .custom
        .claims
        .iter()
        .find(|claim| claim.key == "region_of_operation")
        .expect("Could not find country")
        .value
        .to_string();
    for zone in conflict_zones.zones.iter() {
        if zone.country == country_of_operation && zone.region == region_of_operation {
            panic!("Mining licence indicates work in conflict zone!")
        }
    }

    let mining_company_validator = valid_licence
        .claims()
        .custom
        .claims
        .iter()
        .find(|claim| claim.key == "subject_pk".to_string())
        .expect("Could not find public key in licence")
        .value
        .to_string()
        .parse::<Validator>()
        .expect("Could not parse validator from public key");

    let valid_passport = mining_company_validator
        .validate_token_integrity(&product_passport)
        .expect("Passport validation failed");

    // Check passport was issued when mining licence was valid

    let licence_issue_date = valid_licence
        .claims()
        .custom
        .claims
        .iter()
        .find(|claim| claim.key == "issue_date".to_string())
        .expect("Could not find issue date in licence");
    let licence_issue_date = licence_issue_date.value.parse::<DateTime<Utc>>().unwrap();

    let licence_expiry_date = valid_licence
        .claims()
        .custom
        .claims
        .iter()
        .find(|claim| claim.key == "expiry_date".to_string())
        .expect("Could not find expiry date in licence");
    let licence_expiry_date = licence_expiry_date.value.parse::<DateTime<Utc>>().unwrap();

    let passport_issue_date_claimitem = valid_passport
        .claims()
        .custom
        .claims
        .iter()
        .find(|claim| claim.key == "issue_date")
        .expect("Could not find issue_date");
    let passport_issue_date = passport_issue_date_claimitem
        .value
        .parse::<DateTime<Utc>>()
        .unwrap();

    let mut licence_valid_when_signing_product_passport = true;
    if passport_issue_date.cmp(&licence_issue_date).is_lt()
        || passport_issue_date.cmp(&licence_expiry_date).is_gt()
    {
        licence_valid_when_signing_product_passport = false;
    }

    let public_output = PublicOutput {
        pks: vec![nma_public_key],
        claims: CustomClaims {
            claims: [
                ClaimItem {
                    key: "shipment_id".to_string(),
                    value: valid_passport
                        .claims()
                        .custom
                        .claims
                        .iter()
                        .find(|claim| claim.key == "shipment_id")
                        .expect("Could not find shipment_id")
                        .value
                        .to_string(),
                },
                passport_issue_date_claimitem.clone(),
                ClaimItem {
                    key: "licence_valid_when_signing_product_passport".to_string(),
                    value: licence_valid_when_signing_product_passport.to_string(),
                },
                ClaimItem {
                    key: "not_operating_in_following_zones".to_string(),
                    value: conflict_zones_str,
                },
            ]
            .to_vec(),
        },
    };
    env::commit(&public_output);
}
