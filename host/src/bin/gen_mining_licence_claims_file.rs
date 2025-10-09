use clap::Parser;
use jwt_core::CustomClaims;
use std::io::prelude::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "./mining_certificate_claims.json")]
    path_to_claims_file: String,

    #[arg(short, long, default_value = "National Mining Authority")]
    issuer_id: String,

    #[arg(short, long, default_value = "ACME Mining Company")]
    subject_id: String,

    #[arg(short, long, default_value = "")]
    subject_pk_file: String,

    #[arg(short, long, default_value = "2025-06-01T00:00:00Z")]
    issue_date: String,

    #[arg(short, long, default_value = "2035-06-01T00:00:00Z")]
    expiry_date: String,

    #[arg(short, long, default_value = "GB")]
    country_of_operation: String,

    #[arg(short, long, default_value = "Cornwall")]
    region_of_operation: String,
}

fn main() {
    let args = Args::parse();

    let mut mining_certificate_claims = CustomClaims::new();
    mining_certificate_claims.add("issuer_id".to_string(), args.issuer_id, false);
    mining_certificate_claims.add("subject_id".to_string(), args.subject_id, false);
    mining_certificate_claims.add("issue_date".to_string(), args.issue_date.to_string(), false);
    mining_certificate_claims.add(
        "expiry_date".to_string(),
        args.expiry_date.to_string(),
        false,
    );
    mining_certificate_claims.add(
        "country_of_operation".to_string(),
        args.country_of_operation.to_string(),
        false,
    );
    mining_certificate_claims.add(
        "region_of_operation".to_string(),
        args.region_of_operation.to_string(),
        false,
    );

    let mut subject_pk_file =
        std::fs::File::open(args.subject_pk_file).expect("Could not find subject public key file");
    let mut subject_pk: String = "".to_string();
    let _ = subject_pk_file
        .read_to_string(&mut subject_pk)
        .expect("Could not read public key from file");

    mining_certificate_claims.add("subject_pk".to_string(), subject_pk, false);

    let mining_certificate_claims_string =
        serde_json::to_string_pretty(&mining_certificate_claims).unwrap();

    let mut f =
        std::fs::File::create(&args.path_to_claims_file).expect("Could not create claims file");
    f.write_all(&mining_certificate_claims_string.as_bytes())
        .expect("Could not write to file");
}
