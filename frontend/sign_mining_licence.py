import subprocess
from gooey import Gooey, GooeyParser

@Gooey(program_name="Mining Licence Signer")
def main():
    parser = GooeyParser(description="Sign a mining licence")

    licence_group = parser.add_argument_group(
        "Mining Authority Signing Key", 
        ""
    )
    licence_group.add_argument('mining_authority_sk', widget="FileChooser")

    licence_group = parser.add_argument_group(
        "Licence details", 
        ""
    )
    licence_group.add_argument('issuer_id', help="Issuer ID", default="National Mining Authority")
    licence_group.add_argument('subject_id', help="Subject ID", default="ACME Mining Company")
    licence_group.add_argument('subject_pk_file', help="Subject Public Key file", widget="FileChooser")
    licence_group.add_argument('valid_from', help="Valid from", default="2025-01-01T00:00:00Z")
    licence_group.add_argument('valid_until', help="Valid until", default="2035-01-01T00:00:00Z")
    licence_group.add_argument('country_of_operation', help="Country of operation", default="GB")
    licence_group.add_argument('region_of_operation', help="Region of operation", default="Cornwall")

    licence_group.add_argument('output_file', help="Licence output file",widget="FileSaver")
    tmp_claims_file = "./mining_licence_claims.json"

    args = parser.parse_args()

    command_output = subprocess.run(["../target/release/gen_mining_licence_claims_file", "--path-to-claims-file", tmp_claims_file, "--issuer-id", args.issuer_id, "--subject-id", args.subject_id, "--subject-pk-file", args.subject_pk_file, "--issue-date", args.valid_from, "--expiry-date", args.valid_until, "--country-of-operation", args.country_of_operation, "--region-of-operation", args.region_of_operation], capture_output=True, text=True)
    print(command_output)
    command_output = subprocess.run(["../target/release/gen", "-s", args.mining_authority_sk, '-c', tmp_claims_file, '-t', args.output_file], capture_output=True, text=True)
    print(command_output)

if __name__ == "__main__":
    main()

    # # Generate product passport
    
    # ./target/release/gen -s ./host/national_mining_authority_sk.jwk -c ./host/licence_claims.json -t ./licence.jwt 

    # # Generate mining licence
    # ./target/release/gen -s ./host/mining_company_sk.jwk -c ./host/product_passport_claims.json -t ./passport.jwt

    # # Prove
    # ./target/release/prove -p ./passport.jwt -l ./licence.jwt -v ./host/national_mining_authority_pk.jwk -c ./host/conflict_zones.json

    # # Verify
    # ./target/release/verify ./receipt.bin 
