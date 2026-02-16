import os
import subprocess
from gooey import Gooey, GooeyParser

@Gooey(program_name="Mining Licence Signer")
def main():
    parser = GooeyParser(description="Sign a mining licence")

    licence_group = parser.add_argument_group(
        "Mining Authority Signing Key", 
        ""
    )
    licence_group.add_argument('national_mining_authority_sk', widget="FileChooser", default="../test_data/national_mining_authority_sk.jwk")

    licence_group = parser.add_argument_group(
        "Licence details", 
        ""
    )
    licence_group.add_argument('issuer_id', help="Issuer ID", default="National_Mining_Authority")
    licence_group.add_argument('subject_id', help="Subject ID", default="ACME_Mining_Company")
    licence_group.add_argument('subject_pk_file', help="Subject Public Key file", default="../test_data/mining_company_pk.jwk", widget="FileChooser")
    licence_group.add_argument('valid_from', help="Valid from", default="2025-01-01T00:00:00Z")
    licence_group.add_argument('valid_until', help="Valid until", default="2035-01-01T00:00:00Z")
    licence_group.add_argument('country_of_operation', help="Country of operation", default="GB")
    licence_group.add_argument('region_of_operation', help="Region of operation", default="Cornwall")

    licence_group.add_argument('output_file', help="Licence output file",widget="FileSaver", default="./licence.jwt")
    tmp_claims_file = "./mining_licence_claims.json"

    args = parser.parse_args()

    output = subprocess.run(
        [
            "../target/release/gen_claims_file",
            "-p", tmp_claims_file,
            "--key-value-claim-pair", "issuer_id," + args.issuer_id,
            "--key-value-claim-pair", "subject_id," + args.subject_id,
            "--key-file-claim-pair", "subject_pk," + args.subject_pk_file,
            "--key-value-claim-pair", "issue_date," + args.valid_from,
            "--key-value-claim-pair", "expiry_date," + args.valid_until,
            "--key-value-claim-pair", "country_of_operation," + args.country_of_operation,
            "--key-value-claim-pair", "region_of_operation," + args.region_of_operation
        ], capture_output=True, text=True)
    
    if output.returncode != 0:
        print("An error occurred.")
        print(output.stderr)
        return

    output = subprocess.run(["../target/release/sign", "-s", args.national_mining_authority_sk, '-c', tmp_claims_file, '-t', args.output_file], capture_output=True, text=True)

    if output.returncode == 0:
        print("Done\n")
    else: 
        print("An error occurred.")
        print(output.stderr)        

if __name__ == "__main__":
    main()
