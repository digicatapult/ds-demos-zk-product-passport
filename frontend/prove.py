import subprocess
import os
from gooey import Gooey, GooeyParser

@Gooey(program_name="Zero Knowledge Product Passport Generator")
def main():
    parser = GooeyParser(description="Generate a JWT")
    parser.add_argument('passport', help="Product passport", widget="FileChooser", default="./product_passport.jwt")
    parser.add_argument('licence', help="Mining licence", widget="FileChooser", default="./licence.jwt")
    parser.add_argument('verification_key', help="National mining authority verification key", widget="FileChooser", default="../test_data/national_mining_authority_pk.jwk")
    parser.add_argument('conflict_zones', help="Conflict zones file", widget="FileChooser", default="../test_data/conflict_zones.json")
    parser.add_argument('receipt_file', help="Receipt file", widget="FileSaver", default="./receipt.bin")

    args = parser.parse_args()

    env = os.environ.copy()
    env["RISC0_DEV_MODE"] = "1"

    output = subprocess.run(["../target/release/prove", "--passport-file-path", args.passport, '--licence-file-path', args.licence, '--path-to-mining-authority-pk', args.verification_key, '--conflict-zones-file-path', args.conflict_zones, '--receipt-file-path', args.receipt_file], env=env, capture_output=True, text=True)

    if output.returncode == 0:
        print("Done\n")
    else: 
        print("An error occurred.")
        print(output.stderr)
        return

if __name__ == "__main__":
    main()
