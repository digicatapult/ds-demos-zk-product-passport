import subprocess
import os
from gooey import Gooey, GooeyParser


@Gooey(program_name="Zero Knowledge Product Passport Verifier", env={'GOOEY_THEME': 'dark'})
def main():
    parser = GooeyParser(description="Verify a Zero Knowledge Product Passport")
    parser.add_argument('receipt', help="Proof file", widget="FileChooser")

    args = parser.parse_args()

    env = os.environ.copy()
    env["RISC0_DEV_MODE"] = "1"

    output = subprocess.run(["../target/release/verify", args.receipt], env=env, capture_output=True, text=True)
    print(output.stdout)

if __name__ == "__main__":
    main()