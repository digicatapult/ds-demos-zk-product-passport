# Supply Chain Proof Demo
This demo is a modified version of the risc0 example for JWT verification from
the main RISC Zero repository
[https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs](https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs)

> [!IMPORTANT]
> This is proof-of-concept code and must not be used in a real environment.

## Scenario
The demo provides a proof of concept of a 'zero-knowledge product passport',
which allows, say, a distributor to prove the provenance of their product
(specifically, that it did not originate in a conflict area) without revealing
precise details about who the supplier was.

## Installation
- Install [rust](https://rust-lang.org/tools/install) and
[RISC0](https://dev.risczero.com/api/zkvm/install), and then run `cargo build`
in the repository root.

## Running the demo
The process is as follows:
- Sign a mining licence
- Sign a product passport using the mining licence
- Prove fixed information about the mining licence
- Verify the proof

If the mining licence indicates that the company operates in a conflict zone
listed in the `conflict_zones.json` input file, they will not be able to
generate a zero-knowledge product passport that will be accepted by the
verifier.

Run the following in the repository root:
```bash
RISC0_DEV_MODE=true cargo run --bin tui 2>/dev/null
```

> [!CAUTION]
> If you do not use the `RISC0_DEV_MODE=true` parameter, a real proof will be
> computed, which takes around 30 minutes on a laptop.  You can kill the process
> by running `ps aux | grep cargo-risczero | grep -v grep | awk '{print $2}' | xargs kill -9`

Test data is provided in the `./test_data` directory.  Here, you can modify the
set of conflict zones.