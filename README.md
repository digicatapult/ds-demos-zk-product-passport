# Supply Chain Proof Demo

This demo is a modified version of the risc0 example for JWT verification from
the main risc0 repository
[https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs](https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs)

## Proof scenario
A user wants to prove that they have a JWT signed by one of a number of possible
keys, but they do not want to reveal which (perhaps the customers have required
that they must not share this information).

The signed JWT attests to the fact that the supplier shipped `1000` units of
product to the customer, and attests to their DID.

The public inputs to the proof are:
- A number of public keys, corresponding to potential customers.
- Some subset of claims stated by the JWT.  In this example, we have defined
  custom claims that record the DID associated with the supplier and the amount
  of product that they shipped.

The private inputs to the proof are:
- The JWT (which includes metadata linking the signature to the consumer) 

The proof proves the statement: 'This JWT was signed by one of three possible
input keys and records that a shipment of size 1000 was sent'.

The choice to use three keys is arbitrary: it is trivial to extend this to more
keys.

## Installation
Install rust.

## Running the demo
### Generate a token
Run `cargo run --release --bin gen test_sk.json issued_token.jwt`.  This will
generate a JWT signed using a secret key built into the binary, which is written
to the filesystem as `./issued_token.jwt`.  The corresponding public key is
provided as input to the proving routine, along with two other 'fake' public
keys.

The JWT has custom fields that can be modified in `./core/src/lib.rs` if
desirable (with necessary changes propagated throughout the repository).

### Prove the statement
Run `RISC0_DEV_MODE=0 cargo run --release --bin prove issued_token.jwt
test_pk.json pk_other.json pk_other_2.json ...` which will create the proof.
(Two or more public keys are required.) This will likely take a long time and
use lots of RAM/swap.  The 'receipt' is stored in `./receipt.bin`, which will be
ingested by the verifier.

This process compiles a binary
`./target/riscv32im-risc0-zkvm-elf/verify_token_with_some_key.bin` of RISC-V-ish
bytecode.  This binary is the compilation of the code in `./methods/guest`.  The
ZKVM then proves its honest execution.

In other words, the proof proves that the code in `./methods/guest/src` is
honestly executed.  It should therefore not contain secret data compiled into
it, since this is the 'circuit' the verifier will see when proving; secret data
should be passed in from the host, along with any other per-proof
parameters (in this example, three choices of public key).

The journal is the public data associated with the proof and is included in the
receipt.  The prover commits information to the journal to make claims about
what was computed.  Since this committing action is part of the execution that
is proved correct, the prover cannot perform operations on dummy data claiming
it was the real data.  Committing data to the journal is needed to allow the
prover to assert what data was passed in from the host.

### Verify the proof
Run `RISC0_DEV_MODE=0 cargo run --release --bin verify receipt.bin` to verify the
proof. 