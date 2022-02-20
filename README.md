# NZCP.circom

ZK proof of [NZ COVID Pass](https://github.com/minhealthnz/nzcovidpass-spec) identity written in [Circom](https://github.com/iden3/circom).

This circuit allows users to prove that they are a holder of the NZ COVID Pass without revealing their identity.

## How it works

The circuit takes in the following private inputs:
- `toBeSigned` - the `ToBeSigned` value of NZ COVID Pass as per https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
- `toBeSignedLen` - the length of `toBeSigned`


The circuit outputs the following public inputs:
- `credSubjSha256` - the SHA256 hash of the credential subject of the NZ COVID Pass. That is your given name, family name and date of birth delimited by comma. 
- `toBeSignedSha256` - the SHA256 hash of the `toBeSigned` value.
- `exp` - the expiry date of the NZ COVID Pass.

## NZ COVID Pass verification
The circuit does not verify the signature of the NZ COVID Pass. It merely proves that an identity is associated with the NZ COVID Pass, be it signed or unsigned. The user may not be in a possession of a valid signature for the `ToBeSigned` value that is provided.

While it is theoretically possbile to verify the signature (using a circuit similar to [circom-ecdsa](https://github.com/0xPARC/circom-ecdsa) for NIST P-256 curves), it is outside the scope of this project.

## Limitations
For live passes:
- The length of the `ToBeSigned` value is limited to 355 bytes.
- The length of the credential subject string (defined as `${familyName},${givenName},${dob}`) is limited to 64 bytes.

## Tests
- Create `.env` file in the root directory of the project
- Populate it with at least 1 live pass URI. 
    - Use `.env.example` as a reference.
- Run `make test`

## Usage
See the [test/nzcp.js](test/nzcp.js) file for usage examples.

## Roadmap
Depending on my availability:
- Optimize the size and compile time of the circuit
- Add more tests
