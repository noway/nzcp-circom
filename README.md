# NZCP.circom

ZK-proof of [NZ COVID Pass](https://github.com/minhealthnz/nzcovidpass-spec) identity written in [Circom](https://github.com/iden3/circom).

This circuit allows users to prove that they are a holder of the NZ COVID Pass without revealing their identity.

## How it works

The circuit takes in the following private inputs:
- `toBeSigned` - the `ToBeSigned` value of NZ COVID Pass as per https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
- `toBeSignedLen` - the length of `toBeSigned`


The circuit outputs the following public inputs:
- `credSubjSha256` - the SHA256 hash of the credential subject of the NZ COVID Pass. That is your given name, family name and date of birth delimited by comma. 
- `toBeSignedSha256` - the SHA256 hash of the `toBeSigned` value.
- `exp` - The expiry date of the NZ COVID Pass.