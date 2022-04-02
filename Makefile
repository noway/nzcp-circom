.PHONY: circuits/nzcp.circom circuits/cbor.circom test clean

all: node_modules circuits/nzcp.circom circuits/nzcp_exampleTest.wasm circuits/nzcp_liveTest.wasm

circuits/nzcp_exampleTest.wasm:
	circom circuits/nzcp_exampleTest.circom --r1cs --wasm

circuits/nzcp_liveTest.wasm:
	circom circuits/nzcp_liveTest.circom --r1cs --wasm

test: node_modules circuits/nzcp.circom
	yarn exec mocha

sha256-var-circom.zip:
	curl -Lo $@ https://github.com/noway/sha256-var-circom/archive/refs/heads/main.zip
	
sha256-var-circom-main/: sha256-var-circom.zip
	unzip $<
	cd $@ && make

circuits/nzcp.circom: circuits/cbor.circom sha256-var-circom-main
	cpp -P circuits/nzcptpl.circom > $@

circuits/cbor.circom: sha256-var-circom-main
	cpp -P circuits/cbortpl.circom > $@

node_modules/:
	yarn

plonk:
	snarkjs plonk setup nzcp_exampleTest.r1cs powersOfTau28_hez_final_22.ptau nzcp_exampleTest_final.zkey
	snarkjs zkey export verificationkey nzcp_exampleTest_final.zkey verification_key.json
	snarkjs zkey export solidityverifier nzcp_exampleTest_final.zkey contracts/VerifierExample.sol

clean:
	rm -rf sha256-var-circom.zip
	rm -rf sha256-var-circom-main
	rm -rf node_modules