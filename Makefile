.PHONY: nzcp/nzcp.wasm circuits/nzcp.circom circuits/cbor.circom

public.json: nzcp/nzcp.wasm
	cd nzcp_js && node generate_witness.js nzcp.wasm ../input.json witness.wtns
	snarkjs groth16 prove nzcp_0001.zkey nzcp_js/witness.wtns proof.json public.json

nzcp/nzcp.wasm: circomlib-master
	circom circuits/nzcp.circom --wasm --sym

circom.zip:
	curl -Lo circomlib.zip https://github.com/iden3/circomlib/archive/refs/heads/master.zip

circomlib-master/: circom.zip
	unzip circomlib.zip

sha256-var-circom.zip:
	curl -Lo $@ https://github.com/noway/sha256-var-circom/archive/refs/heads/main.zip
	
sha256-var-circom-main/: sha256-var-circom.zip
	unzip $<
	cd sha256-var-circom-main && make

circuits/nzcp.circom: circuits/cbor.circom  sha256-var-circom-main
	cpp -P circuits/nzcptpl.circom | sed 's/##//g' > circuits/nzcp.circom

circuits/cbor.circom: circomlib-master
	cpp -P circuits/cbortpl.circom | sed 's/##//g' > circuits/cbor.circom