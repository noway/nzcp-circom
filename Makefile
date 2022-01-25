.PHONY: multiplier2/multiplier2.wasm

public.json: multiplier2/multiplier2.wasm
	cd multiplier2_js && node generate_witness.js multiplier2.wasm ../input.json witness.wtns
	snarkjs groth16 prove multiplier2_0001.zkey multiplier2_js/witness.wtns proof.json public.json

multiplier2/multiplier2.wasm: circomlib-master
	circom multiplier2.circom --wasm

circom.zip:
	curl -Lo circomlib.zip https://github.com/iden3/circomlib/archive/refs/heads/master.zip

circomlib-master/: circom.zip
	unzip circomlib.zip
