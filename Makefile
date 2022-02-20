.PHONY: nzcp/nzcp.wasm circuits/nzcp.circom circuits/cbor.circom clean

all: node_modules circuits/nzcp.circom

test: node_modules circuits/nzcp.circom
	yarn exec mocha

sha256-var-circom.zip:
	curl -Lo $@ https://github.com/noway/sha256-var-circom/archive/refs/heads/main.zip
	
sha256-var-circom-main/: sha256-var-circom.zip
	unzip $<
	cd sha256-var-circom-main && make

circuits/nzcp.circom: circuits/cbor.circom  sha256-var-circom-main
	cpp -P circuits/nzcptpl.circom > circuits/nzcp.circom

circuits/cbor.circom: sha256-var-circom-main
	cpp -P circuits/cbortpl.circom > circuits/cbor.circom

node_modules/:
	yarn

clean:
	rm -rf sha256-var-circom.zip
	rm -rf sha256-var-circom-main
	rm -rf node_modules