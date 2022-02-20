const chai = require("chai");
const path = require("path");
const { wasm: wasm_tester } = require("circom_tester");

const assert = chai.assert;

describe("CBOR getType", function () {
    const p = path.join(__dirname, "../circuits/log2_test.circom")
    it ("log2 works", async () => {
        // exhaustive test for 8 bits
        const cir = await wasm_tester(p);
        const witness = await cir.calculateWitness({  }, true);
    });
});