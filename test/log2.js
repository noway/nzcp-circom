const chai = require("chai");
const { wasm: wasm_tester } = require("circom_tester");

const assert = chai.assert;

describe("CBOR getType", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/log2_test.circom`);
    })
    it ("log2 works", async () => {
        // exhaustive test for 8 bits
        const witness = await cir.calculateWitness({}, true);
    });
});