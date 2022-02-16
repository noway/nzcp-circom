const chai = require("chai");
const path = require("path");
const assert = chai.assert;

const wasm_tester = require("circom_tester").wasm;

const {buffer2bitArray, bitArray2buffer} = require("./helpers/utils");


describe("CBOR getType", function () {
    const p = path.join(__dirname, "../circuits/log2_test.circom")
    it ("log2 works", async () => {
        // exhaustive test for 8 bits
        const cir = await wasm_tester(p);
        // for (let v = 255; v >= 0; v--) {
            const witness = await cir.calculateWitness({  }, true);
            // assert.equal(witness[1], v >> 5);
        // }
    });
});