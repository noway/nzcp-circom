const { assert } = require("chai");
const { wasm: wasm_tester } = require("circom_tester");

describe("pow function", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/pow_test.circom`);
    })
    it ("pow works", async () => {
        const witness = await cir.calculateWitness({}, true);
    });
});