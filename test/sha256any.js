const chai = require("chai");
const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const {buffer2bitArray, bitArray2buffer, arrayChunk, padMessage} = require("./helpers/utils");
const assert = chai.assert;
const Sha256 = require('./helpers/sha256')

function msgToBits(msg) {
    let inn = buffer2bitArray(Buffer.from(msg))
    // const blocks = Math.floor((inn.length + 64) / 512) + 1
    const blocks = 4;
    const overall_len = blocks * 512
    const add_bits = overall_len - inn.length
    inn = inn.concat(Array(add_bits).fill(0));
    return inn
}

describe("Sha256", function () {
    this.timeout(1000000000);

    // TODO: into a separate test
    it ("Should generate hash for 1-4 blocks", async () => {
        const p = path.join(__dirname, "../", "circuits", "sha256Any_test.circom")
        const cir = await wasm_tester(p);

        for(let i=0; i<248; i++) {

            const message = Array(i).fill("a").join("")
            const len = message.length * 8;
            console.log("message", message, len, len / 8)

            const inn = msgToBits(message)

            const witness = await cir.calculateWitness({ "in": inn, len }, true);

            const arrOut = witness.slice(1, 257);
            const hash2 = bitArray2buffer(arrOut).toString("hex");

            assert.equal(hash2,Sha256.hash(message))
        }

    });


});