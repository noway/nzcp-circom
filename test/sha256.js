const chai = require("chai");
const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const {buffer2bitArray, bitArray2buffer, arrayChunk, padMessage} = require("./helpers/utils");
const assert = chai.assert;
const Sha256 = require('./helpers/sha256')

function genSha256Inputs(input, nCount, nWidth = 512, inParam = "in") {
    var segments = arrayChunk(padMessage(buffer2bitArray(Buffer.from(input))), nWidth);
    const tBlock = segments.length / (512 / nWidth);
    
    if(segments.length < nCount) {
        segments = segments.concat(Array(nCount-segments.length).fill(Array(nWidth).fill(0)));
    }
    
    if(segments.length > nCount) {
        throw new Error('Padded message exceeds maximum blocks supported by circuit');
    }
    
    return { segments, "tBlock": tBlock }; 
}

function msgToBitsAs1Block(msg) {
    let inn = buffer2bitArray(Buffer.from(msg))
    const add_bits = 512 - inn.length
    inn = inn.concat(Array(add_bits).fill(0));
    return inn
}

function msgToBitsAs2Blocks(msg) {
    let inn = buffer2bitArray(Buffer.from(msg))
    const add_bits = 1024 - inn.length
    inn = inn.concat(Array(add_bits).fill(0));
    return inn
}

describe("Sha256", function () {
    this.timeout(100000);

    /*
    it ("Should generate hash for 1 block", async () => {
        const p = path.join(__dirname, "../", "circuits", "sha256Block1_test.circom")
        const cir = await wasm_tester(p);

        const message = "Jack,Sparrow,1960-04-16"
        const input = genSha256Inputs(message, 1);
        const len = message.length;
        
        const witness = await cir.calculateWitness({ "in": input.segments[0], len }, true);

        const arrOut = witness.slice(1, 257);
        const hash2 = bitArray2buffer(arrOut).toString("hex");

        assert.equal(hash2,Sha256.hash(message))
    });
    */

    // TODO: into a separate test
    /*
    it ("Should generate hash for 1 block", async () => {
        const p = path.join(__dirname, "../", "circuits", "sha256Block1_test.circom")
        const cir = await wasm_tester(p);

        for(let i=0; i<56; i++) {

            const message = Array(i).fill("a").join("")
            const len = message.length;
            console.log("message", message, len)

            // let inn = buffer2bitArray(Buffer.from(message))
            // const add_bits = 512-inn.length
            // inn = inn.concat(Array(add_bits).fill(0));
            const inn = msgToBitsAs1Block(message)

            const witness = await cir.calculateWitness({ "in": inn, len }, true);

            const arrOut = witness.slice(1, 257);
            const hash2 = bitArray2buffer(arrOut).toString("hex");

            assert.equal(hash2,Sha256.hash(message))
        }

    });
    */


    it ("Should generate hash for 2 blocks", async () => {
        const p = path.join(__dirname, "../", "circuits", "sha256Block2_test.circom")
        const cir = await wasm_tester(p);

        const message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        // const input = genSha256Inputs(message, 2);
        // console.log('input.segments[0]',bitArray2buffer(input.segments[0]).toString('hex'))
        // console.log('input.segments[1]',bitArray2buffer(input.segments[1]).toString('hex'))
        const len = message.length;
        const inn = msgToBitsAs2Blocks(message)
        
        const witness = await cir.calculateWitness({ "in": inn, len }, true);

        const arrOut = witness.slice(1, 257);
        const actualHash = bitArray2buffer(arrOut).toString("hex");
        const expectedHash = Sha256.hash(message)
        
        assert.equal(actualHash, expectedHash)
    });
});