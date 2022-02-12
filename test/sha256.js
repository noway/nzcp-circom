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

function msgToBits(msg) {
    let inn = buffer2bitArray(Buffer.from(msg))
    const overall_len = inn.length < 448 ? 512 : (inn.length < 960 ? 1024 : 1536)
    const add_bits = overall_len - inn.length
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

            const inn = msgToBits(message)

            const witness = await cir.calculateWitness({ "in": inn, len }, true);

            const arrOut = witness.slice(1, 257);
            const hash2 = bitArray2buffer(arrOut).toString("hex");

            assert.equal(hash2,Sha256.hash(message))
        }

    });


    it ("Should generate hash for 56-119 len", async () => {
        const p = path.join(__dirname, "../", "circuits", "sha256Block2_test.circom")
        const cir = await wasm_tester(p);

        for(let i=56; i<120; i++) {
            const message = Array(i).fill("a").join("")
            const len = message.length;
            const inn = msgToBits(message)
            console.log("message", message, len)
            
            const witness = await cir.calculateWitness({ "in": inn, len }, true);

            const arrOut = witness.slice(1, 257);
            const actualHash = bitArray2buffer(arrOut).toString("hex");
            const expectedHash = Sha256.hash(message)
            
            assert.equal(actualHash, expectedHash)
        }
    });
    */

    it ("Should generate hash for 120-183 len", async () => {
        const p = path.join(__dirname, "../", "circuits", "sha256Block3_test.circom")
        const cir = await wasm_tester(p);

        for(let i=120; i<183; i++) {
            const message = Array(i).fill("a").join("")
            const len = message.length;
            const inn = msgToBits(message)
            console.log("message", message, len)
            
            const witness = await cir.calculateWitness({ "in": inn, len }, true);

            const arrOut = witness.slice(1, 257);
            const actualHash = bitArray2buffer(arrOut).toString("hex");
            const expectedHash = Sha256.hash(message)
            
            assert.equal(actualHash, expectedHash)
        }
    });
});