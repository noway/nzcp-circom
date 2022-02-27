const chai = require("chai");
const { wasm: wasm_tester } = require("circom_tester");
const chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
const { assert } = chai;


describe("QuinSelector", function () {
    let cir0
    let cir1
    let cir2
    let cir3
    let cir4
    let cir5
    before(async () => {
        cir0 = await wasm_tester(`${__dirname}/../circuits/quinSelector0_test.circom`);
        cir1 = await wasm_tester(`${__dirname}/../circuits/quinSelector1_test.circom`);
        cir2 = await wasm_tester(`${__dirname}/../circuits/quinSelector2_test.circom`);
        cir3 = await wasm_tester(`${__dirname}/../circuits/quinSelector3_test.circom`);
        cir4 = await wasm_tester(`${__dirname}/../circuits/quinSelector4_test.circom`);
        cir5 = await wasm_tester(`${__dirname}/../circuits/quinSelector5_test.circom`);
    })
    it ("QuinSelector(0) select from array []", async () => {
        const index = -1;
        const inArray = [];
        const witness = await cir0.calculateWitness({ in: inArray, index }, true);
        assert.equal(witness[1], 0);    
    });
    it ("QuinSelector(1) select from array [1]", async () => {
        const index = 0;
        const inArray = [1]
        const witness = await cir1.calculateWitness({ in: inArray, index }, true);
        assert.equal(witness[1], inArray[index]);    
    });
    it ("QuinSelector(2) select from array [1, 2]", async () => {
        for (let index = 0; index < 2; index++) {
            const inArray = [1, 2]
            const witness = await cir2.calculateWitness({ in: inArray, index }, true);
            assert.equal(witness[1], inArray[index]);    
        }
    });
    it ("QuinSelector(3) select from array [1, 2, 3]", async () => {
        for (let index = 0; index < 3; index++) {
            const inArray = [1, 2, 3]
            const witness = await cir3.calculateWitness({ in: inArray, index }, true);
            assert.equal(witness[1], inArray[index]);    
        }
    });
    it ("QuinSelector(4) select from array [1, 2, 3, 4]", async () => {
        for (let index = 0; index < 4; index++) {
            const inArray = [1, 2, 3, 4]
            const witness = await cir4.calculateWitness({ in: inArray, index }, true);
            assert.equal(witness[1], inArray[index]);    
        }
    });
    it ("QuinSelector(5) select from array [1, 2, 3, 4, 5]", async () => {
        for (let index = 0; index < 5; index++) {
            const inArray = [1, 2, 3, 4, 5]
            const witness = await cir5.calculateWitness({ in: inArray, index }, true);
            assert.equal(witness[1], inArray[index]);    
        }
    });
    it ("QuinSelector(1) should throw on 1 index", async () => {
        const index = 1;
        const inArray = [1]
        await assert.isRejected(cir1.calculateWitness({ in: inArray, index }, true))
    });
    it ("QuinSelector(2) should throw on 2 index", async () => {
        const index = 2;
        const inArray = [1, 2]
        await assert.isRejected(cir2.calculateWitness({ in: inArray, index }, true))
    });
    it ("QuinSelector(3) should throw on 3 index", async () => {
        const index = 3;
        const inArray = [1, 2, 3]
        await assert.isRejected(cir3.calculateWitness({ in: inArray, index }, true))
    });
    it ("QuinSelector(4) should throw on 4 index", async () => {
        const index = 4;
        const inArray = [1, 2, 3, 4]
        await assert.isRejected(cir4.calculateWitness({ in: inArray, index }, true))
    });
    it ("QuinSelector(5) should throw on 5 index", async () => {
        const index = 5;
        const inArray = [1, 2, 3, 4, 5]
        await assert.isRejected(cir5.calculateWitness({ in: inArray, index }, true))
    });
});
