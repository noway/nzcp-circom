
var MAJOR_TYPE_INT = 0
var MAJOR_TYPE_NEGATIVE_INT = 1
var MAJOR_TYPE_BYTES = 2
var MAJOR_TYPE_STRING = 3
var MAJOR_TYPE_ARRAY = 4
var MAJOR_TYPE_MAP = 5
var MAJOR_TYPE_TAG = 6

function encodeUint(val) {
    if (val <= 23) {
        return [val];
    }
    else if (val >= 24 && val <= 0xFF) {
        return [24, val];
    }
    else if (val > 0xFF && val <= 0xFFFF) {
        return [25, val >> 8, val & 255];
    }
    else if (val > 0xFFFF && val <= 0xFFFFFFFF) {
        return [26, Number(BigInt(val) >> 24n), (val >> 16) & 255, (val >> 8) & 255, val & 255];
    }
    else if (val > 0xFFFFFFFF && val <= 0xFFFFFFFFFFFFFFFFn) {
        return [27, val >> 56, (val >> 48) & 255, (val >> 40) & 255, (val >> 32) & 255, (val >> 24) & 255, (val >> 16) & 255, (val >> 8) & 255, val & 255];
    }
    else {
        throw new Error('Value too large');
    }
}

function encodeInt(val) {
    const [x, ...rest] = encodeUint(val);
    return [(MAJOR_TYPE_INT << 5) | x, ...rest];
}

function encodeString(str) {
    const [x, ...rest] = encodeUint(str.length);
    return [(MAJOR_TYPE_STRING << 5) | x, ...rest, ...stringToArray(str)];
}

function stringToArray(str) {
    return str.split('').map(c => c.charCodeAt(0));
}

function encodeArray(arr) {
    const [x, ...rest] = encodeUint(arr.length);
    return [(MAJOR_TYPE_ARRAY << 5) | x, ...rest, ...arr.flat()];
}

function encodeMap(obj) {
    const [x, ...rest] = encodeUint(Object.keys(obj).length);
    return [(MAJOR_TYPE_MAP << 5) | x, ...rest, ...Object.entries(obj).map(entry => [parseInt(entry[0], 10), entry[1]].flat()).flat()];
}

function padArray(arr, len) {
    const extraZeroes = Math.max(len - arr.length, 0);
    return [...arr, ...Array(extraZeroes).fill(0)];
}

module.exports = {
    encodeUint,
    encodeInt,
    encodeString,
    stringToArray,
    encodeArray,
    encodeMap,
    padArray,
}