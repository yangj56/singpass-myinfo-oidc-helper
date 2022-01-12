"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractNricAndUuidFromPayload = exports.isBase64Valid = exports.replaceLineBreaks = void 0;
const isBase64 = require("is-base64");
function replaceLineBreaks(input) {
    if (!input) {
        return input;
    }
    return input.replace(/\\n/g, "\n");
}
exports.replaceLineBreaks = replaceLineBreaks;
function isBase64Valid(test) {
    return isBase64(test, { paddingRequired: false });
}
exports.isBase64Valid = isBase64Valid;
function extractNricAndUuidFromPayload(payload) {
    const { sub } = payload;
    if (sub) {
        const extractionRegex = /s=([STFG]\d{7}[A-Z]).*,u=(.*)/i;
        const matchResult = sub.match(extractionRegex);
        if (!matchResult) {
            throw Error("Token payload sub property is invalid, does not contain valid NRIC and uuid string");
        }
        const nric = matchResult[1];
        const uuid = matchResult[2];
        return { nric, uuid };
    }
    throw Error("Token payload sub property is not defined");
}
exports.extractNricAndUuidFromPayload = extractNricAndUuidFromPayload;
//# sourceMappingURL=StringUtil.js.map