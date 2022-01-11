"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verify = exports.decrypt = exports.generateJWT = void 0;
const jose_1 = require("jose");
const util_1 = require("util");
const SingpassMyinfoError_1 = require("./error/SingpassMyinfoError");
const Logger_1 = require("./Logger");
function generateJWT(clientId, openIdDiscovery, keyId, jwksSignPrivateKey, algorithm) {
    return __awaiter(this, void 0, void 0, function* () {
        let jwt;
        try {
            jwt = yield new jose_1.SignJWT({
                sub: clientId,
                aud: openIdDiscovery,
                iss: clientId,
            })
                .setProtectedHeader({
                typ: "JWT",
                alg: algorithm,
                kid: keyId,
            })
                .setIssuedAt()
                .setExpirationTime('2m')
                .sign(jwksSignPrivateKey);
        }
        catch (err) {
            Logger_1.logger.log(err);
            throw new SingpassMyinfoError_1.SingpassMyInfoError("test to generate JWT with sign key");
        }
        return jwt;
    });
}
exports.generateJWT = generateJWT;
function decrypt(prviateKey, jwe) {
    return __awaiter(this, void 0, void 0, function* () {
        const { plaintext } = yield jose_1.compactDecrypt(jwe, prviateKey);
        return new util_1.TextDecoder().decode(plaintext);
    });
}
exports.decrypt = decrypt;
function verify(publicKey, jws) {
    return __awaiter(this, void 0, void 0, function* () {
        const { payload } = yield jose_1.compactVerify(jws, publicKey);
        return new util_1.TextDecoder().decode(payload);
    });
}
exports.verify = verify;
//# sourceMappingURL=JoseUtil.js.map