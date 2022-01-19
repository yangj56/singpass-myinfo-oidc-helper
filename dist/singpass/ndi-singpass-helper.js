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
exports.NdiOidcHelper = void 0;
const jose_1 = require("jose");
const querystringUtil = require("querystring");
const axios_client_1 = require("../client/axios-client");
const SingpassMyinfoError_1 = require("../util/error/SingpassMyinfoError");
const JoseUtil_1 = require("../util/JoseUtil");
const Logger_1 = require("../util/Logger");
class NdiOidcHelper {
    constructor(props) {
        this.axiosClient = axios_client_1.createClient({
            timeout: 10000,
        });
        this.getTokens = (authCode, axiosRequestConfig) => __awaiter(this, void 0, void 0, function* () {
            const clientAssertionJWT = yield this.getClientAssertionJWT();
            const params = {
                grant_type: "authorization_code",
                code: authCode,
                client_id: this.clientID,
                client_assertion: clientAssertionJWT,
                redirect_uri: this.redirectUri,
                client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            };
            const body = querystringUtil.stringify(params);
            const config = Object.assign({ headers: Object.assign(Object.assign({}, this.additionalHeaders), { "content-type": "application/x-www-form-urlencoded" }) }, axiosRequestConfig);
            const response = yield this.axiosClient.post(this.tokenUrl, body, config);
            if (!response.data.id_token) {
                Logger_1.logger.error("Failed to get ID token: invalid response data", response.data);
                throw new SingpassMyinfoError_1.SingpassMyInfoError("Failed to get ID token");
            }
            return response.data;
        });
        this.getClientAssertionJWT = () => __awaiter(this, void 0, void 0, function* () {
            return yield JoseUtil_1.generateJWT(this.clientID, this.singpassOpenIdDiscoveryUrl, this.jwsKid, this.jwsVerifyKey, this.algorithm);
        });
        this._testExports = {
            singpassClient: this.axiosClient,
        };
        this.tokenUrl = props.tokenUrl;
        this.clientID = props.clientID;
        this.redirectUri = props.redirectUri;
        this.singpassOpenIdDiscoveryUrl = props.singpassOpenIdDiscoveryUrl;
        this.singpassJWKSUrl = props.singpassJWKSUrl;
        this.algorithm = props.algorithm;
        this.jwsKid = props.jwsKid;
        this.jweDecryptKeyString = props.jweDecryptKey;
        this.jwsVerifyKeyString = props.jwsVerifyKey;
        this.additionalHeaders = props.additionalHeaders || {};
    }
    initialize() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                this.jweDecryptKey = yield jose_1.importPKCS8(this.jweDecryptKeyString, this.algorithm);
                this.jwsVerifyKey = yield jose_1.importPKCS8(this.jwsVerifyKeyString, this.algorithm);
            }
            catch (err) {
                Logger_1.logger.error(err);
                throw new SingpassMyinfoError_1.SingpassMyInfoError("Unable to load jwe and/or jws key");
            }
        });
    }
    getIdTokenPayload(tokens, nonce) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const { id_token } = tokens;
                const decryptedJwe = yield JoseUtil_1.decrypt(this.jweDecryptKey, id_token);
                Logger_1.logger.info(decryptedJwe);
                return yield this.verifyToken(decryptedJwe, nonce);
            }
            catch (e) {
                Logger_1.logger.error("Failed to get token payload", e);
                throw new SingpassMyinfoError_1.SingpassMyInfoError("Failed to get token payload");
            }
        });
    }
    extractNricAndUuidFromPayload(payload) {
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
    verifyToken(token, nonce) {
        return __awaiter(this, void 0, void 0, function* () {
            const singpassPublicKey = yield this.obtainSingpassPublicKey("sig");
            const { payload } = yield jose_1.jwtVerify(token, singpassPublicKey);
            if (!payload || payload.nonce !== nonce) {
                throw new Error("Failed to verify the nonce");
            }
            return payload;
        });
    }
    obtainSingpassPublicKey(type) {
        return __awaiter(this, void 0, void 0, function* () {
            const singpassJWKResponse = yield this.axiosClient.get(this.singpassJWKSUrl);
            const singpassJWS = singpassJWKResponse.data.keys.find((x) => x.use === type);
            const singpassSigPublicKey = yield jose_1.importJWK(singpassJWS, "ES512");
            if (!singpassSigPublicKey) {
                throw new Error(`Singpass public ${type} key is not found`);
            }
            return singpassSigPublicKey;
        });
    }
}
exports.NdiOidcHelper = NdiOidcHelper;
//# sourceMappingURL=ndi-singpass-helper.js.map