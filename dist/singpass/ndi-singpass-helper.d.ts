import { AxiosInstance, AxiosRequestConfig } from "axios";
import { JWTPayload } from "jose";
export interface NDITokenResponse {
    access_token: string;
    token_type: string;
    id_token: string;
}
export declare type Supportedalgorithm = "ES256" | "ES384" | "ES512";
export interface NdiOidcHelperConstructor {
    tokenUrl: string;
    clientID: string;
    redirectUri: string;
    singpassOpenIdDiscoveryUrl: string;
    singpassJWKSUrl: string;
    algorithm: Supportedalgorithm;
    jwsKid: string;
    jwsVerifyKey: string;
    jweDecryptKey: string;
    additionalHeaders?: Record<string, string>;
}
export declare class NdiOidcHelper {
    private axiosClient;
    private tokenUrl;
    private clientID;
    private redirectUri;
    private algorithm;
    private jwsKid;
    private jwsVerifyKeyString;
    private jweDecryptKeyString;
    private jwsVerifyKey;
    private jweDecryptKey;
    private singpassOpenIdDiscoveryUrl;
    private singpassJWKSUrl;
    private additionalHeaders?;
    constructor(props: NdiOidcHelperConstructor);
    initialize(): Promise<void>;
    getTokens: (authCode: string, axiosRequestConfig?: AxiosRequestConfig) => Promise<NDITokenResponse>;
    getIdTokenPayload(tokens: NDITokenResponse, nonce: string): Promise<JWTPayload>;
    extractNricAndUuidFromPayload(payload: JWTPayload): {
        nric: string;
        uuid: string;
    };
    private getClientAssertionJWT;
    private verifyToken;
    private obtainSingpassPublicKey;
    _testExports: {
        singpassClient: AxiosInstance;
    };
}
//# sourceMappingURL=ndi-singpass-helper.d.ts.map