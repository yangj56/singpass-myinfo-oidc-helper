import { AxiosInstance, AxiosRequestConfig } from "axios";
export interface NDITokenResponse {
    access_token: string;
    token_type: string;
    id_token: string;
}
export declare type SupportedAlgorithm = "ES256" | "ES384" | "ES512";
export interface NdiOidcHelperConstructor {
    tokenUrl: string;
    clientID: string;
    redirectUri: string;
    singpassJWKSUrl: string;
    algorithmn: SupportedAlgorithm;
    jwsKid: string;
    jwsPrivateKey: string;
    jwePrivateKey: string;
    additionalHeaders?: Record<string, string>;
}
export declare class NdiOidcHelper {
    private axiosClient;
    private tokenUrl;
    private clientID;
    private redirectUri;
    private algorithm;
    private jwsKid;
    private jwsKey;
    private jweKey;
    private singpassJWKSUrl;
    private additionalHeaders?;
    constructor(props: NdiOidcHelperConstructor);
    private importKeys;
    getClientAssertionJWT: () => Promise<string>;
    getTokens: (authCode: string, axiosRequestConfig?: AxiosRequestConfig) => Promise<NDITokenResponse>;
    getIdTokenPayload(tokens: NDITokenResponse, nonce: string): Promise<import("jose").JWTPayload>;
    private verifyToken;
    private obtainSingpassPublicKey;
    _testExports: {
        singpassClient: AxiosInstance;
    };
}
//# sourceMappingURL=ndi-singpass-helper.d.ts.map