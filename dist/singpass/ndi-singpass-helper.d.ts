import { AxiosInstance, AxiosRequestConfig } from "axios";
import { TokenPayload, TokenResponse } from "./singpass-helper";
export declare type SupportedAlgorithm = "ES256" | "ES384" | "ES512";
export interface NdiOidcHelperConstructor {
    authorizationUrl: string;
    logoutUrl?: string;
    tokenUrl: string;
    clientID: string;
    redirectUri: string;
    singpassJWKSUrl: string;
    algorithmn: SupportedAlgorithm;
    jwsKid: string;
    jwsPrivateKey: string;
    jweKid: string;
    jwePrivateKey: string;
    /**
     * Headers already added by the client:
     * Content-Type, Cookie (refreshSession, logoutOfSession)
     */
    additionalHeaders?: Record<string, string>;
}
export declare class NdicOidcHelper {
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
    importKeys(jweKey: string, jwsKey: string, algorithmn: SupportedAlgorithm): Promise<void>;
    getClientAssertionJWT: () => Promise<string>;
    getTokens: (authCode: string, axiosRequestConfig?: AxiosRequestConfig) => Promise<TokenResponse>;
    /**
     * Decrypts the ID Token JWT inside the TokenResponse to get the payload
     * Use extractNricAndUuidFromPayload on the returned Token Payload to get the NRIC and UUID
     */
    getIdTokenPayload(tokens: TokenResponse, nonce: string): Promise<void>;
    verifyToken(token: string, nonce: string): Promise<void>;
    private obtainSingpassPublicKey;
    /**
     * Returns the nric and uuid from the token payload
     */
    extractNricAndUuidFromPayload(payload: TokenPayload): {
        nric: string;
        uuid: string;
    };
    private validateStatus;
    _testExports: {
        singpassClient: AxiosInstance;
        validateStatusFn: (status: any) => boolean;
    };
}
//# sourceMappingURL=ndi-singpass-helper.d.ts.map