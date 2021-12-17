export declare enum HttpMethod {
    GET = "GET",
    POST = "POST"
}
/**
 * Generate the Authorization header for requests to V3 MyInfo
 * @param url
 * @param queryParams
 * @param method
 * @param appId
 * @param signingKey
 * @param signingKeyPassphrase
 */
export declare function generateMyInfoAuthorizationHeader(url: string, queryParams: {
    [key: string]: any;
}, method: HttpMethod, appId: string, signingKey: string, nonce?: number, timestamp?: number, signingKeyPassphrase?: string): string;
//# sourceMappingURL=SigningUtil.d.ts.map