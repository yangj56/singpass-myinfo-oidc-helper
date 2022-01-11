import { KeyLike } from "jose";
export declare function generateJWT(clientId: string, openIdDiscovery: string, keyId: string, jwksSignPrivateKey: KeyLike, algorithm: "ES256" | "ES384" | "ES512"): Promise<string>;
export declare function decrypt(prviateKey: KeyLike | Uint8Array, jwe: string): Promise<string>;
export declare function verify(publicKey: KeyLike | Uint8Array, jws: string): Promise<string>;
//# sourceMappingURL=JoseUtil.d.ts.map