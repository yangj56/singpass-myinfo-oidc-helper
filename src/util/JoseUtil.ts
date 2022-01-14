import { compactDecrypt, KeyLike, SignJWT } from "jose";
import { TextDecoder } from "util";
import { logger } from "./Logger";

export async function generateJWT(
	clientId: string,
	openIdDiscovery: string,
	keyId: string,
	jwksSignPrivateKey: KeyLike,
	algorithm: "ES256" | "ES384" | "ES512"
) {
	let jwt: string;
	try {
		jwt = await new SignJWT({
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
	} catch (err) {
		logger.log(err);
		throw new Error("Unable to generate JWT with sign key");
	}
	return jwt;
}

export async function decrypt(prviateKey: KeyLike | Uint8Array, jwe: string) {
	const { plaintext } = await compactDecrypt(jwe, prviateKey);
	return new TextDecoder().decode(plaintext);
}
