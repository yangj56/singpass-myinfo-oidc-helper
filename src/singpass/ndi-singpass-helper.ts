import { AxiosInstance, AxiosRequestConfig } from "axios";
import { importJWK, importPKCS8, KeyLike } from "jose";
import * as querystringUtil from "querystring";
import { createClient } from "../client/axios-client";
import { SingpassMyInfoError } from "../util/error/SingpassMyinfoError";
import { decrypt, generateJWT, verify } from "../util/JoseUtil";
import { logger } from "../util/Logger";
import { TokenPayload, TokenResponse } from "./singpass-helper";

export type SupportedAlgorithm = "ES256" | "ES384" | "ES512";

export interface NdiOidcHelperConstructor {
	authorizationUrl: string;
	logoutUrl?: string;
	tokenUrl: string;
	clientID: string;
	clientSecret: string;
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

export class NdicOidcHelper {
	private axiosClient: AxiosInstance = createClient({
		timeout: 10000,
	});

	private tokenUrl: string;
	private clientID: string;
	private redirectUri: string;
	private algorithm: SupportedAlgorithm;
	private jwsKid: string;
	private jwsKey: KeyLike;
	private jweKey: KeyLike;
	private singpassJWKSUrl: string;
	private additionalHeaders?: Record<string, string>;

	constructor(props: NdiOidcHelperConstructor) {
		this.tokenUrl = props.tokenUrl;
		this.clientID = props.clientID;
		this.redirectUri = props.redirectUri;
		this.algorithm = props.algorithmn;
		this.jwsKid = props.jwsKid;
		this.additionalHeaders = props.additionalHeaders || {};
		this.importKeys(props.jwePrivateKey, props.jwsPrivateKey, props.algorithmn);
	}

	public async importKeys(
		jweKey: string,
		jwsKey: string,
		algorithmn: SupportedAlgorithm
	) {
		this.jweKey = await importPKCS8(jweKey, algorithmn);
		this.jwsKey = await importPKCS8(jwsKey, algorithmn);
	}

	public getClientAssertionJWT = async () => {
		return await generateJWT(
			this.clientID,
			this.singpassJWKSUrl,
			this.jwsKid,
			this.jwsKey,
			this.algorithm
		);
	};

	public getTokens = async (
		authCode: string,
		axiosRequestConfig?: AxiosRequestConfig
	): Promise<TokenResponse> => {
		const clientAssertionJWT = await this.getClientAssertionJWT();
		const params = {
			grant_type: "authorization_code",
			code: authCode,
			client_id: this.clientID,
			client_assertion: clientAssertionJWT,
			redirect_uri: this.redirectUri,
			client_assertion_type:
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		};
		const body = querystringUtil.stringify(params);

		const config = {
			headers: {
				...this.additionalHeaders,
				"content-type": "application/x-www-form-urlencoded",
			},
			...axiosRequestConfig,
		};
		const response = await this.axiosClient.post<TokenResponse>(
			this.tokenUrl,
			body,
			config
		);
		if (!response.data.id_token) {
			logger.error(
				"Failed to get ID token: invalid response data",
				response.data
			);
			throw new SingpassMyInfoError("Failed to get ID token");
		}
		return response.data;
	};

	/**
	 * Decrypts the ID Token JWT inside the TokenResponse to get the payload
	 * Use extractNricAndUuidFromPayload on the returned Token Payload to get the NRIC and UUID
	 */
	public async getIdTokenPayload(tokens: TokenResponse, nonce: string) {
		try {
			const { id_token } = tokens;
			const decryptedJwe = await decrypt(this.jweKey, id_token);
			const verifiedJws = await this.verifyToken(decryptedJwe, nonce);
			return verifiedJws;
		} catch (e) {
			logger.error("Failed to get token payload", e);
			throw e;
		}
	}

	public async verifyToken(token: string, nonce: string) {
		const singpassPublicKey = await this.obtainSingpassPublicKey("sig");
		const verifiedIDTokenPayload = await verify(singpassPublicKey, token);
		if (verifiedIDTokenPayload !== nonce) {
			throw new SingpassMyInfoError("Failed to verify the nonce");
		}
	}

	private async obtainSingpassPublicKey(type: "sig" | "enc") {
		const singpassJWKResponse = await this.axiosClient.get(
			this.singpassJWKSUrl
		);
		const singpassJWS = singpassJWKResponse.data.keys.filter(
			(x: { use: string }) => x.use === type
		)[0];
		const singpassSigPublicKey = await importJWK(singpassJWS, "ES512");
		if (!singpassSigPublicKey) {
			throw new Error("Singpass public sig key is not found");
		}
		return singpassSigPublicKey;
	}

	/**
	 * Returns the nric and uuid from the token payload
	 */
	public extractNricAndUuidFromPayload(payload: TokenPayload): {
		nric: string;
		uuid: string;
	} {
		const { sub } = payload;

		if (sub) {
			const extractionRegex = /s=([STFG]\d{7}[A-Z]).*,u=(.*)/i;
			const matchResult = sub.match(extractionRegex);

			if (!matchResult) {
				throw Error(
					"Token payload sub property is invalid, does not contain valid NRIC and uuid string"
				);
			}

			const nric = matchResult[1];
			const uuid = matchResult[2];

			return { nric, uuid };
		}

		throw Error("Token payload sub property is not defined");
	}

	private validateStatus(status) {
		return status === 302 || (status >= 200 && status < 300);
	}

	public _testExports = {
		singpassClient: this.axiosClient,
		validateStatusFn: this.validateStatus,
	};
}
