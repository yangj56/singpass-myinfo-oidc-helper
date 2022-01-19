import { AxiosInstance, AxiosRequestConfig } from "axios";
import { importJWK, importPKCS8, JWTPayload, jwtVerify, KeyLike } from "jose";
import * as querystringUtil from "querystring";
import { createClient } from "../client/axios-client";
import { SingpassMyInfoError } from "../util/error/SingpassMyinfoError";
import { decrypt, generateJWT } from "../util/JoseUtil";
import { logger } from "../util/Logger";

export interface NDITokenResponse {
	access_token: string;
	token_type: string;
	id_token: string;
}

export type Supportedalgorithm = "ES256" | "ES384" | "ES512";

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

export class NdiOidcHelper {
	private axiosClient: AxiosInstance = createClient({
		timeout: 10000,
	});

	private tokenUrl: string;
	private clientID: string;
	private redirectUri: string;
	private algorithm: Supportedalgorithm;
	private jwsKid: string;
	private jwsVerifyKeyString: string;
	private jweDecryptKeyString: string;
	private jwsVerifyKey: KeyLike;
	private jweDecryptKey: KeyLike;
	private singpassOpenIdDiscoveryUrl: string;
	private singpassJWKSUrl: string;
	private additionalHeaders?: Record<string, string>;

	constructor(props: NdiOidcHelperConstructor) {
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

	public async initialize() {
		try {
			this.jweDecryptKey = await importPKCS8(this.jweDecryptKeyString, this.algorithm);
			this.jwsVerifyKey = await importPKCS8(this.jwsVerifyKeyString, this.algorithm);
		} catch (err) {
			logger.error(err);
			throw new SingpassMyInfoError("Unable to load jwe and/or jws key");
		}
	}

	public getTokens = async (
		authCode: string,
		axiosRequestConfig?: AxiosRequestConfig
	): Promise<NDITokenResponse> => {
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
		const response = await this.axiosClient.post<NDITokenResponse>(
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

	public async getIdTokenPayload(tokens: NDITokenResponse, nonce: string) {
		try {
			const { id_token } = tokens;
			const decryptedJwe = await decrypt(this.jweDecryptKey, id_token);
			logger.info(decryptedJwe);
			return await this.verifyToken(decryptedJwe, nonce);
		} catch (e) {
			logger.error("Failed to get token payload", e);
			throw new SingpassMyInfoError("Failed to get token payload");
		}
	}

	public extractNricAndUuidFromPayload(payload: JWTPayload): {
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

	private getClientAssertionJWT = async () => {
		return await generateJWT(
			this.clientID,
			this.singpassOpenIdDiscoveryUrl,
			this.jwsKid,
			this.jwsVerifyKey,
			this.algorithm
		);
	};

	private async verifyToken(token: string, nonce: string) {
		const singpassPublicKey = await this.obtainSingpassPublicKey("sig");
		const { payload } = await jwtVerify(token, singpassPublicKey);
		if (!payload || payload.nonce !== nonce) {
			throw new Error("Failed to verify the nonce");
		}
		return payload;
	}

	private async obtainSingpassPublicKey(type: "sig" | "enc") {
		const singpassJWKResponse = await this.axiosClient.get(
			this.singpassJWKSUrl
		);
		const singpassJWS = singpassJWKResponse.data.keys.find(
			(x: { use: string }) => x.use === type
		);
		const singpassSigPublicKey = await importJWK(singpassJWS, "ES512");
		if (!singpassSigPublicKey) {
			throw new Error(`Singpass public ${type} key is not found`);
		}
		return singpassSigPublicKey;
	}

	public _testExports = {
		singpassClient: this.axiosClient,
	};
}
