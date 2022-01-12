import { AxiosInstance, AxiosRequestConfig } from "axios";
import { importJWK, importPKCS8, jwtVerify, KeyLike } from "jose";
import * as querystringUtil from "querystring";
import { createClient } from "../client/axios-client";
import { SingpassMyInfoError } from "../util/error/SingpassMyinfoError";
import { decrypt, generateJWT } from "../util/JoseUtil";
import { logger } from "../util/Logger";
import { TokenPayload } from "./singpass-helper";

export interface NDITokenResponse {
	access_token: string;
	token_type: string;
	id_token: string;
}

export type SupportedAlgorithm = "ES256" | "ES384" | "ES512";

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

export class NdiOidcHelper {
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
		this.singpassJWKSUrl = props.singpassJWKSUrl;
		this.algorithm = props.algorithmn;
		this.jwsKid = props.jwsKid;
		this.additionalHeaders = props.additionalHeaders || {};
		this.importKeys(props.jwePrivateKey, props.jwsPrivateKey, props.algorithmn);
	}

	private async importKeys(
		jweKey: string,
		jwsKey: string,
		algorithmn: SupportedAlgorithm
	) {
		try {
			this.jweKey = await importPKCS8(jweKey, algorithmn);
			this.jwsKey = await importPKCS8(jwsKey, algorithmn);
		} catch (err) {
			logger.error(err);
			throw new SingpassMyInfoError("Unable to load jwe and/or jws key");
		}
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
			const decryptedJwe = await decrypt(this.jweKey, id_token);
			return await this.verifyToken(decryptedJwe, nonce);
		} catch (e) {
			logger.error("Failed to get token payload", e);
			throw new SingpassMyInfoError("Failed to get token payload");
		}
	}


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
			throw new Error("Singpass public sig key is not found");
		}
		return singpassSigPublicKey;
	}

	public _testExports = {
		singpassClient: this.axiosClient,
	};
}
