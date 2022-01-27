import { JWTPayload } from "jose";
import { NDITokenResponse } from "..";
import { NdiOidcHelperConstructor, NdiOidcHelper } from "../ndi-singpass-helper";

const mockTokenUrl = "https://mocksingpass.sg/token";
const mockClientId = "CLIENT-ID";
const mockRedirectUri = "http://mockme.sg/callback";
const mockSingpassOpenIdDiscoveryUrl = "https://mock.singpass.gov.sg";
const mocksingpassJWKSUrl = "https://mock.singpass.gov.sg";
const mockAuthCode = "auth-code";
const testKey = `-----BEGIN PRIVATE KEY-----
MIHtAgEAMBAGByqGSM49AgEGBSuBBAAjBIHVMIHSAgEBBEGPMg1SnaD49tQSIlvA
EOHcOVJ2WEqcRB8x2w/pNtspTumRZsBQOQ0+b4jsDoTPNNafgn38CDPyrA3v2ttC
AWkZw6GBiQOBhgAEAE7feGLpNZizMA929ZCQM5eUrJmMbZNm726L0Uyq2FWsGFG1
j4Pzn/Lwrh15JWPZMdQjS4Rf4sUqVDT/fyVfM49jARLQRSs2MKo1JnEPn9UPMsRe
4rifWzI1BDSLuo2Eu0d9tqFxaMBxU/Rs8saxH0xkBeVbYkJ/g2znzO2gk3JHWTAJ
-----END PRIVATE KEY-----`
const mockDecryptKey = testKey;
const mockVerifyKey = testKey;
const mockJwsKid = 'jws-kid';
const mockTokenReponse: NDITokenResponse = {
	id_token: "some-token",
	access_token: "some-token",
	token_type: "some-token"
}

const createMockJWTPayload = (overrideProps?: Partial<JWTPayload>): JWTPayload => ({
	rt_hash: "TJXzQKancNCg3f3YQcZhzg",
	amr: ["pwd"],
	iat: 1547620274,
	iss: "https://stg-saml.singpass.gov.sg",
	sub: "s=S1234567A,u=f19fdf4c-f57b-40b5-a8e0-6fb6eef640e3",
	at_hash: "5LGrRzmsFWLd360gX7HDtw",
	exp: 1547623874,
	aud: "MY-CLIENT-ID",
	...overrideProps,
});

describe("NdiSingpass Helper", () => {
	const props: NdiOidcHelperConstructor = {
		algorithm: 'ES512',
		jwsKid: mockJwsKid,
		singpassJWKSUrl: mocksingpassJWKSUrl,
		singpassOpenIdDiscoveryUrl: mockSingpassOpenIdDiscoveryUrl,
		tokenUrl: mockTokenUrl,
		clientID: mockClientId,
		redirectUri: mockRedirectUri,
		jweDecryptKey: mockDecryptKey,
		jwsVerifyKey: mockVerifyKey,
	};
	const helper = new NdiOidcHelper(props);


	describe("get tokens", () => {
		it("should append additional headers if provided", async () => {
			const helperWithHeaders = new NdiOidcHelper({
				...props,
				additionalHeaders: {
					"some-header": "some-value",
				}
			});
			await helperWithHeaders.initialize();
			helperWithHeaders._testExports.singpassClient.post = jest.fn()
				.mockResolvedValue({
					data: mockTokenReponse
				});
			const result = await helperWithHeaders.getTokens(mockAuthCode);
			expect(helperWithHeaders._testExports.singpassClient.post).toHaveBeenCalledWith(
				expect.anything(),
				expect.anything(),
				expect.objectContaining({
					headers: expect.objectContaining({
						"some-header": "some-value",
					}),
				})
			);
			expect(result).toEqual(mockTokenReponse)
		})
		it("should NOT override reserved headers", async () => {
			const helperWithHeaders = new NdiOidcHelper({
				...props,
				additionalHeaders: {
					"content-type": "some-override-value",
				}
			});
			await helperWithHeaders.initialize();
			helperWithHeaders._testExports.singpassClient.post = jest.fn()
				.mockResolvedValue({
					data: mockTokenReponse
				});
			const result = await helperWithHeaders.getTokens(mockAuthCode);
			expect(helperWithHeaders._testExports.singpassClient.post).toHaveBeenCalledWith(
				expect.anything(),
				expect.anything(),
				expect.objectContaining({
					headers: {
						"content-type": "application/x-www-form-urlencoded",
					},
				})
			);
			expect(result).toEqual(mockTokenReponse)
		});
	});

	describe("extracting nric and uuid from payload", () => {
		it("should extract the nric and uuid from the payload", () => {
			const mockNric = "S1234567X";
			const mockUuid = "f09fcf4c-f57b-40b5-a8e0-6fb6eef640e3";

			const mockPayload = createMockJWTPayload({
				sub: `s=${mockNric},u=${mockUuid}`,
			});
			const { nric, uuid } = helper.extractNricAndUuidFromPayload(mockPayload);
			expect(nric).toEqual(mockNric);
			expect(uuid).toEqual(mockUuid);
		});

		it("should throw an error if payload does not have the property 'sub'", () => {
			const mockPayload = createMockJWTPayload({
				sub: undefined,
			});
			expect(() => helper.extractNricAndUuidFromPayload(mockPayload)).toThrowError("Token payload sub property is not defined");
		});

		it("should throw an error if sub property does not contain a valid NRIC", () => {
			const mockPayload = createMockJWTPayload({
				sub: `s=some-nonsense,u=f09fcf4c-f57b-40b5-a8e0-6fb6eef640e3`,
			});

			expect(() => helper.extractNricAndUuidFromPayload(mockPayload)).toThrowError("Token payload sub property is invalid, does not contain valid NRIC and uuid string");
		});

		it("should throw an error if sub property is not in the expected format", () => {
			const mockPayload = createMockJWTPayload({
				sub: `s=S6005040F,f=f09fcf4c-f57b-40b5-a8e0-6fb6eef640e3`,
			});

			expect(() => helper.extractNricAndUuidFromPayload(mockPayload)).toThrowError("Token payload sub property is invalid, does not contain valid NRIC and uuid string");
		});
	});
});
