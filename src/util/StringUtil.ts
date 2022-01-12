import * as isBase64 from "is-base64";
import { TokenPayload } from "../singpass";


export function replaceLineBreaks(input: string): string {
	if (!input) {
		return input;
	}

	return input.replace(/\\n/g, "\n");
}

export function isBase64Valid(test: string): boolean {
	return isBase64(test, { paddingRequired: false });
}

export function extractNricAndUuidFromPayload(payload: TokenPayload): {
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
