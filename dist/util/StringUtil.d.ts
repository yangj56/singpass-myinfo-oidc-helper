import { TokenPayload } from "../singpass";
export declare function replaceLineBreaks(input: string): string;
export declare function isBase64Valid(test: string): boolean;
export declare function extractNricAndUuidFromPayload(payload: TokenPayload): {
    nric: string;
    uuid: string;
};
//# sourceMappingURL=StringUtil.d.ts.map