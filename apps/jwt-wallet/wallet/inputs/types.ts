import { JSON } from "@klave/sdk";

@JSON
export class JWTHeader {
    algorithm: string;      // RSA, ECDSA, AES
}

@JSON
export class JWTPayload {
    payload: string;
}

@JSON
export class RenameWalletInput {
    oldName: string;
    newName: string;
}

@JSON
export class CreateWalletInput {
    name: string;
    rootKeyData: string;
}

@JSON
export class SignInput {
    keyId: string;
    payload: string;
}

@JSON
export class VerifyInput {
    keyId: string;
    payload: string;
    signature: string;
}

@JSON
export class AddUserInput {
    userId: string;
    role: string;
}

@JSON
export class RemoveUserInput {
    userId: string;
}

@JSON
export class AddKeyInput {
    description: string;
    type: string;
}

@JSON
export class ImportRootKeyInput {
    keyData: string;        // base64 encoded
}

@JSON
export class ImportPrivateKeyInput {
    format: string;         // raw, pkcs8, spki, jwk
    keyData: string;        // base64 encoded
    algorithm: string;      // RSA, ECDSA, AES
    extractable: boolean;
}

@JSON
export class ExportKeyInput {
    keyId: string;
    format: string;         // raw, pkcs8, spki, jwk
}

@JSON
export class RemoveKeyInput {
    keyId: string;
}

@JSON
export class ResetInput {
    keys: string[];
}
