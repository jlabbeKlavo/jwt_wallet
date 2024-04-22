import { JSON, Utils } from "@klave/sdk"
import { CreateWalletInput, SignInput, VerifyInput, RemoveKeyInput, JWTHeader, JWTPayload, ImportKeyInput, GenerateKeyInput, KeyInput, JWTInput, JWTGenerateInput} from "./wallet/inputs/types";
import { Wallet } from "./wallet/wallet";
import { emit, revert } from "./klave/types";
import { decode, encode } from 'as-base64/assembly';

/**
 * check the jwt token
 */
const _checkJWT = function(jwt: string): string | null {
     let items = jwt.split(".");
    if (items.length != 3) {
        revert("Invalid JWT format");
        return null;
    }

    let wallet = Wallet.load();
    if (!wallet) {
        return null;
    }
    let jwtHeaderU8 = decode(items[0]);
    let jwtHeaderStr: string = String.UTF8.decode(jwtHeaderU8.buffer, true);
    jwtHeaderStr = jwtHeaderStr.replace("\\", "");
    emit("jwtHeaderStr: " + jwtHeaderStr);
    let jwtPayloadU8 = decode(items[1]);
    let jwtPayloadStr: string = String.UTF8.decode(jwtPayloadU8.buffer, true);
    jwtPayloadStr = jwtPayloadStr.replace("\\", "");
    emit("jwtPayloadStr: " + jwtPayloadStr);

    let jwtHeader : JWTHeader = JSON.parse<JWTHeader>(jwtHeaderStr);
    emit("jwtHeader: " + jwtHeader.alg + " - " + items[0] + "." + items[1] + " - " + items[2]);

    if (!wallet.verifyInput(jwtHeader.alg, items[0] + "." + items[1], items[2])) {
        revert("Invalid JWT signature");
        return null;
    }    
    emit("Verification Successful");
    return jwtPayloadStr;
}


/**
 * @transaction add a key to the wallet
 * @param input containing a jwt string with a payload containing the following fields:
 * - description: string
 * - key: KeyInput
 * @returns success boolean
 */
export function generateKey(jwt_input: JWTInput): void {
    let jwtPayload = _checkJWT(jwt_input.jwt);
    if (!jwtPayload) {
        return;
    }
    let input: GenerateKeyInput = JSON.parse<GenerateKeyInput>(jwtPayload);

    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    if (wallet.generateKey(input.description, input.algorithm)) {
        wallet.save();
    }
}

/**
 * @transaction import a private key to the wallet
 * @param input containing a jwt string with a payload containing the following fields:
 * - description: string
 * - key: KeyInput
 * @returns success boolean
 */
export function importRootKey(jwt_input: JWTInput): void {
    let jwtPayload = _checkJWT(jwt_input.jwt);
    if (!jwtPayload) {
        return;
    }
    let input: KeyInput = JSON.parse<KeyInput>(jwtPayload);

    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    wallet.importRootKey(input.format, input.keyData, input.algorithm, input.extractable, input.usages);
    wallet.save();
}

/**
 * @transaction import a private key to the wallet
 * @param input containing a jwt string with a payload containing the following fields:
 * - description: string
 * - key: KeyInput
 * @returns success boolean
 */
export function importKey(jwt_input: JWTInput): void {
    let jwtPayload = _checkJWT(jwt_input.jwt);
    if (!jwtPayload) {
        return;
    }
    let input: ImportKeyInput = JSON.parse<ImportKeyInput>(jwtPayload);

    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    wallet.importKey(input.description, input.key.format, input.key.keyData, input.key.algorithm, input.key.extractable, input.key.usages);
    wallet.save();
}

/**
 * @transaction remove a key from the wallet
 * @param input containing the following fields:
 * - keyId: string
 * @returns success boolean
 */
export function removeKey(jwt_input: JWTInput): void {
    let jwtPayload = _checkJWT(jwt_input.jwt);
    if (!jwtPayload) {
        return;
    }
    let input: RemoveKeyInput = JSON.parse<RemoveKeyInput>(jwtPayload);

    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    if (wallet.removeKey(input.keyId)) {
        wallet.save();
    }
}

/**
 * @query list all keys in the wallet
 * @param input containing the following fields:
 * - user: string, the user to list the keys for (optional)
 * @returns the list of keys
 */
export function listKeys(jwt_input: JWTInput): void {
    //Payload should be empty but we need to check the signature
    let jwtPayload = _checkJWT(jwt_input.jwt);
    if (!jwtPayload) {
        return;
    }

    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    wallet.listKeys();
}

/**
 * @query
 * @param input containing the following fields:
 * - keyId: string
 * - payload: string
 * @returns success boolean and the created text
 */
export function sign(jwt_input: JWTInput) : void {
    let jwtPayload = _checkJWT(jwt_input.jwt);
    if (!jwtPayload) {
        return;
    }
    let input: SignInput = JSON.parse<SignInput>(jwtPayload);

    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    let signature = wallet.sign(input.keyId, input.payload);
    if (signature == null) {
        revert("Failed to sign");
        return;
    }
    emit(signature);
}

/**
 * @query
 * @param input containing the following fields:
 * - keyId: string
 * - payload: string
 * - signature: string
 * @returns success boolean
 */
export function verify(jwt_input: JWTInput) : void {
    let jwtPayload = _checkJWT(jwt_input.jwt);
    if (!jwtPayload) {
        return;
    }
    let input: VerifyInput = JSON.parse<VerifyInput>(jwtPayload);

    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    let result = wallet.verify(input.keyId, input.payload, input.signature);
    if (!result) {
        revert(`Failed to verify`);
        return;
    }
    emit("verified");
}

/**
 * @query
 * @param input containing the following fields:
 * - keyId: string
 * - payload: string
 * @returns success boolean and the crypted message
 */
export function encrypt(jwt_input: JWTInput): void {
    let jwtPayload = _checkJWT(jwt_input.jwt);
    if (!jwtPayload) {
        return;
    }
    let input: SignInput = JSON.parse<SignInput>(jwtPayload);

    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    let encrypted = wallet.encrypt(input.keyId, input.payload);
    if (encrypted == null) {
        revert("Failed to encrypt");
        return;
    }
    emit(encrypted);
}

/**
 * @query
 * @param input containing the following fields:
 * - keyId: string
 * - payload: string
 * @returns success boolean and text decyphered
 */
export function decrypt(jwt_input: JWTInput): void {
    let jwtPayload = _checkJWT(jwt_input.jwt);
    if (!jwtPayload) {
        return;
    }
    let input: SignInput = JSON.parse<SignInput>(jwtPayload);

    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    let decrypted = wallet.decrypt(input.keyId, input.payload);
    if (decrypted == null) {
        revert("Failed to decrypt");
        return;
    }
    emit(decrypted);
}

/**
 * @transaction initialize the wallet
 * @param input containing the following fields:
 * - name: string
 * @returns success boolean
 */
export function createWallet(input: CreateWalletInput): void {
    let existingWallet = Wallet.load();
    if (existingWallet) {
        revert(`Wallet does already exists.`);
        return;
    }
    let wallet = new Wallet();
    wallet.create(input.name);
    wallet.importRootKey(input.rootKey.key.format, input.rootKey.key.keyData, input.rootKey.key.algorithm, input.rootKey.key.extractable, input.rootKey.key.usages);
    wallet.save();
}