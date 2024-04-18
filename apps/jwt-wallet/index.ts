import { JSON } from "@klave/sdk"
import { CreateWalletInput, SignInput, VerifyInput, RemoveKeyInput, JWTHeader, JWTPayload, GenerateKeyInput, ImportKeyInput} from "./wallet/inputs/types";
import { Wallet } from "./wallet/wallet";
import { emit, revert } from "./klave/types";
import { decode } from 'as-base64/assembly';

/**
 * check the jwt token
 */
const _checkJWT = function(jwt: string): JWTPayload | null {
     let items = jwt.split(".");
    if (items.length != 3) {
        revert("Invalid JWT format");
        return null;
    }

    let wallet = Wallet.load();
    if (!wallet) {
        return null;
    }
    let jwtHeader : JWTHeader = JSON.parse<JWTHeader>(decode(items[0]).toString());
    if (!wallet.verifyInput(jwtHeader, items[1], items[2])) {
        revert("Invalid JWT signature");
        return null;
    }
    let jwtPayload = JSON.parse<JWTPayload>(decode(items[1]).toString());
    return jwtPayload;
}


/**
 * @transaction add a key to the wallet
 * @param input containing a jwt string with a payload containing the following fields:
 * - description: string
 * - key: KeyInput
 * @returns success boolean
 */
export function generateKey(jwt: string): void {
    let jwtPayload = _checkJWT(jwt);
    if (!jwtPayload) {
        return;
    }
    let input: GenerateKeyInput = JSON.parse<GenerateKeyInput>(jwtPayload.payload);

    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    if (wallet.addKey(input.description, input.type)) {
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
export function importRootKey(jwt: string): void {
    let jwtPayload = _checkJWT(jwt);
    if (!jwtPayload) {
        return;
    }
    let input: ImportKeyInput = JSON.parse<ImportKeyInput>(jwtPayload.payload);

    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    wallet.importRootKey(input.key.format, input.key.keyData, input.key.algorithm, input.key.extractable, input.key.usages);
    wallet.save();
}

/**
 * @transaction import a private key to the wallet
 * @param input containing a jwt string with a payload containing the following fields:
 * - description: string
 * - key: KeyInput
 * @returns success boolean
 */
export function importKey(jwt: string): void {
    let jwtPayload = _checkJWT(jwt);
    if (!jwtPayload) {
        return;
    }
    let input: ImportKeyInput = JSON.parse<ImportKeyInput>(jwtPayload.payload);

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
export function removeKey(jwt: string): void {
    let jwtPayload = _checkJWT(jwt);
    if (!jwtPayload) {
        return;
    }
    let input: RemoveKeyInput = JSON.parse<RemoveKeyInput>(jwtPayload.payload);

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
export function listKeys(jwt: string): void {
    //Payload should be empty but we need to check the signature
    let jwtPayload = _checkJWT(jwt);
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
export function sign(jwt: string) : void {
    let jwtPayload = _checkJWT(jwt);
    if (!jwtPayload) {
        return;
    }
    let input: SignInput = JSON.parse<SignInput>(jwtPayload.payload);

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
export function verify(jwt: string) : void {
    let jwtPayload = _checkJWT(jwt);
    if (!jwtPayload) {
        return;
    }
    let input: VerifyInput = JSON.parse<VerifyInput>(jwtPayload.payload);

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
export function encrypt(jwt: string): void {
    let jwtPayload = _checkJWT(jwt);
    if (!jwtPayload) {
        return;
    }
    let input: SignInput = JSON.parse<SignInput>(jwtPayload.payload);

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
export function decrypt(jwt: string): void {
    let jwtPayload = _checkJWT(jwt);
    if (!jwtPayload) {
        return;
    }
    let input: SignInput = JSON.parse<SignInput>(jwtPayload.payload);

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
