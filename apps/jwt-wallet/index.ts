import { JSON } from "@klave/sdk"
import { RenameWalletInput, CreateWalletInput, SignInput, VerifyInput, AddUserInput, AddKeyInput, ListKeysInput, ResetInput, RemoveKeyInput, RemoveUserInput, ImportKeyInput, JWTHeader, JWTPayload} from "./wallet/inputs/types";
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
    let jwtHeader = JSON.parse<JWTHeader>(decode(items[0]));
    if (!wallet.verifyInput(jwtHeader, items[1], items[2])) {
        revert("Invalid JWT signature");
        return null;
    }
    let jwtPayload = JSON.parse<JWTPayload>(decode(items[1]));
    return jwtPayload;
}


/**
 * @transaction add a key to the wallet
 * @param input containing the following fields:
 * - description: string
 * - type: string
 * @returns success boolean
 */
export function addKey(jwt: string): void {
    let jwtPayload = _checkJWT(jwt);
    if (!jwtPayload) {
        return;
    }
    let input: AddKeyInput = JSON.parse<AddKeyInput>(jwtPayload.payload);

    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    if (wallet.addKey(input.description, input.type)) {
        wallet.save();
    }
}

/**
 * @transaction import a key to the wallet
 * @param input containing the following fields:
 * - description: string
 * - type: string
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
    if (wallet.importKey(input.format, input.keyData, input.algorithm, input.extractable, input.keyUsages)) {
        wallet.save();
    }
}

/**
 * @transaction remove a key from the wallet
 * @param input containing the following fields:
 * - keyId: string
 * @returns success boolean
 */
export function removeKey(input: RemoveKeyInput): void {
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
export function listKeys(input: ListKeysInput): void {
    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    wallet.listKeys(input.user);
}

/**
 * @query
 * @param input containing the following fields:
 * - keyId: string
 * - payload: string
 * @returns success boolean and the created text
 */
export function sign(input: SignInput) : void {
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
export function verify(input: VerifyInput) : void {
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
export function encrypt(input: SignInput): void {
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
export function decrypt(input: SignInput): void {
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
 * @transaction add a user to the wallet
 * @param input containing the following fields:
 * - userId: string
 * - role: string, "admin" or "user"
 * @returns success boolean
 */
export function addUser(input: AddUserInput): void {
    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    if (wallet.addUser(input.userId, input.role, false)) {
        wallet.save();
    }
}

/**
 * @transaction remove a user from the wallet
 * @param input containing the following fields:
 * - userId: string
 * @returns success boolean
 */
export function removeUser(input: RemoveUserInput): void {
    let wallet = Wallet.load();
    if (!wallet) {
        return;
    }
    if (wallet.removeUser(input.userId)) {
        wallet.save();
    }
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
    wallet.save();
}

// /**
//  * @transaction rename the wallet
//  * @param input containing the following fields:
//  * - oldName: string
//  * - newName: string
//  * @returns success boolean
//  */
// export function renameWallet(input: RenameWalletInput): void {
//     let wallet = Wallet.load();
//     if (!wallet) {
//         return;
//     }
//     wallet.rename(input.oldName, input.newName);
//     wallet.save();
// }

// /**
//  * @transaction clears the wallet
//  * @param input containing the following fields:
//  * - keys: string[], the keys to remove (optional)
//  * @returns success boolean
//  */
// export function reset(input: ResetInput): void {
//     let wallet = Wallet.load();
//     if (!wallet) {
//         return;
//     }
//     wallet.reset(input.keys);
//     wallet.save();
// }
