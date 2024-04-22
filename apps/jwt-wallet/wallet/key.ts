import { Ledger, Crypto, JSON } from '@klave/sdk'
import { emit, revert } from "../klave/types"
import { SignInput, VerifyInput, sign, verify } from "../klave/crypto";
import { encode as b64encode, decode as b64decode } from 'as-base64/assembly';
import { convertToUint8Array, convertToU8Array } from "../klave/helpers";

const KeysTable = "KeysTable";

@JSON
export class Key {
    id: string;
    type: string;
    description: string;

    constructor(id: string) {
        this.id = id;
        this.type = "";
        this.description = "";
    }

    static load(keyId: string) : Key | null {
        let keyTable = Ledger.getTable(KeysTable).get(keyId);
        if (keyTable.length == 0) {
            revert("Key does not exists. Create it first");
            return null;
        }
        let key = JSON.parse<Key>(keyTable);
        emit(`Key loaded successfully: '${key.id}'`);
        return key;
    }

    save(): void {
        let keyTable = JSON.stringify<Key>(this);
        Ledger.getTable(KeysTable).set(this.id, keyTable);
        emit(`Key saved successfully: '${this.id}'`);
    }

    create(description: string, algorithm: string) : boolean {
        this.id = b64encode(convertToUint8Array(Crypto.getRandomValues(64)));
        this.type = algorithm;
        this.description = description;
        if (this.type == "ECDSA") {
            const key = Crypto.ECDSA.generateKey(this.id);
            if (key) {
                emit(`SUCCESS: Key '${this.id}' has been generated`);
                return true;
            } else {
                revert(`ERROR: Key '${this.id}' has not been generated`);
                return false;
            }
        }
        else if (this.type == "AES") {
            const key = Crypto.AES.generateKey(this.id);
            if (key) {
                emit(`SUCCESS: Key '${this.id}' has been generated`);
                return true;
            } else {
                revert(`ERROR: Key '${this.id}' has not been generated`);
                return false;
            }
        }
        else {
            revert(`ERROR: Key type '${this.type}' is not supported`);
            return false;
        }
    }

    delete(): void {
        Ledger.getTable(KeysTable).unset(this.id);
        emit(`Key deleted successfully: '${this.id}'`);
    }

    sign(message: string): string | null {
        if (this.type != "ECDSA") {
            revert("ERROR: Key type is not ECDSA")
            return null;
        }
        return sign(new SignInput(this.id, message));
    }

    verify(message: string, signature: string): boolean {
        if (this.type != "ECDSA") {
            revert("ERROR: Key type is not ECDSA")
            return false;
        }
        return verify(new VerifyInput(this.id, message, signature));
    }

    encrypt(message: string): string {
        if (this.type != "AES") {
            revert("ERROR: Key type is not AES");
            return "";
        }
        let KeyAES = Crypto.AES.getKey(this.id);
        if (!KeyAES) {
            revert("ERROR: Key not found");
            return "";
        }
        return b64encode(convertToUint8Array(KeyAES.encrypt(message)));
    }

    decrypt(cypher: string): string {
        if (this.type != "AES") {
            revert("ERROR: Key type is not AES");
            return "";
        }
        let KeyAES = Crypto.AES.getKey(this.id);
        if (!KeyAES) {
            revert("ERROR: Key not found");
            return "";
        }
        return KeyAES.decrypt(convertToU8Array(b64decode(cypher)));
    }

    import(description: string, format: string, keyData: string, algorithm: string, extractable: boolean, usages: string[]) : boolean {
        if (algorithm == "ECDSA") {
            this.id = b64encode(convertToUint8Array(Crypto.getRandomValues(64)));
            this.type = algorithm;
            this.description = description;
            let key = Crypto.ECDSA.importKey(format, keyData, extractable, usages, this.id);
            if (key) {
                emit(`SUCCESS: Key '${this.id}' has been imported`);
                return true;
            } else {
                revert(`ERROR: Key '${this.id}' has not been imported`);
                return false;
            }
        }
        else {
            revert(`ERROR: Key type '${algorithm}' is not supported`);
            return false;
        }
    }
}