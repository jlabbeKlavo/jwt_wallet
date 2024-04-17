import { Ledger, JSON, Context } from "@klave/sdk";
import { emit, revert } from "../klave/types";
import { Key } from "./key";
import { User } from "./user";
import { JWTHeader } from "./inputs/types";
import { encode } from 'as-base64/assembly';

const WalletTable = "WalletTable";

/**
 * An Wallet is associated with a list of users and holds keys.
 */
@JSON
export class Wallet {
    name: string;
    keys: Array<string>;
    rootKeyId: string;

    constructor() {
        this.name = "";
        this.keys = new Array<string>();
    }

    /**
     * load the wallet from the ledger.
     * @returns true if the wallet was loaded successfully, false otherwise.
     */
    static load(): Wallet | null {
        let walletTable = Ledger.getTable(WalletTable).get("ALL");
        if (walletTable.length == 0) {
            revert("Wallet does not exists. Create it first");
            return null;
        }
        let wlt = JSON.parse<Wallet>(walletTable);
        emit("Wallet loaded successfully: " + walletTable);
        return wlt;
    }

    /**
     * save the wallet to the ledger.
     */
    save(): void {
        let walletTable = JSON.stringify<Wallet>(this);
        Ledger.getTable(WalletTable).set("ALL", walletTable);
        emit("Wallet saved successfully: " + walletTable);
    }

    /**
     * rename the wallet.
     * @param newName
     */
    rename(oldName: string, newName: string): void {
        if (this.name != oldName) {
            revert("Wallet name does not match");
            return;
        }
        this.name = newName;
        emit("Wallet renamed successfully");
    }

    /**
     * Create a wallet with the given name.
     * Also adds the sender as an admin user.
     * @param name
     */
    create(name: string): void {
        this.name = name;
        emit("Wallet created successfully: " + this.name);
        return;
    }

    /**
     * Import a key to the wallet.
     */
    importRootKey(keyData: string): void {
        let key = new Key("");
        key.importPublicKey(keyData);
        this.rootKeyId = key.id;
        emit("Root Key imported successfully: " + key.id);
    }

    /**
     * Import a key to the wallet.
     */
    importPrivateKey(format: string, keyData: string, algorithm: string, extractable: boolean): void {
        let key = new Key("");
        key.importPrivateKey(format, keyData, algorithm, extractable);
        this.keys.push(key.id);
        emit("Key imported successfully: " + key.id);
    }

    /**
     * Verify a signature with the given key.
     */
    verifyInput(jwtHeader: JWTHeader, payload: string, signature: string): boolean {
        if (jwtHeader.algorithm != "ECDSA") {
            revert("Only ECDSA algorithm is supported");
            return false;
        }
        let key = Key.load(this.rootKeyId);
        if (!key) {
            revert("Root key not found");
            return false;
        }
        return key.verify(payload, signature);
    }

    /**
     * list all the keys in the wallet.
     * @returns
     */
    listKeys(): void {
        let keys: string = "";
        for (let i = 0; i < this.keys.length; i++) {
            let key = this.keys[i];
            let keyObj = Key.load(key);
            if (!keyObj) {
                revert(`Key ${key} does not exist`);
                continue;
            }
            if (keys.length > 0) {
                keys += ", ";
            }
            keys += JSON.stringify<Key>(keyObj);
        }
        if (keys.length == 0) {
            emit(`No keys found in the wallet`);
        }
        emit(`Keys in the wallet: ${keys}`);
    }

    /**
     * reset the wallet to its initial state.
     * @returns
     */
    reset(keys: Array<string>): void {
        if (keys.length == 0) {
            this.name = "";
            this.keys = new Array<string>();
            emit("Wallet reset successfully");
         } else {
            for (let i = 0; i < keys.length; i++) {
                let key = new Key(keys[i]);
                key.delete();
                let index = this.keys.indexOf(keys[i]);
                this.keys.splice(index, 1);
            }
            emit("Keys removed successfully");
        }

    }

    /**
     * Sign a message with the given key.
     * @param keyId The id of the key to sign with.
     * @param payload The message to sign.
     */
    sign(keyId: string, payload: string): string | null {
        let key = Key.load(keyId);
        if (!key) {
            return null;
        }
        return key.sign(payload);
    }

    /**
     * Verify a signature with the given key.
     * @param keyId The id of the key to verify with.
     * @param payload The message to verify.
     * @param signature The signature to verify.
     */
    verify(keyId: string, payload: string, signature: string): boolean {
        let key = Key.load(keyId);
        if (!key) {
            return false;
        }
        return key.verify(payload, signature);
    }

    /**
     * Create a key with the given description and type.
     * @param description The description of the key.
     * @param type The type of the key.
     */
    addKey(description: string, type: string): boolean {
        let key = new Key("");
        key.create(description, type);
        key.save();

        this.keys.push(key.id);
        return true;
    }

    /**
     * Remove a key from the wallet.
     * @param keyId The id of the key to remove.
     */
    removeKey(keyId: string): boolean {
        let key = Key.load(keyId);
        if (!key) {
            return false;
        }
        key.delete();

        let index = this.keys.indexOf(keyId);
        this.keys.splice(index, 1);
        return true;
    }

    /**
     * encrypt a message with the given key.
     */
    encrypt(keyId: string, message: string): string | null {
        let key = Key.load(keyId);
        if (!key) {
            return null;
        }
        return key.encrypt(message);
    }

    /**
     * encrypt a message with the given key.
     */
    decrypt(keyId:string, cypher: string): string | null{
        let key = Key.load(keyId);
        if (!key) {
            return null;
        }
        return key.decrypt(cypher);
    }

}