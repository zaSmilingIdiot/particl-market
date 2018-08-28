// Copyright (c) 2017-2018, The Particl Market developers
// Distributed under the GPL software license, see the accompanying
// file COPYING or https://github.com/particl/particl-market/blob/develop/LICENSE

import * as _ from 'lodash';
import { inject, named } from 'inversify';
import { Logger as LoggerType } from '../../core/Logger';
import { Types, Core, Targets } from '../../constants';
import { Environment } from '../../core/helpers/Environment';
import * as WebRequest from 'web-request';
import { HttpException } from '../exceptions/HttpException';
import { JsonRpc2Response } from '../../core/api/jsonrpc';
import { InternalServerException } from '../exceptions/InternalServerException';
import { CoreCookieService } from './CoreCookieService';
import { Output } from 'resources';

import { ISignature, TransactionBuilder, RPC, Output as OmpOutput, toSatoshis, fromSatoshis } from 'omp-lib';

declare function escape(s: string): string;
declare function unescape(s: string): string;

let RPC_REQUEST_ID = 1;

export class CoreRpcService implements RPC {

    public log: LoggerType;

    private DEFAULT_MAINNET_PORT = 51735;
    private DEFAULT_TESTNET_PORT = 51935;
    private DEFAULT_HOSTNAME = 'localhost';
    // DEFAULT_USERNAME & DEFAULT_PASSWORD in CoreCookieService

    constructor(
        @inject(Types.Core) @named(Core.Logger) public Logger: typeof LoggerType,
        @inject(Types.Service) @named(Targets.Service.CoreCookieService) private coreCookieService: CoreCookieService
    ) {
        this.log = new Logger(__filename);
    }

    /*public async call(method: string, params: any[]): Promise<any> {
        this.log.error('Not implemented.');
    }*/

    /*
        WALLET - generating keys, addresses.
    */
    /*public async getNewPubkey(): Promise<string> {
        this.log.error('Not implemented.');
    }*/

    /*public async getNewAddress(): Promise<string> {
        this.log.error('Not implemented.');
    }*/

    // Retrieving information of outputs
    /*
     * TODO: Might need modification
     */
    public async getNormalOutputs(reqSatoshis: number): Promise<OmpOutput[]> {
        const chosen: OmpOutput[] = [];
        const utxoLessThanReq: number[] = [];
        const defaultIdxs: number[] = [];
        let utxoIdxs: number[] = [];
        let exactMatchIdx = -1;
        let maxOutputIdx = -1;
        let chosenSatoshis = 0;

        const unspent: OmpOutput[] = await this.call(
            'listunspent',
            [0]
        );

        unspent.filter(
            (output: any, outIdx: number) => {
                if (output.spendable && output.safe && (output.scriptPubKey.substring(0, 2) === '76')) {
                    if ((exactMatchIdx === -1) && ((toSatoshis(output.amount) - reqSatoshis) === 0)) {
                        // Found a utxo with amount that is an exact match for the requested value.
                        exactMatchIdx = outIdx;
                    } else if (toSatoshis(output.amount) < reqSatoshis) {
                        // utxo is less than the amount requested, so may be summable with others to get to the exact value (or within a close threshold).
                        utxoLessThanReq.push(outIdx);
                    }

                    // Get the max utxo amount in case an output needs to be split
                    if (maxOutputIdx === -1) {
                        maxOutputIdx = outIdx;
                    } else if (unspent[maxOutputIdx].amount < output.amount) {
                        maxOutputIdx = outIdx;
                    }

                    // Sum up output amounts for the default case
                    if (chosenSatoshis < reqSatoshis) {
                        chosenSatoshis += toSatoshis(output.amount);
                        defaultIdxs.push(outIdx);
                    }
                    return true;
                }
                return false;
            }
        );

        // Step 1: Check whether an exact match was found.
        if (exactMatchIdx === -1) {
            // No exact match found, so...
            //  ... Step 2: Sum utxos to find a summed group that matches exactly or is greater than the requried amount by no more than 1%.
            // ( Convert the number of utxos available to bits, then loop over a total value of the bits, extracting the 'on' bits values
            //      to ensure all combinations of possible utxos are matched to try and find a valid sum).
            for (let ii = 0; ii < Math.pow(2, utxoLessThanReq.length); ii++) {
                const selectedIdxs: number[] = utxoLessThanReq.filter(( num: number, index: number) =>  ii & (1 << index) );
                const summed: number = toSatoshis(selectedIdxs.reduce((acc: number, idx: number) => acc + unspent[idx].amount, 0));

                if ((summed >= reqSatoshis) && ((summed - reqSatoshis) < (reqSatoshis / 100))) {
                    // Sum of utxos is within a 1 percent upper margin of the requested amount.
                    if (summed === reqSatoshis) {
                        // Found the exact required amount.
                        utxoIdxs = selectedIdxs;
                        break;
                    } else if (!utxoIdxs.length) {
                        utxoIdxs.length = 0;
                        utxoIdxs = selectedIdxs;
                    }
                }
            }

            // ... Step 3: If no summed values found, attempt to split a large enough output.
            if (utxoIdxs.length === 0 && maxOutputIdx !== -1 && toSatoshis(unspent[maxOutputIdx].amount) > reqSatoshis) {
                // TODO: fix this to actually do proper splitting. Currently just uses the found utxo

                // const newAddr = await this.call('getnewaddress', []);
                // const txid: string = await this.call('sendtoaddress', [newAddr, fromSatoshis(reqSatoshis), 'Splitting output']);
                // const txData: any = await this.call('getrawtransaction', [txid, true]);
                // const outData: any = txData.vout.find(outObj => outObj.valueSat === reqSatoshis);
                // if (outData) {
                //     chosen.push({
                //         txid: txData.txid,
                //         vout: outData.n,
                //         _satoshis: outData.valueSat,
                //         _scriptPubKey: outData.scriptPubKey.hex,
                //         _address: newAddr
                //     });
                // }
                utxoIdxs.push(maxOutputIdx);
            }
        } else {
            // Push the exact match.
            utxoIdxs.push(exactMatchIdx);
        }

        // Step 4: Default to the summed utxos if no other method was successful
        if (!chosen.length && !utxoIdxs.length) {
            if (chosenSatoshis >= reqSatoshis) {
                utxoIdxs = defaultIdxs;
            } else {
                throw new Error('Not enough available output to cover the required amount.');
            }
        }

        utxoIdxs.forEach(utxoIdx => {
            const utxo: any = unspent[utxoIdx];
            chosen.push({
                txid: utxo.txid,
                vout: utxo.vout,
                _satoshis: toSatoshis(utxo.amount),
                _scriptPubKey: utxo.scriptPubKey,
                _address: utxo.address
            });
        });

        await this.call('lockunspent', [false, chosen, true]);
        return chosen;
    }

    /*
     * TODO: Might need modification
     */
    public async getSatoshisForUtxo(utxo: Output): Promise<OmpOutput> {
        const vout = (await this.call('getrawtransaction', [utxo.txid, true]))
            .vout.find((tmpVout: any) => tmpVout.n === utxo.vout);
        const utxoOmp: OmpOutput = vout;
        utxoOmp._satoshis = vout.valueSat;
        return utxoOmp;
    }

    // Importing and signing
    /*
     * TODO: Might need modification
     */
    public async importRedeemScript(script: any): Promise<boolean> {
        await this.call('importaddress', [script, '', false, true]);
        return true;
    }

    /*
     * TODO: Might need modification
     */
    public async signRawTransactionForInputs(tx: TransactionBuilder, inputs: OmpOutput[]): Promise<ISignature[]> {
        const r: ISignature[] = [];

        // needs to synchronize, because the order needs to match
        // the inputs order.
        for (const i of inputs) {
            if (i) {
                const input = inputs[i];
                // console.log('signing for ', input)
                const params = [
                    await tx.build(),
                    {
                        txid: input.txid,
                        vout: input.vout,
                        scriptPubKey: input._scriptPubKey,
                        amount: fromSatoshis(input._satoshis)
                    },
                    input._address
                ];

                const sig = {
                    signature: (await this.call('createsignaturewithwallet', params)),
                    pubKey: (await this.call('getaddressinfo', [input._address])).pubkey
                };
                r.push(sig);
                tx.addSignature(input, sig);
            }
        }

        return r;
    }

    // Networking
    /*public async sendRawTransaction(rawtx: string) {

    }*/

    /*
     * OLD STUFF BELOW
     */

    public async isConnected(): Promise<boolean> {
        return await this.getNetworkInfo()
            .then(response => true)
            .catch(error => {
                return false;
            });
    }

    /**
     * returns the particld version:
     * 16000400: 0.16.0.4,
     * 16000700: 0.16.0.7, ...
     *
     * @returns {Promise<number>}
     */
    public async getVersion(): Promise<number> {
        return await this.getNetworkInfo()
            .then(response => {
                return response.version;
            });
    }

    public async getNetworkInfo(): Promise<any> {
        return await this.call('getnetworkinfo', [], false);
    }

    /**
     * ﻿Returns a new Particl address for receiving payments, key is saved in wallet.
     *
     * If 'account' is specified (DEPRECATED), it is added to the address book
     * so payments received with the address will be credited to 'account'.
     *
     * params:
     * ﻿[0] "account", (string, optional) DEPRECATED. The account name for the address to be linked to. If not provided,
     *      the default account "" is used. It can also be set to the empty string "" to represent the default account.
     *      The account does not need to exist, it will be created if there is no account by the given name.
     * [1] bech32, (bool, optional) Use Bech32 encoding.
     * [2] hardened, (bool, optional) Derive a hardened key.
     * [3] 256bit, (bool, optional) Use 256bit hash.
     *
     * @param {any[]} params
     * @param {boolean} smsgAddress
     * @returns {Promise<any>}
     */
    public async getNewAddress(params: any[] = [], smsgAddress: boolean = true): Promise<any> {
        const response = await this.call('getnewaddress', params);

        if (smsgAddress) {
            // call﻿smsgaddlocaladdress, even though I'm not sure if its required
            const addLocalAddressResponse = await this.call('smsgaddlocaladdress', [response]);
            this.log.debug('addLocalAddressResponse: ', addLocalAddressResponse);

            // add address as receive address
            // const localKeyResponse = await this.call('smsglocalkeys', ['recv', '+', response]);
            // this.log.debug('localKeyResponse: ', localKeyResponse);
        }
        return response;
    }

    /**
     * ﻿﻿Return information about the given particl address. Some information requires the address to be in the wallet.
     *
     * example result:
     * {
     *   "address": "pdtVbU4WBLCvM3gwfBFbDtkG79qUnF62xV",
     *   "scriptPubKey": "76a91462c87f85096decc977f6abe76a6824d2dcd11b9a88ac",
     *   "from_ext_address_id": "xBc887dWRvSSwTkNbsfrVrms23YVXD2NZc",
     *   "path": "m/0/6817",
     *   "ismine": true,
     *   "iswatchonly": false,
     *   "isscript": false,
     *   "iswitness": false,
     *   "pubkey": "02570e92f4b8fb95599bd22a2428286bffad59d2de62ddf42d276653806a61e7f9",
     *   "iscompressed": true,
     *   "account": "_escrow_pub_0b787bf9b0da334baf91b62213f0f0362858299d3babd96893fd010414b71c43"
     * }
     *
     * @param {string} address
     * @returns {Promise<any>}
     */
    public async getAddressInfo(address: string): Promise<any> {
        return await this.call('getaddressinfo', [address]);
    }

    /**
     * ﻿Add a nrequired-to-sign multisignature address to the wallet. Requires a new wallet backup.
     *
     * Each key is a Particl address or hex-encoded public key.
     * If 'account' is specified (DEPRECATED), assign address to that account.
     *
     * params:
     * ﻿[0] ﻿nrequired,       (numeric, required) The number of required signatures out of the n keys or addresses.
     * [1] "keys",          (string, required) A json array of particl addresses or hex-encoded public keys
     *      [
     *          "address"   (string) particl address or hex-encoded public key
     *          ...,
     *      ]
     * [2] "account"        (string, optional) DEPRECATED. An account to assign the addresses to.
     * [3] bech32           (bool, optional) Use Bech32 encoding.
     * [4] 256bit           (bool, optional) Use 256bit hash.
     *
     * example result:
     * ﻿{
     *   "address":"multisigaddress",    (string) The value of the new multisig address.
     *   "redeemScript":"script"         (string) The string value of the hex-encoded redemption script.
     * }
     *
     * @param {number} nrequired
     * @param {string[]} keys
     * @param {string} account
     * @returns {Promise<any>}
     */
    public async addMultiSigAddress(nrequired: number, keys: string[], account: string): Promise<any> {
        const params: any[] = [nrequired, keys, account];
        this.log.debug('params: ', params);
        return await this.call('addmultisigaddress', params);
    }

    /**
     * ﻿Create a transaction spending the given inputs and creating new outputs.
     * Outputs can be addresses or data.
     * Returns hex-encoded raw transaction.
     * Note that the transaction's inputs are not signed, and
     * it is not stored in the wallet or transmitted to the network.
     *
     * @param {"resources".Output[]} inputs
     * @param outputs
     * @returns {Promise<any>}
     */
    public async createRawTransaction(inputs: Output[], outputs: any): Promise<any> {
        return await this.call('createrawtransaction', [inputs, outputs]);
    }

    /**
     * ﻿Sign inputs for raw transaction (serialized, hex-encoded)
     *
     * @param {string} hexstring
     * @param {any[]} outputs
     * @returns {Promise<any>}
     */
    public async signRawTransactionWithWallet(hexstring: string, outputs?: any[]): Promise<any> {
        const params: any[] = [];
        params.push(hexstring);
        if (outputs) {
            params.push(outputs);
        }
        return await this.call('signrawtransactionwithwallet', params);
    }

    /**
     * ﻿Sign inputs for raw transaction (serialized, hex-encoded)
     *
     * @param {string} hexstring
     * @param {string[]} privkeys
     * @param prevtxs
     * @param sighashtype
     * @returns {Promise<any>}
     */
    public async signRawTransactionWithKey(hexstring: string, privkeys: string[], prevtxs?: any, sighashtype?: any): Promise<any> {
        const params: any[] = [hexstring, privkeys];
        if (prevtxs) {
            params.push(prevtxs);
        }
        if (sighashtype) {
            params.push(sighashtype);
        }

        return await this.call('signrawtransactionwithkey', params);
    }

    /**
     * Sign inputs for raw transaction (serialized, hex-encoded)
     *
     * @param {string} hexstring
     * @param {any[]} outputs
     * @returns {Promise<any>}
     */
    public async signRawTransaction(hexstring: string, outputs?: any[]): Promise<any> {
        const params: any[] = [];
        params.push(hexstring);
        if (outputs) {
            params.push(outputs);
        }
        return await this.call('signrawtransaction', params);
    }

    /**
     * Submits raw transaction (serialized, hex-encoded) to local node and network.
     *
     * @param {string} hexstring
     * @returns {Promise<any>}
     */
    public async sendRawTransaction(hexstring: string, allowHighFees: boolean = false): Promise<any> {
        const params: any[] = [];
        params.push(hexstring);
        params.push(allowHighFees);
        return await this.call('sendrawtransaction', params);
    }

    /**
     * Return a JSON object representing the serialized, hex-encoded transaction.
     *
     * @param {string} hexstring
     * @returns {Promise<any>}
     */
    public async decodeRawTransaction(hexstring: string, isWitness?: boolean): Promise<any> {
        const params: any[] = [];
        params.push(hexstring);

        if (isWitness !== undefined) {
            params.push(isWitness);
        }
        return await this.call('decoderawtransaction', params);
    }

    /**
     * Return the raw transaction data.
     *
     * @param {string} hexstring
     * @returns {Promise<any>}
     */
    public async getRawTransaction(txid: string, verbose?: boolean, blockhash?: string): Promise<any> {
        const params: any[] = [];
        params.push(txid);

        if (verbose !== undefined) {
            params.push(verbose);
        }
        if (blockhash !== undefined) {
            params.push(blockhash);
        }
        return await this.call('getrawtransaction', params);
    }

    /**
     * ﻿Returns array of unspent transaction outputs
     * with between minconf and maxconf (inclusive) confirmations.
     * Optionally filter to only include txouts paid to specified addresses.
     *
     * @param {number} minconf
     * @param {number} maxconf
     * @param {string[]} addresses
     * @param {boolean} includeUnsafe
     * @param queryOptions
     * @returns {Promise<any>}
     */
    public async listUnspent(minconf: number, maxconf: number,
                             addresses: string[] = [], includeUnsafe: boolean = true, queryOptions: any = {}): Promise<any> {

        const params: any[] = [minconf, maxconf, addresses, includeUnsafe];
        if (!_.isEmpty(queryOptions)) {
            params.push(queryOptions);
        }

        return await this.call('listunspent', params);
    }

    /**
     *
     * @param {boolean} unlock
     * @param {module:resources.Output[]} outputs, [{"txid":"id","vout": n},...]
     * @returns {Promise<any>}
     */
    public async lockUnspent(unlock: boolean, outputs: Output[]): Promise<any> {

        const params: any[] = [unlock, outputs, true];
        return await this.call('lockunspent', params);
    }

    /**
     * ﻿DEPRECATED. Returns the current Particl address for receiving payments to this account.
     *
     * @param {string} account
     * @returns {Promise<any>}
     */
    public async getAccountAddress(account: string): Promise<any> {
        const params: any[] = [account];
        return await this.call('getaccountaddress', params);
    }

    /**
     * ﻿Get the current block number
     *
     * @param {string} account
     * @returns {Promise<any>}
     */
    public async getBlockCount(): Promise<number> {
        return await this.call('getblockcount', []);
    }

    /**
     * ﻿Reveals the private key corresponding to 'address'.
     *
     * @param {string} address
     * @returns {Promise<string>}
     */
    public async dumpPrivKey(address: string): Promise<string> {
        const params: any[] = [address];
        return await this.call('dumpprivkey', params);
    }

    /**
     * ﻿Return information about the given particl address.
     *
     * @param {string} address
     * @returns {Promise<string>}
     */
    public async validateAddress(address: string): Promise<any> {
        const params: any[] = [address];
        return await this.call('validateaddress', params);
    }

    public async call(method: string, params: any[] = [], logCall: boolean = true): Promise<any> {

        const id = RPC_REQUEST_ID++;
        const postData = JSON.stringify({
            jsonrpc: '2.0',
            method,
            params,
            id
        });

        const url = this.getUrl();
        const options = this.getOptions();

        if (logCall) {
            this.log.debug('call: ' + method + ' ' + params.toString().replace(new RegExp(',', 'g'), ' '));
        }
        // this.log.debug('call url:', url);
        // this.log.debug('call postData:', postData);

        return await WebRequest.post(url, options, postData)
            .then( response => {

                if (response.statusCode !== 200) {
                    this.log.error('response.headers: ', response.headers);
                    this.log.error('response.statusCode: ', response.statusCode);
                    this.log.error('response.statusMessage: ', response.statusMessage);
                    this.log.error('response.content: ', response.content);
                    const message = response.content ? JSON.parse(response.content) : response.statusMessage;
                    throw new HttpException(response.statusCode, message);
                }

                const jsonRpcResponse = JSON.parse(response.content) as JsonRpc2Response;
                if (jsonRpcResponse.error) {
                    throw new InternalServerException([jsonRpcResponse.error.code, jsonRpcResponse.error.message]);
                }

                // this.log.debug('RESULT:', jsonRpcResponse.result);
                return jsonRpcResponse.result;
            })
            .catch(error => {
                // this.log.error('ERROR: ' + JSON.stringify(error));
                if (error instanceof HttpException || error instanceof InternalServerException) {
                    throw error;
                } else {
                    throw new InternalServerException([error.name, error.message]);
                }
            });

    }

    private getOptions(): any {

        const auth = {
            user: (process.env.RPCUSER ? process.env.RPCUSER : this.coreCookieService.getCoreRpcUsername()),
            pass: (process.env.RPCPASSWORD ? process.env.RPCPASSWORD : this.coreCookieService.getCoreRpcPassword()),
            sendImmediately: false
        };

        const headers = {
            'User-Agent': 'Marketplace RPC client',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };
        const rpcOpts = {
            auth,
            headers
        };

        // this.log.debug('initializing rpc with opts:', rpcOpts);
        return rpcOpts;
    }

    private getUrl(): string {
        // this.log.debug('Environment.isTestnet():', Environment.isTestnet());
        // this.log.debug('Environment.isAlpha():', Environment.isAlpha());
        // this.log.debug('process.env.TESTNET:', process.env.TESTNET);

        const host = (process.env.RPCHOSTNAME ? process.env.RPCHOSTNAME : this.DEFAULT_HOSTNAME);
        const port = (Environment.isTestnet() ?
            (process.env.TESTNET_PORT ? process.env.TESTNET_PORT : this.DEFAULT_TESTNET_PORT) :
            (process.env.MAINNET_PORT ? process.env.MAINNET_PORT : this.DEFAULT_MAINNET_PORT));
        return 'http://' + host + ':' + port;
    }

}
