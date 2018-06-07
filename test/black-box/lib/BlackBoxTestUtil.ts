import { app } from '../../../src/app';

import { api, rpc, ApiOptions } from './api';
import { Commands } from '../../../src/api/commands/CommandEnumType';
import { CreatableModel } from '../../../src/api/enums/CreatableModel';
import * as _ from 'lodash';
import * as resources from 'resources';
import { LoggerConfig } from '../../../src/config/LoggerConfig';
import { Logger as LoggerType } from '../../../src/core/Logger';
import { AddressType } from '../../../src/api/enums/AddressType';

import * as addressCreateRequestSHIPPING_OWN from '../../testdata/createrequest/addressCreateRequestSHIPPING_OWN.json';
import { MessageException } from '../../../src/api/exceptions/MessageException';

export class BlackBoxTestUtil {

    public log: LoggerType = new LoggerType(__filename);
    private node;

    constructor(node: number = 0) {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = process.env.JASMINE_TIMEOUT;
        new LoggerConfig().configure();
        this.node = node;
    }

    /**
     * clean the db, also seeds the default data
     *
     * @returns {Promise<void>}
     */
    public async cleanDb(): Promise<any> {

        this.log.debug('cleanDb, this.node', this.node);
        const res = await this.rpc(Commands.DATA_ROOT.commandName, [Commands.DATA_CLEAN.commandName]);
        res.expectJson();
        res.expectStatusCode(200);
        return { result: 'success' };

    }

    /**
     * add your custom data
     *
     * @param model
     * @param data
     * @returns {Promise<any>}
     */
    public async addData(model: CreatableModel, data: any): Promise<any> {
        const res = await this.rpc(Commands.DATA_ROOT.commandName, [Commands.DATA_ADD.commandName, model.toString(), JSON.stringify(data)]);
        res.expectJson();
        expect(res.error).toBe(null);
        res.expectStatusCode(200);
        return res.getBody()['result'];
    }

    /**
     * generate real looking test data
     *
     * @param model - CreatableModel
     * @param amount - amount of models to create
     * @param withRelated - return full related model data or just id's, defaults to true
     * @param generateParams
     * @returns {Promise<any>}
     */
    public async generateData(model: CreatableModel, amount: number = 1, withRelated: boolean = true, generateParams: boolean[] = []): Promise<any> {
        const params = [Commands.DATA_GENERATE.commandName, model.toString(), amount, withRelated]
            .concat(generateParams);
        const res: any = await this.rpc(Commands.DATA_ROOT.commandName, params);
        res.expectJson();
        res.expectStatusCode(200);
        return res.getBody()['result'];
    }

    /**
     *
     * @param {boolean} generateShippingAddress, default true
     * @returns {Promise<"resources".Profile>}
     */
    public async getDefaultProfile(generateShippingAddress: boolean = true): Promise<resources.Profile> {
        const res: any = await this.rpc(Commands.PROFILE_ROOT.commandName, [Commands.PROFILE_GET.commandName, 'DEFAULT']);

        res.expectJson();
        res.expectStatusCode(200);

        const defaultProfile = res.getBody()['result'];

        if (_.isEmpty(defaultProfile.ShippingAddresses
            || _.find(defaultProfile.ShippingAddresses, (address: resources.Address) => {
                    return AddressType.SHIPPING_OWN === address.type;
        }) === undefined )) {

            if (generateShippingAddress) {
                this.log.debug('Adding a missing ShippingAddress for the default Profile.');

                // if default profile doesnt have a shipping address, add it
                // TODO: generate a random address
                const addCommandParams = [
                    Commands.ADDRESS_ADD.commandName,
                    defaultProfile.id,
                    addressCreateRequestSHIPPING_OWN.firstName,
                    addressCreateRequestSHIPPING_OWN.lastName,
                    addressCreateRequestSHIPPING_OWN.title,
                    addressCreateRequestSHIPPING_OWN.addressLine1,
                    addressCreateRequestSHIPPING_OWN.addressLine2,
                    addressCreateRequestSHIPPING_OWN.city,
                    addressCreateRequestSHIPPING_OWN.state,
                    addressCreateRequestSHIPPING_OWN.country,
                    addressCreateRequestSHIPPING_OWN.zipCode
                ];

                // create address for default profile
                const addressRes: any = await this.rpc(Commands.ADDRESS_ROOT.commandName, addCommandParams);
                addressRes.expectJson();
                addressRes.expectStatusCode(200);

            }

            // get the updated profile
            const profileRes: any = await this.rpc(Commands.PROFILE_ROOT.commandName, [Commands.PROFILE_GET.commandName, 'DEFAULT']);
            return profileRes.getBody()['result'];
        } else {
            return defaultProfile;
        }
    }

    public async getRandomBase64Image(): Promise<string> {
/*
        return await require('request')({
            url: 'https://picsum.photos/200/300/?random'
        }, function (e,r,b) {
            const type    = r.headers['content-type'];
            const prefix  = 'data:' + type + ';base64,';
            const base64  = new Buffer(b, 'binary').toString('base64');
            const dataURI = prefix + base64;
            return dataURI;
        });
*/
        const request = require('request').defaults({ encoding: 'base64' });

        const result = await request.get('https://picsum.photos/200/300/?random', (error, response, body) => {
            if (!error && response.statusCode === 200) {
                return 'data:' + response.headers['content-type'] + ';base64,' + new Buffer(body).toString('base64');
            }
        });
        return result;
    }

    /**
     * get default market
     *
     * @returns {Promise<any>}
     */
    public async getDefaultMarket(): Promise<resources.Market> {
        const res: any = await this.rpc(Commands.MARKET_ROOT.commandName, [Commands.MARKET_LIST.commandName]);
        res.expectJson();
        res.expectStatusCode(200);
        const result: resources.Market[] = res.getBody()['result'];
        // get the commandType for the method name
        return _.find(result, o => o.name === 'DEFAULT');
    }

    public async rpc(method: string, params: any[] = [], logError: boolean = true): Promise<any> {
        const response = await rpc(method, params, this.node);
        if (logError && response.error) {
            this.log.error(response.error.error.message);
        }
        return response;
    }

    /**
     * wait for given amount of time
     *
     * @param {number} maxSeconds
     * @returns {Promise<boolean>}
     */
    public async waitFor(maxSeconds: number): Promise<boolean> {
        for (let i = 0; i < maxSeconds; i++) {
            this.log.debug('waiting... ');
            await this.waitTimeOut(1000);
        }
        return true;
    }

    /**
     *
     * @param {string} method
     * @param {any[]} params
     * @param {number} maxSeconds
     * @param {number} waitForStatusCode
     * @param {string} waitForObjectProperty
     * @param waitForObjectPropertyValue
     * @returns {Promise<any>}
     */
    public async rpcWaitFor(method: string, params: any[] = [], maxSeconds: number = 10, waitForStatusCode: number = 200,
                            waitForObjectProperty?: string, waitForObjectPropertyValue?: any ): Promise<any> {

        this.log.debug('==[ rpcWaitFor ]=============================================================================');
        this.log.debug('command: ' + method + ' ' + params.toString());
        this.log.debug('waiting for StatusCode: ' + waitForStatusCode);
        this.log.debug('waiting for ObjectProperty: ' + waitForObjectProperty);
        this.log.debug('waiting for ObjectPropertyValue: ' + JSON.stringify(waitForObjectPropertyValue));
        this.log.debug('=============================================================================================');

        let errorCount = 0;

        for (let i = 0; i < maxSeconds; i++) {

            // call every 5 seconds
            if (i % 5 === 0) {
                const response: any = await this.rpc(method, params, false);

                if (response.error) {
                    errorCount++;
                    if (errorCount < 5 || errorCount % 15 === 0) {
                        this.log.error(response.error.error.message);
                    }
                    if (errorCount === 5) {
                        this.log.error('... posting every 15th from now on...');
                    }

                } else if (waitForStatusCode === response.res.statusCode) {
                    if (waitForObjectProperty) {
                        const result = response.getBody()['result'];

                        // this.log.debug('result: ' + JSON.stringify(result, null, 2));

                        const objectPropertyValue = !_.isEmpty(result) ? _.get(result, waitForObjectProperty) : null;

                        // this.log.debug('typeof waitForObjectPropertyValue: ' + typeof waitForObjectPropertyValue);
                        // this.log.debug('waitForObjectPropertyValue.toString(): ' + waitForObjectPropertyValue.toString());
                        // this.log.debug('objectPropertyValue: ' + objectPropertyValue);

                        if (objectPropertyValue === waitForObjectPropertyValue) {
                            this.log.debug('success! statusCode === ' + waitForStatusCode + ' && ' + waitForObjectProperty + ' === ' + waitForObjectPropertyValue);
                            return response;
                        } else {

                            errorCount++;

                            if (errorCount < 5 || errorCount % 15 === 0) {
                                this.log.error(waitForObjectProperty + ': ' + objectPropertyValue + ' ' + ' !== ' + waitForObjectPropertyValue);
                            }
                            if (errorCount === 5) {
                                this.log.error('... posting every 15th from now on...');
                            }

                            // do not throw here for now.
                            // for example bid search will not throw an exception like findOne so the statusCode === 200,
                            // but we need to keep on querying until correct value is returned.
                            // todo: it should be configurable how this works
                            // throw new MessageException('rpcWaitFor received non-matching waitForObjectPropertyValue: ' + waitForObjectPropertyValue);
                        }
                    } else {
                        this.log.debug('success! statusCode === ' + waitForStatusCode);
                        return response;
                    }
                } else {
                    this.log.debug('wtf?! not expecting this: ', response);
                }
            }

            // try again
            await this.waitTimeOut(1000);
        }

        this.log.error('rpcWaitFor did not receive expected response within given time.');
        throw new MessageException('rpcWaitFor did not receive expected response within given time.');
    }

    private waitTimeOut(timeoutMs: number): Promise<void> {

        return new Promise((resolve) => {
            setTimeout(() => {
                resolve();
            }, timeoutMs);
        });
    }

}


