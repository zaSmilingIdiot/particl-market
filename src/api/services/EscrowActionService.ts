import { inject, named } from 'inversify';
import { Logger as LoggerType } from '../../core/Logger';
import { Types, Core, Targets, Events } from '../../constants';
import * as resources from 'resources';
import { MarketplaceEvent } from '../messages/MarketplaceEvent';

import { EventEmitter } from 'events';
import { ActionMessageService } from './ActionMessageService';
import { EscrowService } from './EscrowService';
import { ListingItemService } from './ListingItemService';
import { MessageException } from '../exceptions/MessageException';
import * as _ from 'lodash';
import { MarketplaceMessage } from '../messages/MarketplaceMessage';
import { SmsgSendResponse } from '../responses/SmsgSendResponse';
import { OrderFactory } from '../factories/OrderFactory';
import { OrderService } from './OrderService';
import { SmsgService } from './SmsgService';
import { CoreRpcService } from './CoreRpcService';
import { EscrowFactory } from '../factories/EscrowFactory';
import { EscrowMessageType } from '../enums/EscrowMessageType';
import { BidMessageType } from '../enums/BidMessageType';
import { EscrowRequest } from '../requests/EscrowRequest';
import { OrderStatus } from '../enums/OrderStatus';
import { Output } from 'resources';
import { NotImplementedException } from '../exceptions/NotImplementedException';
import { OrderItemObjectService } from './OrderItemObjectService';
import { OrderItemObjectCreateRequest } from '../requests/OrderItemObjectCreateRequest';
import { OrderItemObjectUpdateRequest } from '../requests/OrderItemObjectUpdateRequest';
import { EscrowMessage } from '../messages/EscrowMessage';
import { OrderItemUpdateRequest } from '../requests/OrderItemUpdateRequest';
import { OrderItemService } from './OrderItemService';
import { OrderSearchParams } from '../requests/OrderSearchParams';
import { LockedOutputService } from './LockedOutputService';
import { BidDataValue } from '../enums/BidDataValue';

import { OutputData } from './BidActionService';
import { BidService } from '../services/BidService';

export class EscrowActionService {

    public log: LoggerType;

    constructor(
        @inject(Types.Service) @named(Targets.Service.ActionMessageService) public actionMessageService: ActionMessageService,
        @inject(Types.Service) @named(Targets.Service.EscrowService) public escrowService: EscrowService,
        @inject(Types.Service) @named(Targets.Service.ListingItemService) public listingItemService: ListingItemService,
        @inject(Types.Service) @named(Targets.Service.SmsgService) public smsgService: SmsgService,
        @inject(Types.Service) @named(Targets.Service.OrderService) public orderService: OrderService,
        @inject(Types.Service) @named(Targets.Service.OrderItemService) public orderItemService: OrderItemService,
        @inject(Types.Service) @named(Targets.Service.OrderItemObjectService) public orderItemObjectService: OrderItemObjectService,
        @inject(Types.Service) @named(Targets.Service.CoreRpcService) private coreRpcService: CoreRpcService,
        @inject(Types.Service) @named(Targets.Service.LockedOutputService) private lockedOutputService: LockedOutputService,
        @inject(Types.Service) @named(Targets.Service.BidService) private bidService: BidService,
        @inject(Types.Factory) @named(Targets.Factory.EscrowFactory) private escrowFactory: EscrowFactory,
        @inject(Types.Factory) @named(Targets.Factory.OrderFactory) private orderFactory: OrderFactory,
        @inject(Types.Core) @named(Core.Events) public eventEmitter: EventEmitter,
        @inject(Types.Core) @named(Core.Logger) public Logger: typeof LoggerType
    ) {
        this.log = new Logger(__filename);
        this.configureEventListeners();
    }

    /**
     * Send the lock message for the given OrderItem
     *
     * @param {EscrowRequest} escrowRequest
     * @returns {Promise<SmsgSendResponse>}
     */
    public async lock(escrowRequest: EscrowRequest): Promise<SmsgSendResponse> {

        this.validateEscrowRequest(escrowRequest);

        // unlock and remove the locked outputs from db before sending the rawtx
        const buyerSelectedOutputs = this.getValueFromOrderItemObjects(BidDataValue.BUYER_OUTPUTS, escrowRequest.orderItem.OrderItemObjects);
        await this.lockedOutputService.destroyLockedOutputs(buyerSelectedOutputs);
        const unlockSuccess = await this.lockedOutputService.unlockOutputs(buyerSelectedOutputs);

        if (unlockSuccess) {
            // generate rawtx and update it in the db
            const rawtx = await this.createRawTx(escrowRequest);
            const updatedRawTx = await this.updateRawTxOrderItemObject(escrowRequest.orderItem.OrderItemObjects, rawtx);

            await this.updateOrderItemStatus(escrowRequest.orderItem, OrderStatus.ESCROW_LOCKED);

            return await this.createAndSendMessage(escrowRequest, rawtx);

        } else {
            throw new MessageException('Failed to unlock the locked outputs.');
        }

    }


    /**
     *
     * @param {EscrowRequest} escrowRequest
     * @returns {Promise<SmsgSendResponse>}
     */
    public async refund(escrowRequest: EscrowRequest): Promise<SmsgSendResponse> {

        throw new NotImplementedException();

        // todo: refactor lock/refund/release since they're pretty much the same
        // todo: add @validate to EscrowLockRequest
/*
        const orderItem = escrowRequest.orderItem;
        const escrow = orderItem.Bid.ListingItem.PaymentInformation.Escrow;

        if (_.isEmpty(orderItem)) {
            throw new MessageException('OrderItem not found!');
        }

        if (_.isEmpty(escrow)) {
            throw new MessageException('Escrow not found!');
        }

        const listingItemModel = await this.listingItemService.findOneByHash(orderItem.itemHash);
        const listingItem = listingItemModel.toJSON();

        // generate rawtx
        const rawtx = await this.createRawTx(escrowRequest, listingItem);

        const updatedRawTx = await this.updateRawTxOrderItemObject(orderItem.OrderItemObjects, rawtx);

        // update OrderStatus
        const newOrderStatus = OrderStatus.CHANGE;
        const updatedOrderItem = await this.updateOrderItemStatus(orderItem, newOrderStatus);

        // use escrowfactory to generate the refund message
        const escrowActionMessage = await this.escrowFactory.getMessage(escrowRequest, rawtx);

        const marketPlaceMessage = {
            version: process.env.MARKETPLACE_VERSION,
            mpaction: escrowActionMessage
        } as MarketplaceMessage;

        return await this.smsgService.smsgSend(orderItem.Order.seller, orderItem.Order.buyer, marketPlaceMessage, false);
*/
    }

    /**
     * Seller sends EscrowReleaseMessage (MPA_RELEASE) to the Buyer, indicating that the item has been sent.
     * Buyer sends EscrowReleaseMessage (MPA_RELEASE) to the Seller, indicating that the sent item has been received.
     *
     * @param {EscrowRequest} escrowRequest
     * @returns {Promise<SmsgSendResponse>}
     */
    public async release(escrowRequest: EscrowRequest): Promise<SmsgSendResponse> {

        this.validateEscrowRequest(escrowRequest);

        const orderItem = escrowRequest.orderItem;
        const escrow = orderItem.Bid.ListingItem.PaymentInformation.Escrow;

        // generate rawtx and update it in the db
        const rawtx = await this.createRawTx(escrowRequest);
        const updatedRawTx = await this.updateRawTxOrderItemObject(orderItem.OrderItemObjects, rawtx);

        // update OrderStatus
        const isMyListingItem = !_.isEmpty(orderItem.Bid.ListingItem.ListingItemTemplate);
        const newOrderStatus = isMyListingItem ? OrderStatus.SHIPPING : OrderStatus.COMPLETE;
        await this.updateOrderItemStatus(orderItem, newOrderStatus);

        return await this.createAndSendMessage(escrowRequest, rawtx);
    }

    /** Copied and pasted from BidActionService.
     *   TODO: Delete when those two files are merged.
     *
     * @param {string} key
     * @param {"resources".BidData[]} bidDatas
     * @returns {any}
     */
    public getValueFromBidDatas(key: string, bidDatas: any): any {
        const value = bidDatas.find(kv => kv.dataId === key);
        if (value) {
            return value.dataValue;
        } else {
            this.log.error('Missing BidData value for key: ' + key);
            throw new MessageException('Missing BidData value for key: ' + key);
        }
    }

    /** Copied and pasted from BidActionService.
     *   TODO: Delete when those two files are merged.
     *
     * find unspent outputs for the required amount
     *
     * @param {number} requiredAmount
     * @returns {Promise<any>}
     */
    public async findUnspentOutputs(requiredAmount: number, unspentOutputs): Promise<OutputData> {
        if (!unspentOutputs || unspentOutputs.length === 0) {
            this.log.warn('No unspent outputs');
            throw new MessageException('No unspent outputs');
        }

        this.log.debug('unspent outputs amount: ', unspentOutputs.length);

        const selectedOutputs: Output[] = [];
        let selectedOutputsSum = 0;
        let selectedOutputsChangeAmount = 0;

        unspentOutputs.find(output => {
            if (output.spendable && output.solvable) {
                selectedOutputsSum += output.amount;
                selectedOutputs.push({
                    txid: output.txid,
                    vout: output.vout,
                    amount: output.amount
                });
            }

            // todo: get the actual fee 
            // check whether we have collected enough outputs to pay for the item and
            // calculate the change amount
            // requiredAmount, for MPA_BID: (totalPrice * 2)
            // requiredAmount, for MPA_ACCEPT: totalPrice

            if (selectedOutputsSum > requiredAmount) {
                selectedOutputsChangeAmount = +(selectedOutputsSum - requiredAmount - 0.0002).toFixed(8);
                return true;
            }
            return false;
        });

        if (selectedOutputsSum < requiredAmount) {
            this.log.warn('Not enough funds');
            throw new MessageException('Not enough funds');
        }

        // todo: type
        const response: OutputData = {
            outputs: selectedOutputs,
            outputsSum: selectedOutputsSum,
            outputsChangeAmount: selectedOutputsChangeAmount
        };

        this.log.debug('selected outputs:', JSON.stringify(response, null, 2));

        return response;
    }

    /** Copied and pasted from BidActionService.
     *   TODO: Delete when those two files are merged.
     *
     * @param {string} escrowMultisigAddress
     * @param {string} sellerEscrowChangeAddress
     * @param {string} buyerEscrowChangeAddress
     * @param {OutputData} sellerSelectedOutputData
     * @param {OutputData} buyerSelectedOutputData
     * @param {string} sellerEscrowPubAddressPublicKey
     * @param {string} buyerEscrowPubAddressPublicKey
     * @param {number} itemTotalPrice
     * @param {string} listingItemHash
     * @returns {any}
     */
    public createTxOut(escrowMultisigAddress: string,
                       sellerEscrowChangeAddress: string,
                       buyerEscrowChangeAddress: string,
                       sellerSelectedOutputData: OutputData,
                       buyerSelectedOutputData: OutputData,
                       sellerEscrowPubAddressPublicKey: string,
                       buyerEscrowPubAddressPublicKey: string,
                       itemTotalPrice: number,
                       listingItemHash: string): any {

        // txout: {
        //   escrowMultisigAddress: amount that should be escrowed
        //   sellerEscrowChangeAddress: sellers change amount
        //   buyerEscrowChangeAddress: buyers change amount
        // }
        const txout = {};


        this.log.debug('sellerEscrowPubAddressPublicKey: ', sellerEscrowPubAddressPublicKey);
        this.log.debug('buyerEcrowPubAddressPublicKey: ', buyerEscrowPubAddressPublicKey);
        this.log.debug('listingItem.hash: ', listingItemHash);

        txout[escrowMultisigAddress] = +(itemTotalPrice * 3).toFixed(8); // TODO: Shipping... ;(
        txout[sellerEscrowChangeAddress] = sellerSelectedOutputData.outputsChangeAmount;
        txout[buyerEscrowChangeAddress] = buyerSelectedOutputData.outputsChangeAmount;


        // this.log.debug('buyerOutputs: ', JSON.stringify(buyerSelectedOutputData.outputs, null, 2));

        // TODO: Verify that buyers outputs are unspent?? :/
        // TODO: Refactor reusable logic. and verify / validate buyer change.

        if (!_.isEmpty(buyerSelectedOutputData.outputs)) {
            let buyerOutputsSum = 0;
            let buyerOutputsChangeAmount = 0;

            buyerSelectedOutputData.outputs.forEach(output => {
                const amount = output.amount || 0;
                buyerOutputsSum += amount;
                if (buyerOutputsSum > itemTotalPrice * 2) { // TODO: Ratio
                    buyerOutputsChangeAmount = +(buyerOutputsSum - (itemTotalPrice * 2) - 0.0001).toFixed(8); // TODO: Get actual fee...
                    return;
                }
            });

            // todo: calculate buyers requiredAmount from Ratio
            // check that buyers outputs contain enough funds
            if (buyerOutputsSum < itemTotalPrice * 2) {
                this.log.warn('Buyers outputs do not contain enough funds!');
                throw new MessageException('Buyers outputs do not contain enough funds!');
            }
            txout[buyerEscrowChangeAddress] = buyerSelectedOutputData.outputsChangeAmount;

        } else {
            this.log.error('Buyer didn\'t supply outputs!');
            throw new MessageException('Buyer didn\'t supply outputs!'); // TODO: proper message for no outputs :P
        }

        // TODO: Decide if we want this on the blockchain or not...
        // TODO: Think about how to recover escrow information to finalize transactions should client pc / database crash..

        //
        // txout['data'] = unescape(encodeURIComponent(data.params[0]))
        //    .split('').map(v => v.charCodeAt(0).toString(16)).join('').substr(0, 80);
        //

        return txout;
    }

    private validateEscrowRequest(escrowRequest: EscrowRequest): boolean {

        const orderItem = escrowRequest.orderItem;
        const escrow = orderItem.Bid.ListingItem.PaymentInformation.Escrow;

        if (_.isEmpty(orderItem)) {
            throw new MessageException('OrderItem not found!');
        }

        if (_.isEmpty(escrow)) {
            throw new MessageException('Escrow not found!');
        }

        // todo: add sanity checks and validate that values are correct and outputs unspent, etc


        return true;
    }

    private async createAndSendMessage(escrowRequest: EscrowRequest, rawtx: string): Promise<SmsgSendResponse> {

        // use escrowfactory to generate the message
        const escrowActionMessage = await this.escrowFactory.getMessage(escrowRequest, rawtx);

        const marketPlaceMessage = {
            version: process.env.MARKETPLACE_VERSION,
            mpaction: escrowActionMessage
        } as MarketplaceMessage;

        const isMyListingItem = !_.isEmpty(escrowRequest.orderItem.Bid.ListingItem.ListingItemTemplate);
        const sendFromAddress = isMyListingItem ? escrowRequest.orderItem.Order.seller : escrowRequest.orderItem.Order.buyer;
        const sendToAddress = isMyListingItem ? escrowRequest.orderItem.Order.buyer : escrowRequest.orderItem.Order.seller;

        return await this.smsgService.smsgSend(sendFromAddress, sendToAddress, marketPlaceMessage, false);
    }

    /**
     * find Order, using buyer, seller and Order.OrderItem.itemHash
     *
     * @param {string} listingItemHash
     * @param {string} buyerAddress
     * @param {string} sellerAddress
     * @returns {Promise<module:resources.Order>}
     */
    private async findOrder(listingItemHash: string, buyerAddress: string, sellerAddress: string): Promise<resources.Order> {

        const orderSearchParams = {
            listingItemHash,
            buyerAddress,
            sellerAddress
        } as OrderSearchParams;

        const ordersModel = await this.orderService.search(orderSearchParams);
        const orders = ordersModel.toJSON();

        if (orders.length === 0) {
            this.log.error('Order not found for EscrowMessage.');
            throw new MessageException('Order not found for EscrowMessage.');
        }

        if (orders.length > 1) {
            this.log.error('Multiple Orders found for EscrowMessage, this should not happen.');
            throw new MessageException('Multiple Orders found for EscrowMessage.');
        }
        return orders[0];
    }

    /**
     *
     * @param {MarketplaceEvent} event
     * @returns {Promise<module:resources.Order>}
     */
    private async processLockEscrowReceivedEvent(event: MarketplaceEvent): Promise<resources.Order> {

        // TODO: EscrowMessage should contain Order.hash to identify the item in case there are two different Orders
        // with the same item for same buyer. Currently, buyer can only bid once for an item, but this might not be the case always.

        const message = event.marketplaceMessage;
        if (!message.mpaction) {   // ACTIONEVENT
            throw new MessageException('Missing mpaction.');
        }

        const escrowMessage = message.mpaction as EscrowMessage;
        const listingItemHash = escrowMessage.item;

        // find the ListingItem
        const listingItemModel = await this.listingItemService.findOneByHash(listingItemHash);
        const listingItem = listingItemModel.toJSON();

        const seller = listingItem.seller;
        const buyer = listingItem.seller === event.smsgMessage.from ? event.smsgMessage.to : event.smsgMessage.from;

        // save ActionMessage
        const actionMessageModel = await this.actionMessageService.createFromMarketplaceEvent(event, listingItem);
        const actionMessage = actionMessageModel.toJSON();

        // find the Order, using buyer, seller and Order.OrderItem.itemHash
        const order: resources.Order = await this.findOrder(listingItemHash, buyer, seller);
        const orderItem = _.find(order.OrderItems, (o: resources.OrderItem) => {
            return o.itemHash === listingItemHash;
        });

        if (orderItem) {

            // update rawtx
            const rawtx = escrowMessage.escrow.rawtx;
            const updatedRawTx = await this.updateRawTxOrderItemObject(orderItem.OrderItemObjects, rawtx);
            this.log.info('processLock(), rawtx:', JSON.stringify(updatedRawTx, null, 2));

            const updatedOrderItem = await this.updateOrderItemStatus(orderItem, OrderStatus.ESCROW_LOCKED);

            // remove the sellers locked outputs
            const selectedOutputs = this.getValueFromOrderItemObjects(BidDataValue.SELLER_OUTPUTS, orderItem.OrderItemObjects);
            await this.lockedOutputService.destroyLockedOutputs(selectedOutputs);

            // TODO: do whatever else needs to be done


        } else {
            this.log.error('OrderItem not found for EscrowMessage.');
            throw new MessageException('OrderItem not found for EscrowMessage.');
        }

        return order;
    }

    private async processReleaseEscrowReceivedEvent(event: MarketplaceEvent): Promise<resources.Order> {

        const message = event.marketplaceMessage;
        if (!message.mpaction) {   // ACTIONEVENT
            throw new MessageException('Missing mpaction.');
        }

        const escrowMessage = message.mpaction as EscrowMessage;
        const listingItemHash = escrowMessage.item;

        // find the ListingItem
        const listingItemModel = await this.listingItemService.findOneByHash(listingItemHash);
        const listingItem: resources.ListingItem = listingItemModel.toJSON();

        const seller = listingItem.seller;
        const buyer = listingItem.seller === event.smsgMessage.from ? event.smsgMessage.to : event.smsgMessage.from;
        const isMyListingItem = !!listingItem.ListingItemTemplate;

        // save ActionMessage
        const actionMessageModel = await this.actionMessageService.createFromMarketplaceEvent(event, listingItem);
        const actionMessage = actionMessageModel.toJSON();

        // find the Order, using buyer, seller and Order.OrderItem.itemHash
        const order: resources.Order = await this.findOrder(listingItemHash, buyer, seller);
        const orderItem = _.find(order.OrderItems, (o: resources.OrderItem) => {
            return o.itemHash === listingItemHash;
        });

        if (orderItem) {

            // update rawtx
            const rawtx = escrowMessage.escrow.rawtx;
            const updatedRawTx = await this.updateRawTxOrderItemObject(orderItem.OrderItemObjects, rawtx);


            const newOrderStatus = isMyListingItem ? OrderStatus.COMPLETE : OrderStatus.SHIPPING;
            const updatedOrderItem = await this.updateOrderItemStatus(orderItem, newOrderStatus);

            // TODO: do whatever else needs to be done


        } else {
            this.log.error('OrderItem not found for EscrowMessage.');
            throw new MessageException('OrderItem not found for EscrowMessage.');
        }

        return order;
    }

    private async processRequestRefundEscrowReceivedEvent(event: MarketplaceEvent): Promise<resources.ActionMessage> {

        // find the ListingItem
        const message = event.marketplaceMessage;
        if (!message.mpaction) {   // ACTIONEVENT
            throw new MessageException('Missing mpaction.');
        }
        const listingItemModel = await this.listingItemService.findOneByHash(message.mpaction.item);
        const listingItem = listingItemModel.toJSON();

        // first save it
        const actionMessageModel = await this.actionMessageService.createFromMarketplaceEvent(event, listingItem);
        const actionMessage = actionMessageModel.toJSON();

        // todo: update order
        // TODO: do whatever else needs to be done

        return actionMessage;
    }

    private async processRefundEscrowReceivedEvent(event: MarketplaceEvent): Promise<resources.ActionMessage> {

        // find the ListingItem
        const message = event.marketplaceMessage;
        if (!message.mpaction) {   // ACTIONEVENT
            throw new MessageException('Missing mpaction.');
        }
        const listingItemModel = await this.listingItemService.findOneByHash(message.mpaction.item);
        const listingItem = listingItemModel.toJSON();

        // first save it
        const actionMessageModel = await this.actionMessageService.createFromMarketplaceEvent(event, listingItem);
        const actionMessage = actionMessageModel.toJSON();

        // todo: update order
        // TODO: do whatever else needs to be done

        return actionMessage;
    }

    /**
     * Creates rawtx based on params
     *
     * @param request
     * @param escrow
     * @returns {string}
     */
    private async createRawTx(request: EscrowRequest): Promise<string> {

        // MPA_LOCK:
        //
        //

        // MPA_RELEASE:
        // rawtx: 'The buyer sends the half signed rawtx which releases the escrow and payment.
        // The vendor then recreates the whole transaction (check ouputs, inputs, scriptsigs
        // and the fee), verifying that buyer\'s rawtx is indeed legitimate. The vendor then
        // signs the rawtx and broadcasts it.'

        // MPA_REFUND
        // rawtx: 'The vendor decodes the rawtx from MP_REQUEST_REFUND and recreates the whole
        // transaction (check ouputs, inputs, scriptsigs and the fee), verifying that buyer\'s
        // rawtx is indeed legitimate. The vendor then signs the rawtx and sends it to the buyer.
        // The vendor can decide to broadcast it himself.'

        const orderItem: resources.OrderItem = request.orderItem;
        const bid: resources.Bid = orderItem.Bid;
        const isMyListingItem = !_.isEmpty(bid.ListingItem.ListingItemTemplate);

        // this.log.debug('createRawTx(), orderItem:', JSON.stringify(orderItem, null, 2));

        // rawtx is potentially the txid in case of ESCROW_LOCKED.
        let rawtx = this.getValueFromOrderItemObjects(BidDataValue.RAW_TX, orderItem.OrderItemObjects);
        const buyerEscrowPubAddressPublicKey = this.getValueFromOrderItemObjects(BidDataValue.BUYER_PUBKEY, orderItem.OrderItemObjects);
        const sellerEscrowPubAddressPublicKey = this.getValueFromOrderItemObjects(BidDataValue.SELLER_PUBKEY, orderItem.OrderItemObjects);
        const pubkeys = [sellerEscrowPubAddressPublicKey, buyerEscrowPubAddressPublicKey].sort();
        // todo: does the order of the pubkeys matter and how?

        this.log.debug('createRawTx(), rawtx:', rawtx);
        this.log.debug('createRawTx(), pubkeys:', pubkeys);

        if (!bid || bid.action !== BidMessageType.MPA_ACCEPT
            || !orderItem || !orderItem.OrderItemObjects || orderItem.OrderItemObjects.length === 0
            || !rawtx || !pubkeys) {

            this.log.error('Not enough valid information to finalize escrow');
            throw new MessageException('Not enough valid information to finalize escrow');
        }

        this.log.debug('createRawTx(), request.action:', request.action);

        switch (request.action) {

            case EscrowMessageType.MPA_LOCK:

                if (isMyListingItem) {
                    throw new MessageException('Seller can\'t lock an Escrow.');
                }

                // Add Escrow address
                // TODO: Way to recover escrow address should we lose it
                const escrowMultisigAddress = await this.coreRpcService.addMultiSigAddress(
                    2,
                    pubkeys,
                    '_escrow_' + orderItem.itemHash
                );
                this.log.debug('createRawTx(), escrowMultisigAddress:', JSON.stringify(escrowMultisigAddress, null, 2));

                // validate the escrow amounts
                const decodedTx = await this.coreRpcService.decodeRawTransaction(rawtx);
                this.log.debug('createRawTx(), decoded:', JSON.stringify(decodedTx, null, 2));

                // Validation of received Tx before completing the transaction
                /*
                 * First generate a tx from the original data
                 */
                // Copy and pasted from BidActionService.generateBidDatasForMPA_ACCEPT
                // todo: price type...
                this.log.debug('createRawTx(), bid:', JSON.stringify(bid, null, 2));
                let listingItem: any = await this.listingItemService.findOneByHash(bid.ListingItem.hash, true);
                listingItem = listingItem.toJSON();
                const shippingPrice = listingItem.PaymentInformation.ItemPrice.ShippingPrice;
                const basePrice = listingItem.PaymentInformation.ItemPrice.basePrice;
                const shippingPriceMax = Math.max(shippingPrice.international, shippingPrice.domestic);
                const totalPrice = basePrice + shippingPriceMax; // TODO: Determine if local or international...
                const requiredAmount = totalPrice; // todo: sellers required amount
                // todo: calculate totalprice using the items escrowratio

                // get all unspent transaction outputs
                let sellerUnspentOutputs: Output[];
                let sellerSelectedOutputData: OutputData;
                try {
                    sellerUnspentOutputs = await this.coreRpcService.listUnspent(1, 99999999, [], false);
                    sellerSelectedOutputData = await this.findUnspentOutputs(requiredAmount, sellerUnspentOutputs);
                } catch (ex) {
                    this.log.error('createRawTx(): 100: ' + ex);
                    throw ex;
                }

                // create OutputData for buyer
                try {
                    let bidFull = await this.bidService.findOne(bid.id, true);
                    bidFull = bidFull.toJSON();
                    this.log.debug('bidFull = ' + JSON.stringify(bidFull, null, 2));
                    const buyerSelectedOutputs: Output[] = JSON.parse(this.getValueFromBidDatas(BidDataValue.BUYER_OUTPUTS, bidFull.BidDatas));
                    const buyerRequiredAmount = totalPrice * 2;

                    this.log.debug('shippingPrice = ' + shippingPrice);
                    this.log.debug('basePrice = ' + basePrice);
                    this.log.debug('shippingPriceMax = ' + shippingPriceMax);
                    this.log.debug('totalPrice = ' + totalPrice);
                    this.log.debug('requiredAmount = ' + requiredAmount);
                    this.log.debug('buyerRequiredAmount = ' + buyerRequiredAmount);

                    const buyerSelectedOutputData: OutputData = await this.findUnspentOutputs(buyerRequiredAmount, buyerSelectedOutputs);

                    /// TODO: print statements print prices here or something
                    /// Not having enough might be ok here if transaction already happened
                    /// May just want to look at if created tx matches

                    const createdTx = this.createTxOut(escrowMultisigAddress,
                           orderItem.Order.seller,
                           orderItem.Order.buyer,
                           sellerSelectedOutputData,
                           buyerSelectedOutputData,
                           sellerEscrowPubAddressPublicKey,
                           buyerEscrowPubAddressPublicKey,
                           totalPrice,
                           orderItem.itemHash);
                    this.log.debug('createTxOut(), created:', JSON.stringify(createdTx, null, 2));
                } catch (ex) {
                    this.log.error('createRawTx(): 200: ' + ex);
                    throw ex;
                }

                /*
                 * TODO: Then check it matches the one received
                 */

                // buyer signs the escrow tx, which should complete
                const signedForLock = await this.signRawTx(rawtx, true);
                this.log.debug('createRawTx(), signedForLock:', JSON.stringify(signedForLock, null, 2));

                // TODO: This requires user interaction, so should be elsewhere possibly?
                // TODO: Save TXID somewhere maybe??!
                const response = await this.coreRpcService.sendRawTransaction(signedForLock.hex);

                this.log.debug('createRawTx(), response:', JSON.stringify(response, null, 2));
                return response;

            case EscrowMessageType.MPA_RELEASE:

                if (OrderStatus.ESCROW_LOCKED === orderItem.status && isMyListingItem) {
                    // seller sends the first MPA_RELEASE, OrderStatus.ESCROW_LOCKED

                    const buyerReleaseAddress = this.getValueFromOrderItemObjects(BidDataValue.BUYER_RELEASE_ADDRESS, orderItem.OrderItemObjects);
                    this.log.debug('createRawTx(), buyerReleaseAddress:', buyerReleaseAddress);

                    if (!buyerReleaseAddress) {
                        this.log.error('Not enough valid information to finalize escrow');
                        throw new MessageException('Not enough valid information to finalize escrow');
                    }

                    const sellerReleaseAddress = await this.coreRpcService.getNewAddress(['_escrow_release'], false);
                    this.log.debug('createRawTx(), sellerReleaseAddress:', sellerReleaseAddress);

                    // rawtx is the transaction id!
                    const realrawtx = await this.coreRpcService.getRawTransaction(rawtx);
                    const decoded = await this.coreRpcService.decodeRawTransaction(realrawtx);
                    this.log.debug('createRawTx(), decoded:', JSON.stringify(decoded, null, 2));

                    const txid = decoded.txid;
                    const value = decoded.vout[0].value - 0.0001; // TODO: Proper TX Fee

                    if (!txid) {
                        this.log.error(`Transaction with not found with txid: ${txid}.`);
                        throw new MessageException(`Transaction with not found with txid: ${txid}.`);
                    }

                    const txout = {};

                    // CRITICAL TODO: Use the right ratio's...

                    // seller gets his escrow amount + buyer payment back
                    // buyer gets the escrow amount back
                    txout[sellerReleaseAddress] = +(value / 3 * 2).toFixed(8);
                    txout[buyerReleaseAddress] = +(value / 3).toFixed(8);

                    // TODO: Make sure this is the correct vout !!!
                    // TODO: loop through the vouts and check the value, but what if theres multiple outputs with same value?
                    const txInputs: Output[] = [{txid, vout: 0}];
                    rawtx = await this.coreRpcService.createRawTransaction(txInputs, txout);
                    const signed = await this.signRawTx(rawtx, false);

                    this.log.debug('createRawTx(), txInputs: ', JSON.stringify(txInputs, null, 2));
                    this.log.debug('createRawTx(), txout: ', JSON.stringify(txout, null, 2));
                    this.log.debug('createRawTx(), rawtx: ', JSON.stringify(rawtx, null, 2));
                    this.log.debug('createRawTx(), signed: ', JSON.stringify(signed, null, 2));

                    return signed.hex;

                } else if (OrderStatus.SHIPPING === orderItem.status && !isMyListingItem) {
                    // buyer sends the MPA_RELEASE, OrderStatus.SHIPPING

                    const signed = await this.signRawTx(rawtx, true);
                    this.log.debug('createRawTx(), signed: ', JSON.stringify(signed, null, 2));

                    const txid =  await this.coreRpcService.sendRawTransaction(signed.hex);
                    this.log.debug('createRawTx(), response:', JSON.stringify(txid, null, 2));
                    return txid;

                } else {
                    throw new MessageException('Something went wrong, MPA_RELEASE should not be sent at this point.');
                }

            default:
                throw new NotImplementedException();
        }
    }

    private configureEventListeners(): void {
        this.eventEmitter.on(Events.LockEscrowReceivedEvent, async (event) => {
            await this.processLockEscrowReceivedEvent(event);
        });
        this.eventEmitter.on(Events.ReleaseEscrowReceivedEvent, async (event) => {
            await this.processReleaseEscrowReceivedEvent(event);
        });
        this.eventEmitter.on(Events.RequestRefundEscrowReceivedEvent, async (event) => {
            await this.processRequestRefundEscrowReceivedEvent(event);
        });
        this.eventEmitter.on(Events.RefundEscrowReceivedEvent, async (event) => {
            await this.processRefundEscrowReceivedEvent(event);
        });
    }

    /**
     * signs rawtx and ignores errors in case tx shouldnt be complete yet.
     *
     * @param {string} rawtx
     * @param {boolean} shouldBeComplete
     * @returns {Promise<any>}
     */
    private async signRawTx(rawtx: string, shouldBeComplete?: boolean): Promise<any> {

        this.log.debug('signRawTx(): signing rawtx, shouldBeComplete:', shouldBeComplete);

        // This requires user interaction, so should be elsewhere possibly?
        // TODO: Verify that the transaction has the correct values! Very important!!! TODO TODO TODO
        const signed = await this.coreRpcService.signRawTransaction(rawtx);

        const ignoreErrors = [
            'Unable to sign input, invalid stack size (possibly missing key)',
            'Operation not valid with the current stack size'
        ];

        if (!signed
            || signed.errors
            && (!shouldBeComplete && ignoreErrors.indexOf(signed.errors[0].error) === -1)) {
            this.log.error('Error signing transaction' + signed ? ': ' + signed.errors[0].error : '');
            this.log.error('signed: ', JSON.stringify(signed, null, 2));
            throw new MessageException('Error signing transaction' + signed ? ': ' + signed.error : '');
        }

        if (shouldBeComplete) {
            if (!signed.complete) {
                this.log.error('Transaction should be complete at this stage.', JSON.stringify(signed, null, 2));
                throw new MessageException('Transaction should be complete at this stage');
            }
        } else if (signed.complete) {
            this.log.error('Transaction should not be complete at this stage, will not send insecure message');
            throw new MessageException('Transaction should not be complete at this stage, will not send insecure message');
        }

        this.log.debug('signRawTx(): signed:', JSON.stringify(signed, null, 2));

        return signed;
    }

    /**
     *
     * @param {string} key
     * @param {module:resources.OrderItemObject[]} orderItemObjects
     * @returns {any}
     */
    private getValueFromOrderItemObjects(key: string, orderItemObjects: resources.OrderItemObject[]): any {
        const value = orderItemObjects.find(kv => kv.dataId === key);
        if (value) {
            return value.dataValue[0] === '[' ? JSON.parse(value.dataValue) : value.dataValue;
        } else {
            this.log.error('Missing OrderItemObject value for key: ' + key);
            throw new MessageException('Missing OrderItemObject value for key: ' + key);
        }
    }

    /**
     * updates rawtx
     *
     * @param {module:resources.OrderItemObject[]} orderItemObjects
     * @param {string} newRawtx
     * @returns {Promise<any>}
     */
    private async updateRawTxOrderItemObject(orderItemObjects: resources.OrderItemObject[], newRawtx: string): Promise<any> {
        const rawtxObject = orderItemObjects.find(kv => kv.dataId === 'rawtx');

        if (rawtxObject) {
            const updatedOrderItemObject = await this.orderItemObjectService.update(rawtxObject.id, {
                dataId: BidDataValue.RAW_TX.toString(),
                dataValue: newRawtx
            } as OrderItemObjectUpdateRequest);
            return updatedOrderItemObject.toJSON();
        } else {
            this.log.error('OrderItemObject for rawtx not found!');
            throw new MessageException('OrderItemObject for rawtx not found!');
        }
    }

    /**
     * updates orderitems status
     *
     * @param {module:resources.OrderItem} orderItem
     * @param {OrderStatus} newOrderStatus
     * @returns {Promise<module:resources.OrderItem>}
     */
    private async updateOrderItemStatus(orderItem: resources.OrderItem, newOrderStatus: OrderStatus): Promise<resources.OrderItem> {

        const orderItemUpdateRequest = {
            itemHash: orderItem.itemHash,
            status: newOrderStatus
        } as OrderItemUpdateRequest;

        const updatedOrderItemModel = await this.orderItemService.update(orderItem.id, orderItemUpdateRequest);
        const updatedOrderItem: resources.OrderItem = updatedOrderItemModel.toJSON();
        // this.log.debug('updatedOrderItem:', JSON.stringify(updatedOrderItem, null, 2));
        return updatedOrderItem;
    }
}
