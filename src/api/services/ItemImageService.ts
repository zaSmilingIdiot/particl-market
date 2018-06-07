import * as Bookshelf from 'bookshelf';
import * as _ from 'lodash';
import { inject, named } from 'inversify';
import { Logger as LoggerType } from '../../core/Logger';
import { Types, Core, Targets } from '../../constants';
import { validate, request } from '../../core/api/Validate';
import { NotFoundException } from '../exceptions/NotFoundException';
import { ItemImageRepository } from '../repositories/ItemImageRepository';
import { ItemImage } from '../models/ItemImage';
import { ItemImageCreateRequest } from '../requests/ItemImageCreateRequest';
import { ItemImageDataCreateRequest } from '../requests/ItemImageDataCreateRequest';
import { ItemImageUpdateRequest } from '../requests/ItemImageUpdateRequest';
import { ItemImageDataService } from './ItemImageDataService';
import { ImageProcessing } from '../../core/helpers/ImageProcessing';
import { ImageTriplet } from '../../core/helpers/ImageTriplet';
import { ImageFactory } from '../factories/ImageFactory';
import { ImageVersions } from '../../core/helpers/ImageVersionEnumType';
import { MessageException } from '../exceptions/MessageException';
import { ImageDataProtocolType } from '../enums/ImageDataProtocolType';
import { ListingItemTemplate } from '../models/ListingItemTemplate';
import { ImagePostUploadRequest } from '../requests/ImagePostUploadRequest';
import { HashableObjectType } from '../../api/enums/HashableObjectType';
import * as fs from 'fs';
import { ObjectHash } from '../../core/helpers/ObjectHash';

export class ItemImageService {

    public log: LoggerType;

    constructor(
        @inject(Types.Service) @named(Targets.Service.ItemImageDataService) public itemImageDataService: ItemImageDataService,
        @inject(Types.Repository) @named(Targets.Repository.ItemImageRepository) public itemImageRepo: ItemImageRepository,
        @inject(Types.Factory) @named(Targets.Factory.ImageFactory) public imageFactory: ImageFactory,
        @inject(Types.Core) @named(Core.Logger) public Logger: typeof LoggerType
    ) {
        this.log = new Logger(__filename);
    }

    public async findAll(): Promise<Bookshelf.Collection<ItemImage>> {
        return this.itemImageRepo.findAll();
    }

    public async findOne(id: number, withRelated: boolean = true): Promise<ItemImage> {
        const itemImage = await this.itemImageRepo.findOne(id, withRelated);
        if (itemImage === null) {
            this.log.warn(`ItemImage with the id=${id} was not found!`);
            throw new NotFoundException(id);
        }
        return itemImage;
    }

    /**
     * create(), but get data from a local file instead.
     *
     * @param imageFile
     * @param {ListingItemTemplate} listingItemTemplate
     * @returns {Promise<ItemImage>}
     */
    @validate()
    public async createFile(imageFile: any, listingItemTemplate: ListingItemTemplate): Promise<ItemImage> {
        // TODO: how am i supposed to know what imageFile contains? add type to it

        // Read the file data in
        const dataStr = fs.readFileSync(imageFile.path, 'base64');
        // this.log.error('dataStr = ' + dataStr);

        // find listing item template
        // this.log.debug('imageFile.mimetype = ' + imageFile.mimetype);
        // find related itemInformation

        const itemInformation = await listingItemTemplate.related('ItemInformation').toJSON();

        const itemImageDataCreateRequest = {
            protocol: ImageDataProtocolType.LOCAL,
            encoding: 'BASE64',
            data: dataStr,
            dataId: imageFile.fieldname, // replaced with local url in factory
            imageVersion: ImageVersions.ORIGINAL.propName,
            originalMime: imageFile.mimetype,
            originalName: imageFile.originalname
        };

        const itemImageCreateRequest = {
            item_information_id: itemInformation.id,
            data: [itemImageDataCreateRequest]
        } as ItemImageCreateRequest;

        return await this.create(itemImageCreateRequest);
    }

    @validate()
    public async create( @request(ItemImageCreateRequest) data: ItemImageCreateRequest): Promise<ItemImage> {
        const startTime = new Date().getTime();

        const body = JSON.parse(JSON.stringify(data));

        // this.log.debug('create image, body: ', JSON.stringify(body, null, 2));

        // extract and remove related models from request
        const itemImageDatas: ItemImageDataCreateRequest[] = body.data;
        delete body.data;

        const protocols = Object.keys(ImageDataProtocolType)
            .map(key => (ImageDataProtocolType[key]));
        // this.log.debug('protocols: ', protocols);

        const itemImageDataOriginal = _.find(itemImageDatas, (imageData) => {
            return imageData.imageVersion === ImageVersions.ORIGINAL.propName;
        });
        // this.log.debug('itemImageDataOriginal: ', itemImageDataOriginal);

        // use the original image version to create a hash for the ItemImage
        body.hash = ObjectHash.getHash(itemImageDataOriginal, HashableObjectType.ITEMIMAGEDATA_CREATEREQUEST);

        // if the request body was valid we will create the itemImage
        const itemImage = await this.itemImageRepo.create(body);


        if (itemImageDataOriginal) {

            if (_.isEmpty(itemImageDataOriginal.protocol) ||  protocols.indexOf(itemImageDataOriginal.protocol) === -1) {
                this.log.warn(`Invalid protocol <${itemImageDataOriginal.protocol}> encountered.`);
                throw new MessageException('Invalid image protocol.');
            }

            // then create the imageDatas from the given original data
            if (!_.isEmpty(itemImageDataOriginal.data)) {
                const toVersions = [ImageVersions.LARGE, ImageVersions.MEDIUM, ImageVersions.THUMBNAIL];
                const imageDatas: ItemImageDataCreateRequest[] = await this.imageFactory.getImageDatas(itemImage.Id, itemImageDataOriginal, toVersions);

                // save all image datas
                for (const imageData of imageDatas) {
                    await this.itemImageDataService.create(imageData);
                }

                // finally find and return the created itemImage
                const newItemImage = await this.findOne(itemImage.Id);
                // this.log.debug('saved image:', JSON.stringify(newItemImage.toJSON(), null, 2));

                this.log.debug('itemImageService.create: ' + (new Date().getTime() - startTime) + 'ms');
                return newItemImage;
            } else {
                this.log.debug('itemImageService.create: ' + (new Date().getTime() - startTime) + 'ms');
                return itemImage;
            }
        } else {
            throw new MessageException('Original image data not found.');
        }
    }

    @validate()
    public async update(id: number, @request(ItemImageUpdateRequest) data: ItemImageUpdateRequest): Promise<ItemImage> {

        const body = JSON.parse(JSON.stringify(data));

        // extract and remove related models from request
        const itemImageDatas: ItemImageDataCreateRequest[] = body.data;
        delete body.data;

        // find the existing one without related
        const itemImage = await this.findOne(id, false);

        const protocols = Object.keys(ImageDataProtocolType)
            .map(key => (ImageDataProtocolType[key]));

        const itemImageDataOriginal = _.find(itemImageDatas, (imageData) => {
            return imageData.imageVersion === ImageVersions.ORIGINAL.propName;
        });

        // use the original image version to create a hash for the ItemImage
        body.hash = ObjectHash.getHash(itemImageDataOriginal, HashableObjectType.ITEMIMAGEDATA_CREATEREQUEST);

        if (itemImageDataOriginal) {

            if (_.isEmpty(itemImageDataOriginal.protocol) || protocols.indexOf(itemImageDataOriginal.protocol) === -1) {
                this.log.warn(`Invalid protocol <${itemImageDataOriginal.protocol}> encountered.`);
                throw new MessageException('Invalid image protocol.');
            }

            // set new values
            itemImage.Hash = body.hash;

            // update itemImage record
            const updatedItemImage = await this.itemImageRepo.update(id, itemImage.toJSON());

            // this.log.debug('updatedItemImage', JSON.stringify(updatedItemImage, null, 2));
            // find and remove old related ItemImageDatas
            const oldImageDatas = updatedItemImage.related('ItemImageDatas').toJSON();
            for (const imageData of oldImageDatas) {
                await this.itemImageDataService.destroy(imageData.id);
            }

            // then create new imageDatas from the given original data
            if (!_.isEmpty(itemImageDataOriginal)) {
                const toVersions = [ImageVersions.LARGE, ImageVersions.MEDIUM, ImageVersions.THUMBNAIL];
                const imageDatas: ItemImageDataCreateRequest[] = await this.imageFactory.getImageDatas(itemImage.Id, itemImageDataOriginal, toVersions);

                // create new image datas
                for (const imageData of imageDatas) {
                    const createdImageData = await this.itemImageDataService.create(imageData);
                    this.log.debug('createdImageData: ', createdImageData.id);
                }
            }

            // finally find and return the updated itemImage
            const newItemImage = await this.findOne(id);
            return newItemImage;
        } else {
            throw new MessageException('Original image data not found.');
        }
    }

    public async destroy(id: number): Promise<void> {
        await this.itemImageRepo.destroy(id);
    }
}
