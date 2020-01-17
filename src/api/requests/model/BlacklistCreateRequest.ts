// Copyright (c) 2017-2020, The Particl Market developers
// Distributed under the GPL software license, see the accompanying
// file COPYING or https://github.com/particl/particl-market/blob/develop/LICENSE

import { IsNotEmpty } from 'class-validator';
import { RequestBody } from '../../../core/api/RequestBody';
import { ModelRequestInterface } from './ModelRequestInterface';
import { BlacklistType } from '../../enums/BlacklistType';

// tslint:disable:variable-name
export class BlacklistCreateRequest extends RequestBody implements ModelRequestInterface {

    @IsNotEmpty()
    public type: BlacklistType;

    @IsNotEmpty()
    public target: string;

    public market: string;
    public profile_id: number;

}
// tslint:enable:variable-name
