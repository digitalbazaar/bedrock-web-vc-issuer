/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {DataHubDocument} from 'secure-data-hub-client';
import {ControllerKey} from 'web-kms-client';

export async function getControllerKey({account}) {
  const {controllerKeySeed: secret} = account;
  return ControllerKey.fromSecret({secret, handle: account.id});
}

export async function getDataHubDocument({account, capability}) {
  const controllerKey = await getControllerKey({account});
  const [kek, hmac] = await Promise.all([
    await controllerKey.getKek({id: account.kek.id, type: account.kek.type}),
    await controllerKey.getHmac({id: account.hmac.id, type: account.hmac.type})
  ]);
  const invocationSigner = controllerKey;
  return new DataHubDocument({kek, hmac, capability, invocationSigner});
}
