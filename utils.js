/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {DataHubDocument} from 'secure-data-hub-client';
import {ControllerKey, KmsClient} from 'web-kms-client';

const DEFAULT_HEADERS = {Accept: 'application/ld+json, application/json'};
const KMS_BASE_URL = `${window.location.origin}/kms`;

export async function getControllerKey({account}) {
  const {controllerKeySeed: secret} = account;
  const kmsClient = new KmsClient();
  const controllerKey = await ControllerKey.fromSecret(
    {secret, handle: account.id, kmsClient});
  await _ensureKeystore({controllerKey});
  return controllerKey;
}

export async function getDataHubDocument({account, capability}) {
  const controllerKey = await getControllerKey({account});
  const [keyAgreementKey, hmac] = await Promise.all([
    await controllerKey.getKeyAgreementKey(
      {id: account.kak.id, type: account.kak.type}),
    await controllerKey.getHmac({id: account.hmac.id, type: account.hmac.type})
  ]);
  const invocationSigner = controllerKey;
  return new DataHubDocument(
    {keyResolver, keyAgreementKey, hmac, capability, invocationSigner});
}

async function _createKeystore({controllerKey, referenceId} = {}) {
  // create keystore
  const config = {
    sequence: 0,
    controller: controllerKey.id,
    // TODO: add `invoker` and `delegator` using arrays including
    // controllerKey.id *and* identifier for backup key recovery entity
    invoker: controllerKey.id,
    delegator: controllerKey.id
  };
  if(referenceId) {
    config.referenceId = referenceId;
  }
  return await KmsClient.createKeystore({
    url: `${KMS_BASE_URL}/keystores`,
    config
  });
}

async function _ensureKeystore({controllerKey}) {
  let config = await KmsClient.findKeystore({
    url: `${KMS_BASE_URL}/keystores`,
    controller: controllerKey.id,
    referenceId: 'primary'
  });
  if(config === null) {
    config = await _createKeystore({controllerKey, referenceId: 'primary'});
  }
  if(config === null) {
    return null;
  }
  controllerKey.kmsClient.keystore = config.id;
  return config;
}

// FIXME: make more restrictive, support `did:key` and `did:v1`
async function keyResolver({id}) {
  const response = await axios.get(id, {
    headers: DEFAULT_HEADERS
  });
  return response.data;
}
