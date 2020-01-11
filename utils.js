/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';
import {EdvClient, EdvDocument} from 'edv-client';
import {ControllerKey, KmsClient} from 'webkms-client';

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

export async function getKeyAgreementKey({account}) {
  const controllerKey = await getControllerKey({account});
  return await controllerKey.getKeyAgreementKey(
    {id: account.kak.id, type: account.kak.type});
}

export async function findDocuments(
  {account, instance, id, type, equals, has, capability}) {
  if(!(id || type || equals || has)) {
    throw new TypeError('"id", "type", "equals", or "has" must be given.');
  }
  if(!equals) {
    equals = [];
  } else {
    equals = equals.slice();
  }
  if(id) {
    equals.push({'content.id': id});
  }
  if(type) {
    if(Array.isArray(type)) {
      const query = type.map(type => ({'content.type': type}));
      equals.push(...query);
    } else {
      equals.push({'content.type': type});
    }
  }
  const controllerKey = await getControllerKey({account});
  const client = await getEdvClient({controllerKey, account, instance});
  const results = await client.find(
    {equals, has, capability, invocationSigner: controllerKey});
  return results;
}

export async function getEdvDocument({id, account, instance, capability}) {
  const controllerKey = await getControllerKey({account});
  const client = await getEdvClient({controllerKey, account, instance});
  const {keyAgreementKey, hmac} = client;
  const invocationSigner = controllerKey;
  const recipients = [{
    header: {kid: keyAgreementKey.id, alg: 'ECDH-ES+A256KW'}
  }];
  return new EdvDocument({
    id, recipients, keyResolver, keyAgreementKey, hmac,
    capability, invocationSigner, client
  });
}

export async function getEdvClient({controllerKey, account, instance}) {
  // FIXME: instead of using KeyAgreementKey and HMAC for the account ...
  // use it for the issuer `instance` ... and give zcaps to the controller
  // key to do so... users with `read` only need HMAC `verify` and KaK `derive`
  // and users with `write` need HMAC `sign`... then controller key also
  // needs zcap for the vault... pass `capability` to `getKeyAgreementKey`
  // and `getHmac` keys below... the `account` did:key that creates the
  // instance is the first `controller` of the instance's keystore
  if(!controllerKey) {
    controllerKey = await getControllerKey({account});
  }
  const [keyAgreementKey, hmac] = await Promise.all([
    await controllerKey.getKeyAgreementKey(
      {id: account.kak.id, type: account.kak.type}),
    await controllerKey.getHmac({id: account.hmac.id, type: account.hmac.type})
  ]);
  const client = new EdvClient({keyResolver, keyAgreementKey, hmac});
  // create indexes for documents
  client.ensureIndex({attribute: 'content.type'});
  client.ensureIndex({attribute: 'content.id', unique: true});
  // TODO: index based on supported credential types for the instance
  // TODO: will need to be able to get all
  // `content.type === 'VerifiableCredential'` and reindex as needed
  return client;
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
