/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';
import {EdvClient, EdvDocument} from 'edv-client';
import {CapabilityAgent, KeystoreAgent} from 'webkms-client';

const DEFAULT_HEADERS = {Accept: 'application/ld+json, application/json'};

export async function getCapabilityAgent({account}) {
  const {capabilityAgentSeed: secret} = account;
  const capabilityAgent = await CapabilityAgent.fromSecret(
    {secret, handle: account.id});
  return capabilityAgent;
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
  const capabilityAgent = await getCapabilityAgent({account});
  const client = await getEdvClient({capabilityAgent, account, instance});
  const invocationSigner = capabilityAgent.getSigner();
  const results = await client.find(
    {equals, has, capability, invocationSigner});
  return results;
}

export async function getEdvDocument({id, account, instance, capability}) {
  const capabilityAgent = await getCapabilityAgent({account});
  const client = await getEdvClient({capabilityAgent, account, instance});
  const {keyAgreementKey, hmac} = client;
  const invocationSigner = capabilityAgent.getSigner();
  const recipients = [{
    header: {kid: keyAgreementKey.id, alg: 'ECDH-ES+A256KW'}
  }];
  return new EdvDocument({
    id, recipients, keyResolver, keyAgreementKey, hmac,
    capability, invocationSigner, client
  });
}

export async function getEdvClient({capabilityAgent, account, instance}) {
  if(!capabilityAgent) {
    capabilityAgent = await getCapabilityAgent({account});
  }
  const [kakZcap, hmacZcap] = await Promise.all([
    getCapability({controller: account.id, referenceId: `${instance.id}-kak`}),
    getCapability({controller: account.id, referenceId: `${instance.id}-hmac`})
  ]);
  const keystoreAgent = new KeystoreAgent({capabilityAgent});
  const [keyAgreementKey, hmac] = await Promise.all([
    keystoreAgent.getKeyAgreementKey(
      {...instance.keys.kak, capability: kakZcap}),
    keystoreAgent.getHmac(
      {...instance.keys.hmac, capability: hmacZcap})
  ]);
  const client = new EdvClient({keyResolver, keyAgreementKey, hmac});
  // create indexes for documents
  client.ensureIndex({attribute: 'content.id', unique: true});
  client.ensureIndex({attribute: 'content.type'});
  // FIXME: make sure compound indexes work
  // client.ensureIndex(
  //   {attribute: ['content.type', 'meta.token.id'], unique: true});
  client.ensureIndex({attribute: 'meta.token.id', unique: true});

  // TODO: index based on supported credential types for the instance
  // TODO: will need to be able to get all
  // `content.type === 'VerifiableCredential'` and reindex as needed
  return client;
}

export async function getCapability({referenceId, controller}) {
  const url = '/zcaps';
  try {
    const response = await axios.get(url, {
      params: {
        referenceId,
        controller
      }
    });
    const capability = response.data;
    return capability;
  } catch(e) {
    // FIXME: make response handling more robust
    if(e.response && e.response.status === 404) {
      return null;
    }
    throw e;
  }
}

// FIXME: make more restrictive, support `did:key` and `did:v1`
async function keyResolver({id}) {
  const response = await axios.get(id, {
    headers: DEFAULT_HEADERS
  });
  return response.data;
}
