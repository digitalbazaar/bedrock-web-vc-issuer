/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';
import {getCapability, getControllerKey} from './utils.js';
import {EdvClient} from 'edv-client';
import {SECURITY_CONTEXT_V2_URL, sign, suites} from 'jsonld-signatures';
import {CapabilityDelegation} from 'ocapld';
import {default as Collection} from './Collection.js';
const {Ed25519Signature2018} = suites;

const route = '/vc-issuer/instances';

const ALLOWED_ACTIONS = {
  read: ['read'],
  write: ['read', 'write'],
  issue: ['sign']
};

export async function claim({instanceId, token}) {
  const url = `${route}/${encodeURIComponent(instanceId)}/claim-user`;
  const response = await axios.post(url, {instanceId, token});
  return response.data;
}

export async function get({instanceId, token}) {
  const url = `${route}/${encodeURIComponent(instanceId)}/users`;
  const response = await axios.get(url, {params: {token}});
  return response.data;
}

export async function delegateCapabilities({account, instance, user}) {
  // TODO: fix data model for these: ["Read", "Issue", "Revoke"]
  const {capabilities} = user;

  // get account's zcaps
  const refs = {
    store: `${instance.id}-edv-configuration`,
    issue: `${instance.id}-key-assertionMethod`
  };
  const [store, issue] = await Promise.all(Object.keys(refs).map(
    referenceId => getCapability({referenceId, controller: account.id})));

  // map what are essentially permissions to the appropriate capabilities
  const zcapMap = {};
  if(capabilities.includes('Issue')) {
    zcapMap.issue = issue;
    if(capabilities.includes('Read') || capabilities.includes('Revoke')) {
      // covers both read and write to vault
      zcapMap.write = store;
    }
  } else if(capabilities.includes('Revoke')) {
    // covers both read and write to vault
    zcapMap.write = store;
  } else if(capabilities.includes('Read')) {
    zcapMap.read = store;
  }

  // delegate zcaps, each type in `zcapMap` using account's `controllerKey`
  // FIXME: consider using a KMS zcapKey for the `account` that is controlled
  // by the `controllerKey` in the future for another layer of security
  const controllerKey = await getControllerKey({account});
  const invoker = `urn:uuid:${user.id}`;
  const delegator = invoker;
  const zcaps = [];
  for(const type in zcapMap) {
    const parent = zcapMap[type];
    // delegate zcap
    const zcap = {
      '@context': SECURITY_CONTEXT_V2_URL,
      // use 128-bit random multibase encoded value
      id: `urn:zcap:${await EdvClient.generateId()}`,
      parentCapability: parent.id,
      invoker,
      delegator,
      // FIXME: ensure ocapld.js checks allowedActions when verifying
      // delegation chains
      allowedAction: ALLOWED_ACTIONS[type]
    };
    if(type === 'kak' || type === 'hmac') {
      zcap.referenceId = `${instance.id}-${type}`;
      zcap.invocationTarget = {
        id: parent.id,
        type: parent.type
      };
    } else {
      zcap.referenceId = parent.referenceId;
      zcap.invocationTarget = {...parent.invocationTarget};
    }
    const delegated = await _delegate({zcap, signer: controllerKey});
    zcaps.push(delegated);
  }
  user.zcaps = zcaps;

  // update user
  const users = await Collection.getInstance(
    {type: 'User', instance, account});
  await users.update({item: user});

  return user;
}

async function _delegate({zcap, signer}) {
  // attach capability delegation proof
  return sign(zcap, {
    // TODO: map `signer.type` to signature suite
    suite: new Ed25519Signature2018({
      signer,
      verificationMethod: signer.id
    }),
    purpose: new CapabilityDelegation({
      capabilityChain: [zcap.parentCapability]
    }),
    compactProof: false
  });
}
