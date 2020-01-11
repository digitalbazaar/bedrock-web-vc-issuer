/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';

export {
  getControllerKey, getKeyAgreementKey, findDocuments,
  getEdvDocument, getEdvClient
} from './utils.js';

export {default as Collection} from './Collection.js';

import * as instances from './instances.js';
//import * as configurations from './configurations.js';
export {instances};//, configurations};

export async function registerIssuer({presentation, account}) {
  // create the issuer instance and the issuer configuration
  const {verifiableCredential: [credential]} = presentation;
  const {instance} = await instances.create(
    {controller: account.id, presentation});
  //await configurations.create({credential, account, instance});
}

export async function unregisterIssuer({issuer, account}) {
  // first remove configuration
  //await configurations.remove({issuer, account});
  // remove instance
  return instances.remove({issuer});
}

export async function issue(
  {issuer, flow, credentials, presentation}) {
  const url = '/vc-issuer/issue';
  const response = await axios.post(
    url, {issuer, flow, credentials, presentation});
  return response.data;
}
