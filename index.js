/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';

export {
  getControllerKey, getKeyAgreementKey, getDataHubDocument
} from './utils.js';

import * as registrations from './registrations.js';
import * as configurations from './configurations.js';
export {registrations, configurations};

export async function registerIssuer({presentation, account}) {
  // create the issuer registration and the issuer configuration
  const {verifiableCredential: [credential]} = presentation;
  const {registration} = await registrations.create(
    {controller: account.id, presentation});
  await configurations.create({credential, account, registration});
}

export async function unregisterIssuer({issuer, account}) {
  // first remove configuration
  await configurations.remove({issuer, account});

  // remove registration
  return registrations.remove({issuer});
}

export async function issue(
  {issuer, flow, credentials, presentation}) {
  const url = '/vc-issuer/issue';
  const response = await axios.post(
    url, {issuer, flow, credentials, presentation});
  return response.data;
}
