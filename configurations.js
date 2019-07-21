/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';

import {getDataHubDocument} from './utils.js';
import * as registrations from './registrations.js';

const route = '/vc-issuer/configurations';

export async function create({credential, account, registration}) {
  const {credentialSubject: issuer} = credential;
  const capability = registration.capability.find(
    c => c.referenceId === 'configuration');
  const dataHubDoc = await getDataHubDocument({account, capability});
  // read dataHubDoc first to get previous version
  let doc;
  try {
    doc = await dataHubDoc.read();
  } catch(e) {
    if(e.name !== 'NotFoundError') {
      throw e;
    }
    // doc not created yet, this is ok
    doc = {id: dataHubDoc.id};
  }

  await dataHubDoc.write({
    doc: {
      ...doc,
      content: {
        // TODO: Consider using a uuid, consider creating an index on the issuer
        id: issuer.id, // FIXME: Redundant data
        type: 'IssuerConfiguration',
        issuer,
        // FIXME: change to recipes?
        flows: []
      }
    }
  });
}

export async function get({issuer, account}) {
  const {registration} = await registrations.get({issuer});
  const capability = registration.capability.find(
    c => c.referenceId === 'configuration');
  const dataHubDoc = await getDataHubDocument({account, capability});
  const doc = await dataHubDoc.read();
  return doc.content;
}

export async function getAll() {
  const response = await axios.get(route);
  return response.data.map(({configuration}) => configuration.content);
}

export async function update({config, issuer, account}) {
  const {registration} = await registrations.get({issuer});
  const capability = registration.capability.find(
    c => c.referenceId === 'configuration');
  const dataHubDoc = await getDataHubDocument({account, capability});
  const doc = await dataHubDoc.read();
  await dataHubDoc.write({
    doc: {
      ...doc,
      content: config
    }
  });
}

export async function remove({issuer, account}) {
  // first delete configuration, if present
  const {registration} = await registrations.get({issuer});
  const capability = registration.capability.find(
    c => c.referenceId === 'configuration');
  const dataHubDoc = await getDataHubDocument({account, capability});
  return dataHubDoc.delete();
}
