/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';
import {getCapabilitySets} from './users.js';

const route = '/vc-issuer/instances';

export async function create({instance}) {
  const url = route;
  const response = await axios.post(url, instance);
  return response.data;
}

export async function setIssuer({id, controller, presentation}) {
  const url = `${route}/${encodeURIComponent(id)}/issuer`;
  const response = await axios.post(url, {controller, presentation});
  return response.data;
}

export async function get({id}) {
  const url = `${route}/${encodeURIComponent(id)}`;
  const response = await axios.get(url);
  return response.data;
}

export async function getAll({controller} = {}) {
  const instanceIds = await _getInstanceIds({accountId: controller});
  const promises = instanceIds.map(async id => {
    try {
      const instance = await get({id});
      return instance;
    } catch(e) {
      console.log(`Unable to fetch issuer: "${id}"`);
      console.error(e);
    }
  });
  // Resolve promises and filter out undefined
  // FIXME: Consider pulling in promises lib to limit concurrency
  const instances = await Promise.all(promises);
  return instances.filter(promise => promise);
}

export async function remove({id}) {
  const url = `${route}/${encodeURIComponent(id)}`;
  try {
    await axios.delete(url);
    return true;
  } catch(e) {
    if(e.name === 'NotFoundError') {
      return false;
    }
    throw e;
  }
}

export async function _getInstanceIds({accountId}) {
  const capabilitySets = await getCapabilitySets({accountId});
  return capabilitySets.map(({instance}) => instance);
}

export async function requestCapabilities({instance}) {
  console.log('request credential issuance capabilities...');
  try {
    const webCredential = await navigator.credentials.get({
      web: {
        VerifiablePresentation: {
          query: {
            type: 'OcapLdQuery',
            capabilityQuery: [{
              referenceId: `${instance.id}-edv-configuration`,
              allowedAction: ['read', 'write'],
              invoker: instance.keys.zcapKey.id,
              delegator: instance.keys.zcapKey.id,
              invocationTarget: {
                type: 'urn:edv:documents'
              }
            }, {
              referenceId: `${instance.id}-edv-revocations`,
              allowedAction: ['read', 'write'],
              invoker: instance.keys.zcapKey.id,
              delegator: instance.keys.zcapKey.id,
              invocationTarget: {
                type: 'urn:edv:revocations'
              }
            }, {
              referenceId: `${instance.id}-key-assertionMethod`,
              // string should match KMS ops
              allowedAction: 'sign',
              invoker: instance.keys.zcapKey.id,
              delegator: instance.keys.zcapKey.id,
              invocationTarget: {
                type: 'Ed25519VerificationKey2018',
                proofPurpose: 'assertionMethod'
              }
            }, {
              referenceId: `${instance.id}-key-revocations`,
              allowedAction: ['read', 'write'],
              invoker: instance.keys.zcapKey.id,
              delegator: instance.keys.zcapKey.id,
              invocationTarget: {
                type: 'urn:webkms:revocations'
              }
            }]
          }
        }
      }
    });
    if(!webCredential) {
      // no response from user
      console.log('credential request canceled/denied');
      return null;
    }

    // destructure to get presentation
    const {data: presentation} = webCredential;

    console.log('presentation', presentation);
    return presentation;
  } catch(e) {
    console.error(e);
  }
}
