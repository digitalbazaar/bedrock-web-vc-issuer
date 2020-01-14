/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';

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

export async function getAll({controller}) {
  if(!controller) {
    throw new TypeError(`"controller" must be a string or array of strings.`);
  }
  const url = `${route}`;
  const params = {controller};
  const response = await axios.get(url, {params});
  return response.data;
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

export async function _getInstanceIds({id}) {
  const zcaps = await getCapabilities({id});
  const ids = [];
  zcaps.forEach(({referenceId}) => {
    // assumes instance ids are 36 characters and prepended on referenceId
    const instanceId = referenceId.slice(0, 36);
    if(!ids.includes(instanceId)) {
      ids.push(instanceId);
    }
  });
  return ids;
}

export async function getCapabilities({id}) {
  const {data} = await axios.get(`/zcaps?controller=${encodeURIComponent(id)}`);
  return data;
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
              referenceId: `${instance.id}-edv-authorizations`,
              allowedAction: ['read', 'write'],
              invoker: instance.keys.zcapKey.id,
              delegator: instance.keys.zcapKey.id,
              invocationTarget: {
                type: 'urn:edv:authorizations'
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
              referenceId: `${instance.id}-key-authorizations`,
              allowedAction: ['read', 'write'],
              invoker: instance.keys.zcapKey.id,
              delegator: instance.keys.zcapKey.id,
              invocationTarget: {
                type: 'urn:webkms:authorizations'
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
