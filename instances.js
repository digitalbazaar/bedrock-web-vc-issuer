/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import axios from 'axios';
import {EdvClient} from 'edv-client';

// import {EdvClient} from 'edv-client';
// import {SECURITY_CONTEXT_V2_URL, sign, suites} from 'jsonld-signatures';
// import {CapabilityDelegation} from 'ocapld';
// const {Ed25519Signature2018} = suites;
//
// const route = '/vc-issuer/instances';
//
// const ALLOWED_ACTIONS = {
//   read: ['read'],
//   write: ['read', 'write'],
//   issue: ['sign']
// };


const route = '/vc-issuer/instances';

export async function create({profileManager, options}) {
  // create the instance as a profile
  // FIXME: rename `profileSettings` to `profile`
  const {profileAgent, profileId} =
    await profileManager.createProfile({
      content: {
        name: options.name,
        // TODO: support instance configurations
        config: {}
      }
    });
  const {id: profileAgentId} = profileAgent;
  const instance = {id: profileId, ...options};
  console.log('instance', instance);

  // request capabilities for the instance
  const presentation = await requestCapabilities({instance});
  if(!presentation) {
    throw new Error('User aborted instance provisioning.');
    return;
  }

  // TODO: validate presentation (ensure it matches request and has the
  // zcaps with the appropriate reference IDs, etc.)

  // TODO: verify presentation via backend call

  const {invocationSigner, kmsClient} = await profileManager.getProfileSigner(
    {profileAgent});

  // assemble the zcaps to include in the profile agent's user document
  const profileAgentZcaps = {
    [profileAgent.zcaps.profileCapabilityInvocationKey.referenceId]:
      profileAgent.zcaps.profileCapabilityInvocationKey
  };

  // TODO: these zcaps for full access to these EDVs by the profileAgent
  // should really only be created on demand -- where the function call to
  // get them (+lazy delegation) requires an optional param that is the
  // profileAgent's powerful zcap to use the profile's zcap key

  // get zcaps for each EDV and the profile's keys (hmac/KAK) as a recipient
  const edvs = ['users', 'credentials'];
  for(const edv of edvs) {
    // get zcaps from presentation based on reference ID
    const edvZcapId = `${instance.id}-edv-${edv}`;
    const revokeZcapId = `${instance.id}-edv-${edv}-revocations`;
    const {capability: capabilities} = presentation;
    const parentCapabilities = {
      edv: _findZcap({capabilities, referenceId: edvZcapId}),
      edvRevocations: _findZcap({capabilities, referenceId: revokeZcapId})
    };

    // create keys for accessing users and credentials EDVs
    const {hmac, keyAgreementKey} = await profileManager.createEdvRecipientKeys(
      {invocationSigner, kmsClient});

    const edvClient = new EdvClient({
      // FIXME: can id be provided?
      // id: config.id,
      // FIXME: is keyResolver required
      // keyResolver,
      keyAgreementKey,
      hmac,
    });

    // delegate zcaps to enable profile agent to access EDV
    const {zcaps} = await profileManager.delegateEdvCapabilities({
      edvClient,
      parentCapabilities,
      invocationSigner,
      profileAgentId,
      referenceId: `${instance.id}-edv-users`,
    });

    // capablities to enable the profile agent to use the profile's users EDV
    for(const capability of zcaps) {
      profileAgentZcaps[capability.referenceId] = capability;
    }
  }

  const profileDocumentReferenceId = `${instance.id}-profile-doc`;
  const {profileAgentUserDocumentDetails} = await profileManager
    .initializeAccessManagement({
      // TODO: get initial manager information
      profileAgentDetails: {name: 'root'},
      profileAgentId,
      profileAgentZcaps,
      profileDetails: options,
      profileDocumentReferenceId,
      profileId
    });

  // update zcaps on profileAgent instance
  profileAgent.zcaps = profileAgentUserDocumentDetails.zcaps;

  // TODO: should assign profile agent to current logged in account

  return {profileAgent, instance};
}

// TODO: remove me
export async function setIssuer({id, controller, presentation}) {
  // TODO: send presentation to backend for verification

  // TODO: setup users EDV/etc. with instance profile (`id` is profile ID)
  // TODO: store zcaps for accessing users/credentials EDV, issuance key, etc.

  const url = `${route}/${encodeURIComponent(id)}/issuer`;
  const response = await axios.post(url, {controller, presentation});
  return response.data;
}

export async function get({id}) {
  // TODO: use profile manager to do getProfile()
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
/*
export async function delegateCapabilities({instanceId, user}) {
  // TODO: fix data model for these: ["Read", "Issue", "Revoke"]
  const {capabilities} = user;

  // get account's zcaps
  const refs = {
    store: `${instance.id}-edv-configuration`,
    issue: `${instance.id}-key-assertionMethod`,
    kak: `${instance.id}-kak`,
    hmac: `${instance.id}-hmac`
  };
  const [store, issue, kak, hmac] = await Promise.all(Object.values(refs).map(
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

  if(zcapMap.read || zcapMap.write) {
    zcapMap.kak = kak;
    zcapMap.hmac = hmac;
  }

  // delegate zcaps, each type in `zcapMap` using account's `capabilityAgent`
  const capabilityAgent = await getCapabilityAgent({account});
  const invoker = `urn:uuid:${user.id}`;
  const delegator = invoker;
  const signer = capabilityAgent.getSigner();
  const zcaps = [];
  for(const type in zcapMap) {
    const parent = zcapMap[type];
    if(parent === null) {
      // no parent zcap for what is being delegated
      throw new Error('Permission Denied.');
    }
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
      allowedAction: ALLOWED_ACTIONS[type],
      referenceId: parent.referenceId,
      invocationTarget: {...parent.invocationTarget}
    };
    const delegated = await _delegate({zcap, signer});
    zcaps.push(delegated);
  }
  user.zcaps = zcaps;

  return user;
}*/

export async function requestCapabilities({instance}) {
  console.log('request credential issuance capabilities...');
  try {
    const webCredential = await navigator.credentials.get({
      web: {
        VerifiablePresentation: {
          query: {
            // TODO: need to add a mechanism to this query language to
            // indicate whether an existing or new EDVs/keys should be
            // created before being given these zcaps ... perhaps a
            // layer where "provision X+give me a zcap for it" query is needed
            type: 'OcapLdQuery',
            capabilityQuery: [{
              referenceId: `${instance.id}-edv-users`,
              revocationReferenceId: `${instance.id}-edv-users-revocations`,
              allowedAction: ['read', 'write'],
              invoker: instance.id,
              delegator: instance.id,
              invocationTarget: {
                type: 'urn:edv:documents'
              }
            }, {
              referenceId: `${instance.id}-edv-credentials`,
              revocationReferenceId:
                `${instance.id}-edv-credentials-revocations`,
              allowedAction: ['read', 'write'],
              invoker: instance.id,
              delegator: instance.id,
              invocationTarget: {
                type: 'urn:edv:documents'
              }
            }, {
              referenceId: `${instance.id}-key-assertionMethod`,
              revocationReferenceId:
                `${instance.id}-key-assertionMethod-revocations`,
              // string should match KMS ops
              allowedAction: 'sign',
              invoker: instance.id,
              delegator: instance.id,
              invocationTarget: {
                type: 'Ed25519VerificationKey2018',
                proofPurpose: 'assertionMethod'
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

function _findZcap({zcaps, referenceId}) {
  return zcaps.find(({referenceId: id}) => id === referenceId);
}
