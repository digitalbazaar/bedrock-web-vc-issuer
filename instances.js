/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import axios from 'axios';
import {EdvClient} from 'edv-client';

const route = '/vc-issuer/instances';

export async function create({profileManager, options}) {
  // create the instance as a profile
  // FIXME: rename `profileSettings` to `profile`
  const {profileAgent, profileSettings: instance} =
    await profileManager.createProfile({
      content: {
        name: options.name,
        // TODO: support instance configurations
        config: {}
      }
    });
  const {id: profileAgentId, profile: profileId} = profileAgent;
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

  // TODO: no `edvClient` what to do?
  /*
  const profileDocumentReferenceId = `${instance.id}-profile-doc`;
  const {profileAgentUserDocumentDetails} = await profileManager
    .initializeAccessManagement({
      edvClient,
      invocationSigner,
      profileAgentDetails,
      profileAgentId,
      profileAgentZcaps,
      profileDetails,
      profileDocumentReferenceId,
      profileId
    });

  // update zcaps on profileAgent instance
  profileAgent.zcaps = profileAgentUserDocumentDetails.zcaps;
  */

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
              allowedAction: ['read', 'write'],
              invoker: instance.id,
              delegator: instance.id,
              invocationTarget: {
                type: 'urn:edv:documents'
              }
            }, {
              referenceId: `${instance.id}-edv-users-revocations`,
              allowedAction: ['read', 'write'],
              invoker: instance.id,
              delegator: instance.id,
              invocationTarget: {
                type: 'urn:edv:revocations'
              }
            }, {
              referenceId: `${instance.id}-edv-credentials`,
              allowedAction: ['read', 'write'],
              invoker: instance.id,
              delegator: instance.id,
              invocationTarget: {
                type: 'urn:edv:documents'
              }
            }, {
              referenceId: `${instance.id}-edv-credentials-revocations`,
              allowedAction: ['read', 'write'],
              invoker: instance.id,
              delegator: instance.id,
              invocationTarget: {
                type: 'urn:edv:revocations'
              }
            }, {
              referenceId: `${instance.id}-issue-key-assertionMethod`,
              // string should match KMS ops
              allowedAction: 'sign',
              invoker: instance.id,
              delegator: instance.id,
              invocationTarget: {
                type: 'Ed25519VerificationKey2018',
                proofPurpose: 'assertionMethod'
              }
            }, {
              referenceId: `${instance.id}-issue-key-revocations`,
              allowedAction: ['read', 'write'],
              invoker: instance.id,
              delegator: instance.id,
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

function _findZcap({zcaps, referenceId}) {
  return zcaps.find(({referenceId: id}) => id === referenceId);
}
