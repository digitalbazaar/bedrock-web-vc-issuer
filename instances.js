/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import axios from 'axios';

const route = '/vc-issuer/instances';

export async function create({options}) {
  // create the instance as a profile
  const profileManager = await getProfileManager();
  const {profileAgent, profile: instance} = await profileManager.createProfile({
    content: {
      name: options.name,
      // TODO: support instance configurations
      config: {}
    }
  });
  const {id: profileAgentId, profile: profileId} = profileAgent;

  // request capabilities for the instance
  const presentation = await requestCapabilities({instance});
  if(!presentation) {
    throw new Error('User aborted instance provisioning.');
    return;
  }

  // TODO: verify presentation via backend call

  const {invocationSigner, kmsClient} = await profileManager.getProfileSigner(
    {profileAgent});

  // TODO: get zcaps from presentation based on reference ID

  // TODO: create edv clients? what is needed to delegate zcaps... seems
  // like we'd just pass `parentCapability`

  // delegate zcaps to enable profile agent to access users EDV
  const {zcaps: usersEdvZcaps} = await profileManager
    .delegateEdvCapabilities({
      edvClient,
      invocationSigner,
      profileAgentId,
      referenceId: `${instance.id}-edv-users`,
    });

  // delegate zcaps to enable profile agent to access credentials EDV
  const {zcaps: credentialsEdvZcaps} = await profileManager
    .delegateEdvCapabilities({
      edvClient: credentialsEdvClient,
      invocationSigner,
      profileAgentId,
      referenceId: `${instance.id}-edv-credentials`
    });

  // assemble the zcaps to include in the profile agent's user document
  const profileAgentZcaps = {
    [profileAgent.zcaps.profileCapabilityInvocationKey.referenceId]:
      profileAgent.zcaps.profileCapabilityInvocationKey
  };

  // capablities to enable the profile agent to use the profile's users EDV
  for(const capability of usersEdvZcaps) {
    profileAgentZcaps[capability.referenceId] = capability;
  }

  // capabilities to enable the profile agent to use the profile's
  // credentials EDV
  for(const capability of credentialsEdvZcaps) {
    profileAgentZcaps[capability.referenceId] = capability;
  }

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
