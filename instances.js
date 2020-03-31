/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
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

export async function create(
  {profileManager, profileContent, profileAgentContent}) {
  // create the instance as a profile
  const {id: profileId} = await profileManager.createProfile();
  let instance = {id: profileId};

  // request capabilities for the instance, including for the `user` EDV
  const presentation = await requestCapabilities({instance});
  if(!presentation) {
    throw new Error('User aborted instance provisioning.');
    return;
  }

  // TODO: validate presentation (ensure it matches request and has the
  // zcaps with the appropriate reference IDs, etc.)

  // TODO: verify presentation via backend call

  // get zcaps from presentation based on reference ID
  const {capability: capabilities} = presentation;
  const capability = _findZcap(
    {capabilities, referenceId: 'user-edv-documents'});
  const revocationCapability = _findZcap(
    {capabilities, referenceId: 'user-edv-revocations'});

  // create keys for accessing `user` EDV
  const {hmac, keyAgreementKey} = await profileManager.createEdvRecipientKeys(
    {profileId});

  // initialize access management
  const {profile, profileAgent} = await profileManager
    .initializeAccessManagement({
      profileId,
      profileContent,
      profileAgentContent,
      hmac,
      keyAgreementKey,
      capability,
      revocationCapability,
      indexes: [
        {attribute: 'content.name'},
        {attribute: 'content.email'}
      ]
    });
  instance = profile;
  let user = profileAgent;

  const {invocationSigner} = await profileManager.getProfileSigner(
    {profileId});

  // TODO: these zcaps for full access to these EDVs by the profileAgent
  // should really only be created on demand -- where the function call to
  // get them (+lazy delegation) requires an optional param that is the
  // profileAgent's powerful zcap to use the profile's zcap key

  // get zcaps for each EDV and the profile's keys (hmac/KAK) as a recipient
  const edvs = ['credential'];
  for(const edv of edvs) {
    // get zcaps from presentation based on reference ID
    const edvZcapId = `${edv}-edv-documents`;
    const revokeZcapId = `${edv}-edv-revocations`;
    const {capability: capabilities} = presentation;
    const parentCapabilities = {
      edv: _findZcap({capabilities, referenceId: edvZcapId}),
      edvRevocations: _findZcap({capabilities, referenceId: revokeZcapId})
    };

    // create keys for accessing users and credentials EDVs
    const {hmac, keyAgreementKey} = await profileManager.createEdvRecipientKeys(
      {profileId});

    // delegate zcaps to enable profile agent to access EDV
    const {zcaps} = await profileManager.delegateEdvCapabilities({
      hmac,
      keyAgreementKey,
      parentCapabilities,
      invocationSigner,
      profileAgentId: profileAgent.id,
      referenceIdPrefix: edv
    });

    // capablities to enable the profile agent to use the profile's users EDV
    for(const capability of zcaps) {
      user.zcaps[capability.referenceId] = capability;
    }
  }

  // set default "capabilities" for user
  // TODO: do this here or elsewhere?
  user.capabilities = ['Admin', 'Read', 'Revoke', 'Issue'];

  // update profile agent user with content and new zcaps
  const accessManager = await profileManager.getAccessManager({profileId});
  user = await accessManager.updateUser({user});
  return {user, instance};
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
              referenceId: 'user-edv-documents',
              revocationReferenceId: 'user-edv-revocations',
              allowedAction: ['read', 'write'],
              invoker: instance.id,
              delegator: instance.id,
              invocationTarget: {
                type: 'urn:edv:documents'
              }
            }, {
              referenceId: `credential-edv-documents`,
              revocationReferenceId: `credential-edv-revocations`,
              allowedAction: ['read', 'write'],
              invoker: instance.id,
              delegator: instance.id,
              invocationTarget: {
                type: 'urn:edv:documents'
              }
            }, {
              referenceId: `key-assertionMethod`,
              revocationReferenceId: `key-assertionMethod-revocations`,
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

function _findZcap({capabilities, referenceId}) {
  return capabilities.find(({referenceId: id}) => id === referenceId);
}
