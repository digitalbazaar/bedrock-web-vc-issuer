/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import {delegateCapability} from 'bedrock-web-profile-manager/utils';

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
  profileContent = {edvs: {}, ...profileContent};
  const profileZcaps = {...profileContent.zcaps};
  for(const zcap of capabilities) {
    profileZcaps[zcap.referenceId] = zcap;
  }
  profileContent.zcaps = profileZcaps;
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

  const accessManager = await profileManager.getAccessManager({profileId});
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

    // create keys for accessing user and credential EDVs
    const {hmac, keyAgreementKey} = await profileManager.createEdvRecipientKeys(
      {profileId});

    // TODO: there should be an API in profile manager that can be used
    // to generate this information -- and the `accessManagement` part of
    // a profile user doc should be removed and moved to `edvs` just like
    // any other edv, its name `user` would be understood to be special
    profile.edvs[edv] = {
      hmac: {id: hmac.id, type: hmac.type},
      keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
      indexes: [
        {attribute: 'content.id', unique: true},
        {attribute: 'content.type'}
      ],
      zcaps: {
        write: edvZcapId,
        revoke: revokeZcapId
      }
    };
    await accessManager.updateUser({user: profile});

    // delegate zcaps to enable profile agent to access EDV
    const {zcaps} = await profileManager.delegateEdvCapabilities({
      hmac,
      keyAgreementKey,
      parentCapabilities,
      invocationSigner,
      profileAgentId: profileAgent.id,
      referenceIdPrefix: edv
    });

    // capablities to enable the profile agent to use the profile's user EDV
    for(const capability of zcaps) {
      user.zcaps[capability.referenceId] = capability;
    }
  }

  // set default "capabilities" for user
  // TODO: do this here or elsewhere?
  user.capabilities = ['Admin', 'Read', 'Revoke', 'Issue'];

  // update profile agent user with content and new zcaps
  user = await accessManager.updateUser({user});
  return {user, instance};
}

export async function delegateCapabilities({profileManager, instance, user}) {
  user = {...user};

  const {zcaps} = await _createZcapDelegations(
    {profileManager, instance, user});
  for(const capability of zcaps) {
    user.zcaps[capability.referenceId] = capability;
  }

  return user;
}

export async function revokeCapabilities(
  {profileManager, instance, user, capabilitiesToRevoke}) {
  user = {...user};

  const revokedZcaps = await _revokeZcaps(
    {profileManager, instance, user, capabilitiesToRevoke});
  for(const capability of revokedZcaps) {
    delete user.zcaps[capability.referenceId];
  }

  return user;
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

async function _createZcapDelegations({profileManager, instance, user}) {
  const {capabilities} = user;
  const controller = user.id;
  const zcapRequests = [];
  // TODO: fix data model for these: ["Read", "Issue", "Revoke", "Admin"]
  // map what are essentially roles to the appropriate capabilities
  if(capabilities.includes('Admin')) {
    const userEdvRequest = await _createZcapRequestFromParent({
      controller,
      parentZcap: instance.zcaps['user-edv-documents'],
      allowedAction: ['read', 'write']
    });
    const userEdvHmacRequest = await _createZcapRequestFromKey({
      key: instance.accessManagement.hmac,
      referenceId: 'user-edv-hmac',
      controller,
      allowedAction: 'sign'
    });
    const userEdvKakRequest = await _createZcapRequestFromKey({
      key: instance.accessManagement.keyAgreementKey,
      referenceId: 'user-edv-kak',
      controller,
      allowedAction: ['deriveSecret', 'sign']
    });
    const userEdvRevocationsRequest = await _createZcapRequestFromParent({
      controller,
      parentZcap: instance.zcaps['user-edv-revocations'],
      allowedAction: ['read', 'write']
    });
    const credentialEdvRevocationsRequest = await _createZcapRequestFromParent({
      controller,
      parentZcap: instance.zcaps['credential-edv-revocations'],
      allowedAction: ['read', 'write']
    });
    const issuanceRevocationsRequest = await _createZcapRequestFromParent({
      controller,
      parentZcap: instance.zcaps['key-assertionMethod-revocations'],
      allowedAction: ['read', 'write']
    });
    const adminZcapRequests = [
      userEdvRequest,
      userEdvHmacRequest,
      userEdvKakRequest,
      userEdvRevocationsRequest,
      credentialEdvRevocationsRequest,
      issuanceRevocationsRequest
    ];
    zcapRequests.push(...adminZcapRequests);
  }
  if(capabilities.includes('Issue')) {
    const issuanceRequest = await _createZcapRequestFromParent({
      controller,
      parentZcap: instance.zcaps['key-assertionMethod'],
      allowedAction: 'sign'
    });
    const allowReadWrite = capabilities.includes('Read') ||
      capabilities.includes('Revoke');
    const credentialEdvRequest = await _createZcapRequestFromParent({
      controller,
      parentZcap: instance.zcaps['credential-edv-documents'],
      allowedAction: allowReadWrite ? ['read', 'write'] : 'write'
    });
    const credentialEdvHmacRequest = await _createZcapRequestFromKey({
      key: instance.edvs.credential.hmac,
      referenceId: 'credential-edv-hmac',
      controller,
      allowedAction: 'sign'
    });
    const credentialEdvKakRequest = await _createZcapRequestFromKey({
      key: instance.edvs.credential.keyAgreementKey,
      referenceId: 'credential-edv-kak',
      controller,
      allowedAction: ['deriveSecret', 'sign']
    });
    const issuanceZcapRequests = [
      issuanceRequest,
      credentialEdvRequest,
      credentialEdvHmacRequest,
      credentialEdvKakRequest
    ];
    zcapRequests.push(...issuanceZcapRequests);
  } else if(capabilities.includes('Revoke')) {
    const credentialEdvRequest = await _createZcapRequestFromParent({
      controller,
      parentZcap: instance.zcaps['credential-edv-documents'],
      allowedAction: ['read', 'write']
    });
    const credentialEdvHmacRequest = await _createZcapRequestFromKey({
      key: instance.edvs.credential.hmac,
      referenceId: 'credential-edv-hmac',
      controller,
      allowedAction: 'sign'
    });
    const credentialEdvKakRequest = await _createZcapRequestFromKey({
      key: instance.edvs.credential.keyAgreementKey,
      referenceId: 'credential-edv-kak',
      controller,
      allowedAction: ['deriveSecret', 'sign']
    });
    const revokeZcapRequests = [
      credentialEdvRequest,
      credentialEdvHmacRequest,
      credentialEdvKakRequest
    ];
    zcapRequests.push(...revokeZcapRequests);
  } else if(capabilities.includes('Read')) {
    const credentialEdvRequest = await _createZcapRequestFromParent({
      controller,
      parentZcap: instance.zcaps['credential-edv-documents'],
      allowedAction: 'read'
    });
    const credentialEdvHmacRequest = await _createZcapRequestFromKey({
      key: instance.edvs.credential.hmac,
      referenceId: 'credential-edv-hmac',
      controller,
      allowedAction: 'sign'
    });
    const credentialEdvKakRequest = await _createZcapRequestFromKey({
      key: instance.edvs.credential.keyAgreementKey,
      referenceId: 'credential-edv-kak',
      controller,
      allowedAction: ['deriveSecret', 'sign']
    });
    const readZcapRequests = [
      credentialEdvRequest,
      credentialEdvHmacRequest,
      credentialEdvKakRequest
    ];
    zcapRequests.push(...readZcapRequests);
  }
  const {invocationSigner: signer} = await profileManager.getProfileSigner(
    {profileId: instance.id});
  const promises = zcapRequests.map(async request =>
    delegateCapability({signer, request}));
  // TODO: Use promise-fun lib to limit concurrency
  const zcaps = await Promise.all(promises);
  return {zcaps};
}

async function _revokeZcaps(
  {profileManager, instance, capabilitiesToRevoke, user}) {
  const zcapsToRevoke = [];
  // map what are essentially roles to the appropriate capabilities
  if(capabilitiesToRevoke.includes('Admin')) {
    const adminZcaps = [
      user.zcaps['user-edv-documents'],
      user.zcaps['user-edv-hmac'],
      user.zcaps['user-edv-kak'],
      user.zcaps['user-edv-revocations'],
      user.zcaps['credential-edv-revocations'],
      user.zcaps['key-assertionMethod-revocations']
    ];
    zcapsToRevoke.push(...adminZcaps);
  }
  if(capabilitiesToRevoke.includes('Issue')) {
    const issueZcaps = [
      user.zcaps['key-assertionMethod'],
      user.zcaps['credential-edv-documents'],
      user.zcaps['credential-edv-hmac'],
      user.zcaps['credential-edv-kak']
    ];
    zcapsToRevoke.push(...issueZcaps);
  } else if(capabilitiesToRevoke.includes('Revoke') ||
    capabilitiesToRevoke.includes('Read')) {
    const zcaps = [
      user.zcaps['credential-edv-documents'],
      user.zcaps['credential-edv-hmac'],
      user.zcaps['credential-edv-kak']
    ];
    zcapsToRevoke.push(...zcaps);
  }
  const {invocationSigner: signer} = await profileManager.getProfileSigner(
    {profileId: instance.id});
  const promises = zcapsToRevoke.map(async zcap => _revokeZcap({signer, zcap}));
  // TODO: Use promise-fun lib to limit concurrency
  await Promise.all(promises);
  return zcapsToRevoke;
}

async function _revokeZcap({signer, zcap}) {
  // FIXME: Implement revocation of zcaps
  return true;
}

async function _createZcapRequestFromParent(
  {parentZcap, controller, allowedAction}) {
  return {
    allowedAction,
    controller,
    parentCapability: parentZcap,
    invocationTarget: {...parentZcap.invocationTarget},
    referenceId: parentZcap.referenceId,
  };
}

async function _createZcapRequestFromKey(
  {key, referenceId, controller, allowedAction}) {
  return {
    allowedAction,
    controller,
    referenceId,
    invocationTarget: {
      id: key.id,
      type: key.type,
      verificationMethod: key.id
    },
    parentCapability: key.id
  };
}

function _findZcap({capabilities, referenceId}) {
  return capabilities.find(({referenceId: id}) => id === referenceId);
}

