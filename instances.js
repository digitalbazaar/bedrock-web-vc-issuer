/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import {EdvDocument} from 'edv-client';
import jsigs from 'jsonld-signatures';
import {decodeList, getCredentialStatus} from 'vc-revocation-list';
import vc from 'vc-js';
import {AsymmetricKey} from 'webkms-client';
const {suites: {Ed25519Signature2018}} = jsigs;

// TODO: need a common place for this
const JWE_ALG = 'ECDH-ES+A256KW';

export async function create(
  {profileManager, profileContent, profileAgentContent}) {
  // create the instance as a profile
  const {id: profileId} = await profileManager.createProfile();
  let instance = {id: profileId};

  // request capabilities for the instance, including for the `user` EDV
  const presentation = await requestCapabilities({instance});
  if(!presentation) {
    throw new Error('User aborted instance provisioning.');
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
  profileContent.issuer = presentation.holder;
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

export async function revokeCredential(
  {profileManager, instance, credentialId, documentLoader}) {
  if(!(credentialId && typeof credentialId === 'string')) {
    throw new TypeError('"credentialId" must be a non-empty string.');
  }

  // get interfaces for issuing/revoking VCs
  const {suite, credentialsCollection} =
    await _getIssuingInterfaces({profileManager, instance});
  const {edvClient, capability, invocationSigner} = credentialsCollection;

  // get credential document
  let results = await edvClient.find({
    equals: {'content.id': credentialId}
  });
  if(results.length === 0) {
    throw new Error(`Credential "${credentialId}" not found.`);
  }
  let [credentialDoc] = results;
  const {content: credential} = credentialDoc;
  const credentialEdvDoc = _getEdvDocument(
    {id: credentialDoc.id, edvClient, capability, invocationSigner});

  // TODO: support other revocation methods

  // get RLC document
  const credentialStatus = getCredentialStatus({credential});
  const revocationListIndex = parseInt(
    credentialStatus.revocationListIndex, 10);
  const {revocationListCredential} = credentialStatus;
  results = await edvClient.find({
    equals: {'content.id': revocationListCredential}
  });
  if(results.length === 0) {
    throw new Error(
      `RevocationListCredential "${revocationListCredential}" not found.`);
  }

  // FIXME: add timeout
  let [rlcDoc] = results;
  const rlcEdvDoc = _getEdvDocument(
    {id: rlcDoc.id, edvClient, capability, invocationSigner});
  let rlcUpdated = false;
  while(!rlcUpdated) {
    try {
      // check if `credential` is already revoked, if so, done
      const {encodedList} = rlcDoc.content;
      const list = await decodeList({encodedList});
      if(list.isRevoked(revocationListIndex)) {
        rlcUpdated = true;
        break;
      }

      // update index as revoked and reissue VC
      list.setRevoked(revocationListIndex, true);
      const {rlcCredential} = rlcDoc.content;
      rlcCredential.encodedList = await list.encode();
      // express date without milliseconds
      const now = (new Date()).toJSON();
      rlcCredential.issuanceDate = `${now.substr(0, now.length - 5)}Z`;

      // clear existing proof and resign VC
      // TODO: define `documentLoader`
      delete rlcCredential.proof;
      rlcDoc.content = await vc.issue(
        {credential: rlcCredential, documentLoader, suite});

      // update RLC doc
      await rlcEdvDoc.write({doc: rlcDoc});
      rlcUpdated = true;
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      // ignore conflict, read and try again
      rlcDoc = await rlcEdvDoc.read();
    }
  }

  // mark credential as revoked in its meta
  // FIXME: add timeout
  let credentialUpdated = credentialDoc.meta.revoked;
  while(!credentialUpdated) {
    try {
      credentialDoc.meta.revoked = true;
      await credentialEdvDoc.write({doc: credentialDoc});
      credentialUpdated = true;
    } catch(e) {
      if(e.name !== 'InvalidStateError') {
        throw e;
      }
      // ignore conflict, read and try again
      credentialDoc = await credentialEdvDoc.read();
      credentialUpdated = credentialDoc.meta.revoked;
    }
  }
}

async function _getIssuingInterfaces({profileManager, instance}) {
  const {id: profileId} = instance;
  const profileAgent = await profileManager.getAgent({profileId});
  const {zcaps: {
    ['key-assertionMethod']: assertionMethodZcap,
    ['credential-edv-documents']: credentialsEdvZcap,
    ['credential-edv-hmac']: credentialsEdvHmacZcap,
    ['credential-edv-kak']: credentialsEdvKakZcap,
  }} = profileAgent;

  if(!(assertionMethodZcap && credentialsEdvZcap && credentialsEdvHmacZcap &&
    credentialsEdvKakZcap)) {
    throw new Error('Permission denied.');
  }

  const {edvClient, capability, invocationSigner} =
    await profileManager.getProfileEdvAccess(
      {profileId, referenceIdPrefix: 'credential'});

  const issuerKey = new AsymmetricKey({
    capability: assertionMethodZcap,
    invocationSigner
  });

  const {invocationTarget: {verificationMethod}} = assertionMethodZcap;
  const suite = new Ed25519Signature2018({
    verificationMethod,
    signer: issuerKey
  });

  edvClient.ensureIndex({attribute: 'content.id', unique: true});
  edvClient.ensureIndex({attribute: 'content.type'});
  edvClient.ensureIndex({attribute: 'meta.revoked'});

  return {
    suite,
    // TODO: expose latter as a `Collection` instance
    credentialsCollection: {edvClient, capability, invocationSigner}
  };
}

async function _getEdvDocument(
  {id, edvClient, capability, invocationSigner} = {}) {
  const {keyResolver, keyAgreementKey, hmac} = edvClient;
  const recipients = [{
    header: {kid: keyAgreementKey.id, alg: JWE_ALG}
  }];
  return new EdvDocument({
    id, recipients, keyResolver, keyAgreementKey, hmac,
    capability, invocationSigner, client: edvClient
  });
}

async function _createZcapDelegations({profileManager, instance, user}) {
  const {capabilities} = user;
  const controller = user.id;
  const zcapRequests = [];
  // TODO: fix data model for these: ["Read", "Issue", "Revoke", "Admin"]
  // map what are essentially roles to the appropriate capabilities
  if(capabilities.includes('Admin')) {
    const profileInvocationZcapKeyRequest =
      await _createProfileInvocationZcapKeyRequest(
        {controller, profileManager, instanceId: instance.id});
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
      profileInvocationZcapKeyRequest,
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
  const promises = zcapRequests.map(async request =>
    profileManager.delegateCapability({profileId: instance.id, request}));
  // TODO: Use promise-fun lib to limit concurrency
  const zcaps = await Promise.all(promises);
  return {zcaps};
}

async function _revokeZcaps(
  {profileManager, instance, capabilitiesToRevoke, user}) {
  const zcapsToRevoke = [];
  // map what are essentially roles to the appropriate capabilities
  if(capabilitiesToRevoke.includes('Admin')) {
    // FIXME: Remove this after profile zcap key is renamed
    const adminAgent = await profileManager.getAgent({profileId: instance.id});
    const {zcaps} = adminAgent;
    const zcapReferenceId = await _getProfileInvocationZcapKeyReferenceId(
      {instanceId: instance.id, zcaps});
    const adminZcaps = [
      user.zcaps[zcapReferenceId],
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

// FIXME: this assumes the `profileManager` is an Admin
async function _createProfileInvocationZcapKeyRequest(
  {controller, profileManager, instanceId}) {
  const adminAgent = await profileManager.getAgent({profileId: instanceId});
  const {zcaps} = adminAgent;
  const zcapReferenceId = await _getProfileInvocationZcapKeyReferenceId(
    {instanceId, zcaps});
  const {invocationTarget, allowedAction, referenceId} = zcaps[zcapReferenceId];
  return {
    allowedAction,
    controller,
    invocationTarget,
    referenceId
  };
}

async function _getProfileInvocationZcapKeyReferenceId(
  {instanceId, zcaps}) {
  // FIXME: simplify reference ID for this; force only one reference ID
  // for using the agent's profile's capability invocation key using the
  // literal reference ID: 'profile-capability-invocation-key'
  return Object.keys(zcaps).find(referenceId => {
    const capabilityInvokeKeyReference = '-key-capabilityInvocation';
    return referenceId.startsWith(instanceId) &&
          referenceId.endsWith(capabilityInvokeKeyReference);
  });
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
