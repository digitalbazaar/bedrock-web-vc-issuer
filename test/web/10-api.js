/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {ProfileManager} from 'bedrock-web-profile-manager';
import {instances} from 'bedrock-web-vc-issuer';

const KMS_MODULE = 'ssm-v1';
const KMS_BASE_URL = `${window.location.origin}/kms`;

describe('instances API', () => {
  describe('create API', () => {
    // FIXME: Test fails without a stub for CHAPI
    it.skip('successfully create an instance', async () => {
      const profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://bedrock.localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
      await profileManager.setSession({
        session: {
          data: {
            account: {
              id: 'urn:uuid:ffaf5d84-7dc2-4f7b-9825-cc8d2e5a5d06'
            }
          },
          on: () => {},
        }
      });

      let error;
      let result;
      try {
        const options = {
          name: 'instance_one'
        };
        result = await instances.create({profileManager, options});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.have.property('profileAgent');
      result.should.have.property('instance');
    });
  });
});
