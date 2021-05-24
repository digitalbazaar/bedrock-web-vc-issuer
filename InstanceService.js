/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import {httpClient} from '@digitalbazaar/http-client';

/**
 * FIXME: Add description.
 *
 * @param {object} [config] - The config options to use.
 * @param {string} [config.baseURL] - The protocol, host and port for use with
 *   node.js (eg https://example.com).
 * @param {object} [config.urls={base: '/instances'}] - The service endpoints.
 */
export class InstanceService {
  constructor({
    baseURL,
    urls = {
      base: '/instances',
    }
  } = {}) {
    this.config = {urls};
    this.baseURL = baseURL;
  }
  /**
   * Publish the latest version of a revocation list credential.
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The ID of the RLC to publish.
   * @param {string} options.profileAgent - The ID of the profile agent to
   *   use to publish the RLC.
   *
   * @returns {Promise} Resolves when the operation completes.
   */
  async publishRlc({id, profileAgent} = {}) {
    let url = `${id}/publish`;
    // this HTTP API returns 204 with no body on success
    if(this.baseURL) {
      url = new URL(url, this.baseURL).toString();
    }
    await httpClient.post(url, {
      json: {profileAgent}
    });
  }
}
