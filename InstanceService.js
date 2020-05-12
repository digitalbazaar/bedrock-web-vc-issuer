/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';

/**
 * Hello.
 *
 * @param {object} [config] - The config options to use.
 * @param {string} [config.baseURL] - The protocol, host and port for use with
 *   node.js (eg https://example.com).
 * @param {object} [config.httpsAgent] - An optional
 *   node.js `https.Agent` instance to use when making requests.
 * @param {object} [config.urls={base: '/instances'}] - The service endpoints.
 */
export class InstanceService {
  constructor({
    baseURL,
    httpsAgent,
    urls = {
      base: '/instances',
    }
  } = {}) {
    this.config = {urls};
    const headers = {Accept: 'application/ld+json, application/json'};
    this._axios = axios.create({
      baseURL,
      headers,
      httpsAgent,
    });
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
    try {
      // this HTTP API returns 204 with no body on success
      await this._axios.post(`${id}/publish`, {profileAgent});
    } catch(e) {
      _rethrowAxiosError(e);
    }
  }
}

function _rethrowAxiosError(error) {
  if(error.response) {
    // The request was made and the server responded with a status code
    // that falls out of the range of 2xx
    // FIXME: there may be better wrappers already created
    if(error.response.data.message && error.response.data.type) {
      throw new Error(
        `${error.response.data.type}: ${error.response.data.message}`);
    }
  }
  throw new Error(error.message);
}
