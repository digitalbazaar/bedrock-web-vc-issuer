/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';

import {EdvClient} from 'edv-client';

const route = '/vc-issuer/instances';

export async function create({controller, presentation}) {
  const url = route;
  const response = await axios.post(url, {
    controller,
    presentation,
    // FIXME: temporary, remove/replace with other design like one
    // that uses indexing on controller/issuer information
    configId: await EdvClient.generateId()
  });
  return response.data;
}

export async function get({issuer}) {
  const url = route;
  const response = await axios.get(url, {
    params: {issuer}
  });
  return response.data;
}

export async function getAll({controller} = {}) {
  const url = route;
  const params = {};
  if(controller) {
    params.controller = controller;
  }
  const response = await axios.get(url, {params});
  return response.data;
}

export async function remove({issuer}) {
  const url = route;
  try {
    await axios.delete(url, {
      params: {issuer}
    });
    return true;
  } catch(e) {
    if(e.name === 'NotFoundError') {
      return false;
    }
    throw e;
  }
}
