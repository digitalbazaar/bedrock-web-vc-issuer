/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';

const route = '/vc-issuer/registrations';

export async function create({controller, presentation}) {
  const url = route;
  const response = await axios.post(url, {controller, presentation});
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
