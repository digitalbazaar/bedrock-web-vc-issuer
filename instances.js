/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';

const route = '/vc-issuer/instances';

export async function create({instance}) {
  const url = route;
  const response = await axios.post(url, instance);
  return response.data;
}

export async function get({id}) {
  const url = `${route}/${encodeURIComponent(id)}`;
  const response = await axios.get(url);
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
