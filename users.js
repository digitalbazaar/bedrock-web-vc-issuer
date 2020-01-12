/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';

const route = '/vc-issuer/instances';

export async function claim({instanceId, token}) {
  const url = `${route}/${encodeURIComponent(instanceId)}/claim-user`;
  const response = await axios.post(url, {instanceId, token});
  return response.data;
}
