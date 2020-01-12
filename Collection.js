/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {EdvClient} from 'edv-client';
import {findDocuments, getEdvDocument, getCapability} from './utils.js';

export default class Collection {
  constructor({type, instance, account, capability}) {
    this.type = type;
    this.instance = instance;
    this.account = account;
    this.capability = capability;
  }

  // FIXME: bikeshed name
  static async getInstance({type, instance, account}) {
    const capability = await getCapability({
      referenceId: `${instance.id}-edv-configuration`,
      controller: account.id
    });
    return new Collection({type, instance, account, capability});
  }

  async create({item}) {
    if(item.type !== this.type) {
      throw new TypeError(`"item.type" (${item.type}) must be "${this.type}".`);
    }
    const {account, instance, capability} = this;
    const edvDoc = await getEdvDocument({account, instance, capability});
    const id = await EdvClient.generateId();
    await edvDoc.write({doc: {id, content: item}});
  }

  async get({id}) {
    const {account, instance, capability} = this;
    const results = await findDocuments({account, instance, id, capability});
    if(results.length > 0) {
      return results[0];
    }
    return null;
  }

  async getAll() {
    const {account, instance, capability} = this;
    const results = await findDocuments(
      {account, instance, type: this.type, capability});
    return results;
  }

  async update({item}) {
    if(item.type !== this.type) {
      throw new TypeError(`"item.type" (${item.type}) must be "${this.type}".`);
    }
    const {account, capability} = this;
    const existing = await this.get({id: item.id});
    const edvDoc = await getEdvDocument({account, id: existing.id, capability});
    const doc = await edvDoc.read();
    await edvDoc.write({
      doc: {
        ...doc,
        content: item
      }
    });
  }

  async remove({id}) {
    const {account, capability} = this;
    const existing = await this.get({id});
    if(!existing) {
      return false;
    }
    const edvDoc = await getEdvDocument({account, id: existing.id, capability});
    return edvDoc.delete();
  }
}
