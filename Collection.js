/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {findDocuments, getEdvDocument} from './utils.js';

export default class Collection {
  constructor({type, instance, account}) {
    this.type = type;
    this.instance = instance;
    this.account = account;
    // FIXME: get capability from `account`, not instance
    this.capability = instance.capability.find(
      c => c.referenceId === 'configuration');
  }

  async create({item}) {
    const {account, instance, capability} = this;
    const edvDoc = await getEdvDocument({account, instance, capability});
    await edvDoc.write({doc: {content: item}});
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
