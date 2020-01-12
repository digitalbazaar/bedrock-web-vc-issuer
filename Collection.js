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

  async create({item, meta}) {
    if(item.type !== this.type) {
      throw new TypeError(`"item.type" (${item.type}) must be "${this.type}".`);
    }
    const {account, instance, capability} = this;
    const edvDoc = await getEdvDocument({account, instance, capability});
    const id = await EdvClient.generateId();
    await edvDoc.write({doc: {id, content: item, meta}});
  }

  async get({id, token}) {
    const {account, instance, capability} = this;
    let results;
    if(id) {
      results = await findDocuments({account, instance, id, capability});
    } else if(token) {
      results = await findDocuments({
        account,
        instance,
        equals: {'content.type': this.type, 'meta.token.id': token},
        capability
      });
    } else {
      throw new TypeError('"id" or "token" must be given.');
    }
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

  async update({item, meta}) {
    if(item.type !== this.type) {
      throw new TypeError(`"item.type" (${item.type}) must be "${this.type}".`);
    }
    const {account, instance, capability} = this;
    const existing = await this.get({id: item.id});
    const edvDoc = await getEdvDocument(
      {id: existing.id, account, instance, capability});
    const doc = await edvDoc.read();
    const updatedDoc = {
      ...doc
    };
    if(item) {
      updatedDoc.content = item;
    }
    if(meta) {
      updatedDoc.meta = meta;
    }
    await edvDoc.write({
      doc: updatedDoc
    });
  }

  async remove({id}) {
    const {account, instance, capability} = this;
    const existing = await this.get({id});
    if(!existing) {
      return false;
    }
    const edvDoc = await getEdvDocument(
      {id: existing.id, account, instance, capability});
    return edvDoc.delete();
  }
}
