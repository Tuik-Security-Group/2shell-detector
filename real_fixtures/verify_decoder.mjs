// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2026 Tuik Security Group
// Local decoder contract test. No network, server action, function reference,
// prototype traversal, or executable input. Use a prepared fixture directory.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';

const root = resolve(process.argv[2]);
const version = JSON.parse(readFileSync(resolve(root, 'node_modules/react-server-dom-webpack/package.json'))).version;
assert(['19.2.0', '19.2.1'].includes(version), 'Contract expectations are pinned to the tested patch pair');
const {decodeReply} = await import(pathToFileURL(resolve(root, 'node_modules/react-server-dom-webpack/server.node.js')));
const results = [];
for (const [kind, value, reference] of [
  ['control', '{}', '["$1:a"]'],
  ['candidate', '{}', '["$1:a:a"]'],
  ['present_property_control', '{"a":{}}', '["$1:a:a"]'],
]) {
  const form = new FormData();
  form.set('1', value);
  form.set('0', reference);
  let rejected = false;
  try {
    const result = await decodeReply(form, {});
    assert.deepEqual(result, version === '19.2.0' ? [undefined] : [{}]);
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
    rejected = true;
  }
  assert.equal(rejected, version === '19.2.0' && kind === 'candidate');
  results.push({kind, rejected});
}
console.log(JSON.stringify({version, results, passed: true}));
