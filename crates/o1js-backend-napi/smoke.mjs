import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const modulePath = process.argv[2];
if (modulePath === undefined) {
  throw new Error('usage: node smoke.mjs /absolute/path/to/o1js_backend.node');
}

const require = createRequire(import.meta.url);
const { backendInfo, MinaRustBackend } = require(modulePath);
const info = JSON.parse(backendInfo());
assert.equal(info.backendApiVersion, 1);
assert.equal(info.wireFormatVersion, 1);

const backend = new MinaRustBackend(8);
const getInfo = JSON.stringify({
  version: 1,
  payload: { operation: 'getInfo' },
});
const sync = JSON.parse(backend.execute(getInfo));
assert.equal(sync.version, 1);
assert.equal(sync.payload.status, 'ok');

const concurrent = await Promise.all([
  backend.executeAsync(getInfo),
  backend.executeAsync(getInfo),
]);
assert.deepEqual(JSON.parse(concurrent[0]), JSON.parse(concurrent[1]));

const compile = JSON.stringify({
  version: 1,
  payload: {
    operation: 'compileCircuit',
    input: {
      circuit: {
        aux_count: 2,
        output: [{ terms: [['1', 1]] }],
        constraints: [
          {
            kind: 'square',
            v: { terms: [['1', 0]] },
            square: { terms: [['1', 1]] },
          },
        ],
      },
    },
  },
});
const compiled = JSON.parse(backend.execute(compile));
const circuitId = compiled.payload.value.output.circuitId;
const prove = JSON.stringify({
  version: 1,
  payload: {
    operation: 'proveCircuit',
    input: { circuitId, witness: ['6', '36'] },
  },
});
const controller = new AbortController();
const runningProof = backend.executeAsync(prove);
const cancelledProof = backend.executeAsync(prove, controller.signal);
controller.abort();
await assert.rejects(cancelledProof);
const proofResponse = JSON.parse(await runningProof);
assert.equal(proofResponse.payload.status, 'ok');
