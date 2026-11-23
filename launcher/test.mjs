import assert from 'node:assert/strict';
import test from 'node:test';
import { chooseCabinet, cabinetFetch } from './dist/cabinet.js';

test('health checks only the configured controller', async () => {
  const calls = [];
  const result = await chooseCabinet('https://controller.example', async (url, options) => {
    calls.push([url, options]);
    return {ok: true, json: async () => ({status: 'ok'})};
  });
  assert.equal(result, 'https://controller.example/api/cabinet');
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], result + '/health');
  assert.equal(calls[0][1].redirect, 'error');
  assert.equal(calls[0][1].credentials, 'omit');
});
test('an unavailable controller yields no fallback', async () => {
  assert.equal(await chooseCabinet('https://controller.example', async () => { throw Error('offline'); }), null);
});
test('mutations are never automatically retried', async () => {
  let calls = 0;
  await assert.rejects(cabinetFetch('https://controller.example/test', {method: 'POST'}, async () => {
    calls++; throw Error('lost response');
  }));
  assert.equal(calls, 1);
});
test('a hanging request is aborted', async () => {
  await assert.rejects(cabinetFetch('https://controller.example/test', {}, async (_url, options) =>
    new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(Error('aborted')))), 5), /aborted/);
});
