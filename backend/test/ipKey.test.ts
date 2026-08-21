/**
 * The rate limiters are only as good as their key. An IPv6 bug here silently
 * turns the login limit into decoration, so the normalisation is tested
 * directly rather than trusted.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ipKey } from '../src/utils/ipKey.js';

describe('ipKey', () => {
  test('passes IPv4 through unchanged', () => {
    assert.equal(ipKey('203.0.113.4'), '203.0.113.4');
  });

  test('unwraps IPv4-mapped IPv6, which Express hands back on dual-stack sockets', () => {
    assert.equal(ipKey('::ffff:203.0.113.4'), '203.0.113.4');
    assert.equal(ipKey('::FFFF:203.0.113.4'), '203.0.113.4');
  });

  test('collapses IPv6 to its /64 so one subscriber cannot draw 2^64 budgets', () => {
    const a = ipKey('2001:db8:1234:5678:1111:2222:3333:4444');
    const b = ipKey('2001:db8:1234:5678:9999:8888:7777:6666');
    assert.equal(a, b, 'addresses in the same /64 must share a bucket');
    assert.equal(a, '2001:db8:1234:5678::/64');
  });

  test('keeps different /64s apart', () => {
    assert.notEqual(
      ipKey('2001:db8:1234:5678::1'),
      ipKey('2001:db8:1234:9999::1'),
    );
  });

  test('resolves :: compression correctly', () => {
    assert.equal(ipKey('2001:db8::1'), '2001:db8:0:0::/64');
    assert.equal(ipKey('::1'), '0:0:0:0::/64');
    assert.equal(ipKey('fe80::abcd:1234:5678:9abc'), 'fe80:0:0:0::/64');
  });

  test('strips a zone index', () => {
    assert.equal(ipKey('fe80::1%eth0'), ipKey('fe80::1'));
  });

  test('does not merge unparseable values into one shared bucket', () => {
    // Malformed input must not collapse distinct clients together, which would
    // let one of them exhaust the budget for all of them.
    assert.notEqual(ipKey('2001:db8:::::1'), ipKey('2001:db8::::9'));
  });

  test('handles a missing address without throwing', () => {
    assert.equal(ipKey(undefined), 'unknown');
    assert.equal(ipKey(''), 'unknown');
  });
});
