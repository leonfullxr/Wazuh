import { describe, expect, it } from 'vitest';
import { resolveWindow } from '../../src/app/state/time-window';

describe('workspace time window', () => {
  const anchor = Date.parse('2026-10-30T12:00:00.000Z');
  it('keeps preset bounds fixed to the selected anchor', () => {
    const input = {range:'7d' as const, anchor, from:null, to:null};
    expect(resolveWindow(input)).toEqual({from:'2026-10-23T12:00:00.000Z', to:'2026-10-30T12:00:00.000Z'});
  });
  it('uses a 24-hour interval ending at a to-only deep link', () => {
    expect(resolveWindow({range:'30d', anchor, from:null, to:'2026-10-20T07:00:00Z'})).toEqual({from:'2026-10-19T07:00:00.000Z', to:'2026-10-20T07:00:00Z'});
  });
  it('preserves both explicit endpoints and uses the anchor for a from-only link', () => {
    const from='2026-10-25T00:00:00.123Z';
    expect(resolveWindow({range:'24h', anchor, from, to:null})).toEqual({from, to:'2026-10-30T12:00:00.000Z'});
    expect(resolveWindow({range:'24h', anchor, from, to:'2026-10-26T03:00:00Z'})).toEqual({from, to:'2026-10-26T03:00:00Z'});
  });
});
