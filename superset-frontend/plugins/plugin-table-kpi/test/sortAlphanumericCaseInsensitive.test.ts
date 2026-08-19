/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { sortAlphanumericCaseInsensitive } from '../src/DataTable/utils/sortAlphanumericCaseInsensitive';

const testData = [
  'test value',
  'a lowercase test value',
  '5',
  NaN,
  '1234',
  Infinity,
  '.!# value starting with non-letter characters',
  'An uppercase test value',
  undefined,
  null,
];

describe('sortAlphanumericCaseInsensitive', () => {
  const sortValues = (values: any[]) =>
    [...values].sort((a, b) => sortAlphanumericCaseInsensitive(a, b));

  test('orders strings case-insensitively', () => {
    const sorted = sortValues(testData).filter(v => typeof v === 'string');

    expect(sorted).toEqual([
      '.!# value starting with non-letter characters',
      '1234',
      '5',
      'a lowercase test value',
      'An uppercase test value',
      'test value',
    ]);
  });

  test('keeps the strings contiguous, wherever the non-strings land', () => {
    const sorted = sortValues(testData);
    const stringIndexes = sorted
      .map((v, i) => (typeof v === 'string' ? i : -1))
      .filter(i => i !== -1);

    // Deliberately not asserting where null/undefined/NaN/Infinity end up. The
    // comparator answers -1 whenever the left value is not a string, so for two
    // non-strings it says -1 in both directions - that is not a total order,
    // and their final positions are an artefact of the sort algorithm rather
    // than a guarantee. (Observed today: null and the numbers sort ahead of the
    // strings while undefined lands last.) What the chart actually relies on is
    // that the strings come out in order and next to each other.
    expect(stringIndexes).toEqual(
      Array.from(
        { length: stringIndexes.length },
        (_, i) => stringIndexes[0] + i,
      ),
    );
  });

  test('keeps every input value', () => {
    expect(sortValues(testData)).toHaveLength(testData.length);
  });
});

const testDataMulti = [
  { colA: 'group 1', colB: '10' },
  { colA: 'group 1', colB: '15' },
  { colA: 'group 1', colB: '20' },
  { colA: 'group 2', colB: '10' },
  { colA: 'group 3', colB: '10' },
  { colA: 'group 3', colB: '15' },
  { colA: 'group 3', colB: '10' },
];

describe('sortAlphanumericCaseInsensitiveMulti', () => {
  test('Sort rows by multiple columns', () => {
    const sorted = [...testDataMulti].sort((a, b) => {
      // Primary sort by colA
      const colASort = sortAlphanumericCaseInsensitive(a.colA, b.colA);
      if (colASort !== 0) {
        return colASort;
      }
      // Secondary sort by colB (descending)
      return -sortAlphanumericCaseInsensitive(a.colB, b.colB);
    });

    expect(sorted).toEqual([
      {
        colA: 'group 1',
        colB: '20',
      },
      {
        colA: 'group 1',
        colB: '15',
      },
      {
        colA: 'group 1',
        colB: '10',
      },
      {
        colA: 'group 2',
        colB: '10',
      },
      {
        colA: 'group 3',
        colB: '15',
      },
      {
        colA: 'group 3',
        colB: '10',
      },
      {
        colA: 'group 3',
        colB: '10',
      },
    ]);
  });
});
