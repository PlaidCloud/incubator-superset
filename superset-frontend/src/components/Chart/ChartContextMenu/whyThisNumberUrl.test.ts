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
import { whyThisNumberUrl } from './ChartContextMenu';

const decoded = (url: string) =>
  JSON.parse(
    decodeURIComponent(url.split('#')[1]).replace(/^weave~/, ''),
  );

test('the link names the clicked point on the PlaidCloud host beside dashboards', () => {
  const url = whyThisNumberUrl(7, 9, [
    { col: 'city', op: '==', val: 'Atlanta' },
  ]);
  expect(url.startsWith(`${window.location.origin}/#weave~`)).toBe(true);
  expect(decoded(url)).toEqual({
    action: 'why_number',
    context: {
      surface: 'link',
      dashboard_id: '7',
      selection: {
        kind: 'chart_point',
        dashboard_id: '7',
        chart_id: '9',
        filters: [{ col: 'city', op: '==', val: 'Atlanta' }],
      },
    },
  });
});

test('a time range and a computed column are carried so PlaidCloud can say the point is not one slice', () => {
  const { filters } = decoded(
    whyThisNumberUrl(
      7,
      9,
      [{ col: { label: 'Year', sqlExpression: 'year(d)' }, op: '==', val: 1 }],
      'Last quarter',
    ),
  ).context.selection;
  expect(filters).toEqual([
    { col: 'Year', op: '==', val: 1 },
    { col: '__time_range', op: 'TEMPORAL_RANGE', val: 'Last quarter' },
  ]);
});

test('a time-axis point keeps its grain', () => {
  const { filters } = decoded(
    whyThisNumberUrl(7, 9, [
      { col: 'order_date', op: '==', val: 1730419200000, grain: 'P1M' },
    ]),
  ).context.selection;
  expect(filters).toEqual([
    { col: 'order_date', op: '==', val: 1730419200000, grain: 'P1M' },
  ]);
});
