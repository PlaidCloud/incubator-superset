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
import { ChartProps } from '@superset-ui/core';
import { supersetTheme } from '@apache-superset/core/theme';
import transformProps from '../../src/plugin/transformProps';

// Deliberately unsorted so the ordering behaviour is actually exercised.
const DATA = [
  { name: 'Thor', sum__num: 20 },
  { name: 'Hulk', sum__num: 50 },
  { name: 'Loki', sum__num: 30 },
];

const buildChartProps = (formDataOverrides = {}, data = DATA) =>
  new ChartProps({
    formData: {
      colorScheme: 'bnbColors',
      datasource: '3__table',
      metrics: ['sum__num'],
      columns: 'name',
      ...formDataOverrides,
    },
    width: 800,
    height: 600,
    theme: supersetTheme,
    queriesData: [{ data, coltypes: [] }],
  }) as any;

describe('SupersetPluginChartWhale transformProps', () => {
  test('passes width and height through untouched', () => {
    const transformed = transformProps(buildChartProps());

    expect(transformed.width).toBe(800);
    expect(transformed.height).toBe(600);
  });

  test('returns the contract the chart component consumes', () => {
    const transformed = transformProps(buildChartProps());

    // Asserting the keys rather than a full snapshot: the echartOptions payload
    // is large and volatile, and pinning it would make this test fail on every
    // cosmetic change without telling us anything useful.
    expect(Object.keys(transformed).sort()).toEqual(
      [
        'data',
        'echartOptions',
        'emitCrossFilters',
        'formData',
        'groupby',
        'height',
        'labelMap',
        'onContextMenu',
        'refs',
        'selectedValues',
        'setDataMask',
        'width',
      ].sort(),
    );
  });

  test('sorts records by metric descending', () => {
    const { data } = transformProps(buildChartProps());

    expect(data.map((d: any) => d.name)).toEqual(['Hulk', 'Loki', 'Thor']);
  });

  test('accumulates the metric and derives its percentages', () => {
    const { data } = transformProps(buildChartProps());

    // Total is 100, which makes the expected percentages readable by hand.
    expect(data.map((d: any) => d.cumulativeMetric)).toEqual([50, 80, 100]);
    expect(data.map((d: any) => d.metricPct)).toEqual([50, 30, 20]);
    expect(data.map((d: any) => d.cumulativeMetricPct)).toEqual([50, 80, 100]);
  });

  test('spreads entity percentiles evenly across the records', () => {
    const { data } = transformProps(buildChartProps());

    expect(data.map((d: any) => Math.round(d.entityPercentile))).toEqual([
      33, 67, 100,
    ]);
  });

  test('builds a label map keyed by the groupby column', () => {
    const { labelMap } = transformProps(buildChartProps());

    expect(labelMap).toEqual({
      Thor: ['Thor'],
      Hulk: ['Hulk'],
      Loki: ['Loki'],
    });
  });

  test('returns no data when the query came back empty', () => {
    const { data } = transformProps(buildChartProps({}, []));

    expect(data).toEqual([]);
  });
});
