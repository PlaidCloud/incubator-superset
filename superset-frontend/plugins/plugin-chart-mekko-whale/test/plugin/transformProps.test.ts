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

const DATA = [{ name: 'Hulk', sum__num: 1 }];

const buildChartProps = (formDataOverrides = {}, data = DATA) =>
  new ChartProps({
    formData: {
      colorScheme: 'bnbColors',
      datasource: '3__table',
      granularity_sqla: 'ds',
      metric: 'sum__num',
      series: 'name',
      ...formDataOverrides,
    },
    width: 800,
    height: 600,
    theme: supersetTheme,
    queriesData: [{ data }],
  });

describe('PluginChartMekkoWhale transformProps', () => {
  it('passes width and height through untouched', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(transformed.width).toBe(800);
    expect(transformed.height).toBe(600);
  });

  it('returns the contract the chart component consumes', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(Object.keys(transformed).sort()).toEqual(
      [
        'data',
        'filterState',
        'groupby',
        'height',
        'setDataMask',
        'showTotalProfit',
        'totalProfit',
        'totalRevenue',
        'waterfallMode',
        'width',
        'xAxisFormat',
        'xAxisLabel',
        'xAxisLabel',
        'xMax',
        'yAxisFormat',
        'yAxisLabel',
        'yMax',
        'yMin',
      ]
        .filter((v, i, a) => a.indexOf(v) === i)
        .sort(),
    );
  });

  it('labels the axes from the metrics, falling back when unnamed', () => {
    const transformed = transformProps(buildChartProps()) as any;

    // No second metric is configured, so the x axis falls back to "Revenue".
    expect(transformed.xAxisLabel).toBe('Revenue');
    expect(transformed.yAxisLabel).toBe('Cumulative sum__num');
  });

  it('totals the metric across the records', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(transformed.totalProfit).toBe(1);
    expect(transformed.yMax).toBe(1);
    expect(transformed.yMin).toBe(0);
  });

  it('shapes each record into a positioned segment', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(transformed.data).toHaveLength(1);
    // value carries the segment geometry, not the raw row.
    expect(Array.isArray(transformed.data[0].value)).toBe(true);
    expect(transformed.data[0].itemStyle).toEqual(
      expect.objectContaining({ opacity: 1 }),
    );
  });

  it('returns no segments when the query came back empty', () => {
    const transformed = transformProps(buildChartProps({}, [])) as any;

    expect(transformed.data).toEqual([]);
    expect(transformed.totalProfit).toBe(0);
  });
});
