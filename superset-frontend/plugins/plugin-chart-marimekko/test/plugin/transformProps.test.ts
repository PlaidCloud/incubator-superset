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

const DATA = [
  { name: 'Hulk', sum__num: 1 },
  { name: 'Thor', sum__num: 3 },
];

const buildChartProps = (formDataOverrides = {}, data = DATA) =>
  new ChartProps({
    formData: {
      colorScheme: 'bnbColors',
      datasource: '3__table',
      granularity_sqla: 'ds',
      metric: 'sum__num',
      series: 'name',
      boldText: true,
      headerFontSize: 'xs',
      headerText: 'my text',
      ...formDataOverrides,
    },
    width: 800,
    height: 600,
    theme: supersetTheme,
    queriesData: [{ data }],
  });

describe('PluginChartMarimekko transformProps', () => {
  test('passes width, height and query data through', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(transformed.width).toBe(800);
    expect(transformed.height).toBe(600);
    expect(transformed.data).toEqual(DATA);
  });

  test('returns the contract the chart component consumes', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(Object.keys(transformed).sort()).toEqual(
      [
        'boldText',
        'data',
        'headerFontSize',
        'headerText',
        'height',
        'heightKey',
        'labelColor',
        'showLabels',
        'showLegend',
        'showPercentage',
        'sortByColumn',
        'sortOrder',
        'title',
        'tooltipIncludeColumn',
        'tooltipNumberFormat',
        'tooltipShowPercentage',
        'width',
        'widthKey',
        'xAxisLabel',
        'yAxisLabel',
      ].sort(),
    );
  });

  test('forwards the control values it is given', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(transformed.boldText).toBe(true);
    expect(transformed.headerFontSize).toBe('xs');
    expect(transformed.headerText).toBe('my text');
  });

  test('applies defaults for the controls left unset', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(transformed.tooltipNumberFormat).toBe('SMART_NUMBER');
    expect(transformed.showLabels).toBe(true);
    expect(transformed.tooltipIncludeColumn).toBe(true);
    expect(transformed.tooltipShowPercentage).toBe(true);
    expect(transformed.showLegend).toBe(false);
    expect(transformed.xAxisLabel).toBe('');
    expect(transformed.yAxisLabel).toBe('');
  });

  test('lets the form data override those defaults', () => {
    const transformed = transformProps(
      buildChartProps({
        showLegend: true,
        showLabels: false,
        xAxisLabel: 'Revenue',
        yAxisLabel: 'Margin',
        tooltipNumberFormat: ',.2f',
      }),
    ) as any;

    expect(transformed.showLegend).toBe(true);
    expect(transformed.showLabels).toBe(false);
    expect(transformed.xAxisLabel).toBe('Revenue');
    expect(transformed.yAxisLabel).toBe('Margin');
    expect(transformed.tooltipNumberFormat).toBe(',.2f');
  });

  test('returns no data when the query came back empty', () => {
    const transformed = transformProps(buildChartProps({}, [])) as any;

    expect(transformed.data).toEqual([]);
  });
});
