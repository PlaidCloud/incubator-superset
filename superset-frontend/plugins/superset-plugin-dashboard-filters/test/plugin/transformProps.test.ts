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
      ...formDataOverrides,
    },
    width: 800,
    height: 600,
    theme: supersetTheme,
    queriesData: [{ data }],
  });

describe('SupersetPluginDashboardFilters transformProps', () => {
  it('passes width, height and query data through', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(transformed.width).toBe(800);
    expect(transformed.height).toBe(600);
    expect(transformed.data).toEqual(DATA);
  });

  it('returns the contract the filter component consumes', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(Object.keys(transformed).sort()).toEqual(
      [
        'allowMultiple',
        'col',
        'data',
        'emitCrossFilters',
        'filterState',
        'height',
        'setDataMask',
        'width',
      ].sort(),
    );
  });

  it('starts with cross-filter emission off and an empty filter state', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(transformed.emitCrossFilters).toBe(false);
    expect(transformed.filterState).toEqual({});
  });

  it('forwards the column and multi-select control values', () => {
    const transformed = transformProps(
      buildChartProps({ col: 'name', allowMultiple: true }),
    ) as any;

    expect(transformed.col).toBe('name');
    expect(transformed.allowMultiple).toBe(true);
  });

  it('returns no data when the query came back empty', () => {
    const transformed = transformProps(buildChartProps({}, [])) as any;

    expect(transformed.data).toEqual([]);
  });
});
