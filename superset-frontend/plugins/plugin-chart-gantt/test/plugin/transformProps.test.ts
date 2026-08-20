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
  {
    id: '1',
    task: 'Task 1',
    team: 'Alpha',
    starts: '2024-01-01',
    ends: '2024-01-10',
  },
  {
    id: '2',
    task: 'Task 2',
    team: 'Alpha',
    starts: '2024-01-05',
    ends: '2024-01-20',
  },
];

const buildChartProps = (formDataOverrides = {}, data = DATA) =>
  new ChartProps({
    formData: {
      colorScheme: 'bnbColors',
      datasource: '3__table',
      granularity_sqla: 'ds',
      task_id_column: 'id',
      task_column: 'task',
      category_column: 'team',
      start_time_column: 'starts',
      end_time_column: 'ends',
      ...formDataOverrides,
    },
    width: 800,
    height: 600,
    theme: supersetTheme,
    queriesData: [{ data }],
  });

describe('PluginChartGantt transformProps', () => {
  test('passes width and height through untouched', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(transformed.width).toBe(800);
    expect(transformed.height).toBe(600);
  });

  test('returns the contract the chart component consumes', () => {
    const transformed = transformProps(buildChartProps()) as any;

    // Keys rather than a snapshot: echartOptions alone is ~180 lines and would
    // make this test fail on any cosmetic change without telling us anything.
    expect(Object.keys(transformed).sort()).toEqual(
      [
        'barHeightRatio',
        'categories',
        'customEndDate',
        'customStartDate',
        'echartOptions',
        'expandedState',
        'flattenedTasks',
        'height',
        'showBarLabels',
        'showProgress',
        'showTodayMarker',
        'showYAxisLabels',
        'taskFilter',
        'tasks',
        'timeGranularity',
        'timeRangePreset',
        'title',
        'width',
        'zoomable',
      ].sort(),
    );
  });

  test('renders one y-axis category per task, bulleted', () => {
    const { categories } = transformProps(buildChartProps()) as any;

    // One row per task, not one per category_column value.
    expect(categories).toEqual(['\u2022 Task 1', '\u2022 Task 2']);
  });

  test('turns every row into a task', () => {
    const { flattenedTasks } = transformProps(buildChartProps()) as any;

    expect(flattenedTasks).toHaveLength(DATA.length);
  });

  test('defaults the today marker on', () => {
    const transformed = transformProps(buildChartProps()) as any;

    expect(transformed.showTodayMarker).toBe(true);
  });

  test('lets the form data turn the today marker off', () => {
    const transformed = transformProps(
      buildChartProps({ showTodayMarker: false }),
    ) as any;

    expect(transformed.showTodayMarker).toBe(false);
  });

  test('produces no tasks or categories when the query came back empty', () => {
    const transformed = transformProps(buildChartProps({}, [])) as any;

    expect(transformed.flattenedTasks).toEqual([]);
    expect(transformed.categories).toEqual([]);
  });
});
