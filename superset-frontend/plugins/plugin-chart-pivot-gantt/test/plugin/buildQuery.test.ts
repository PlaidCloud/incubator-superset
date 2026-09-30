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
import buildQuery from '../../src/plugin/buildQuery';

const formData = {
  datasource: '5__table',
  viz_type: 'pivot_gantt',
  groupbyRows: ['stage', 'substage'],
  metrics: ['cost', 'progress'],
  date_start_col: 'start',
  date_end_col: ['end'],
  marker_label_top_col: [],
  marker_description_cols: ['owner'],
  order_by_col: 'stage',
  order_desc: true,
  extras: { time_grain_sqla: 'P1D' },
};

describe('PivotGantt buildQuery', () => {
  const { queries } = buildQuery(formData as any);

  test('emits raw rows + grand total + one query per hierarchy level', () => {
    expect(queries).toHaveLength(4);
  });

  test('raw query has hierarchy, date and label columns and no metrics', () => {
    expect(queries[0].columns).toEqual([
      'stage',
      'substage',
      'start',
      'end',
      'owner',
    ]);
    expect(queries[0].metrics).toEqual([]);
    expect(queries[0].orderby).toEqual([
      ['stage', false],
      ['substage', true],
    ]);
  });

  test('grand total and per-level queries carry the metrics', () => {
    expect(queries[1].columns).toEqual([]);
    expect(queries[1].metrics).toEqual(['cost', 'progress']);
    expect(queries[2].columns).toEqual(['stage']);
    expect(queries[3].columns).toEqual(['stage', 'substage']);
  });

  test('drops time grain from extras', () => {
    queries.forEach(q => {
      expect(q.extras).not.toHaveProperty('time_grain_sqla');
    });
  });

  test('skips metric queries when there are no metrics', () => {
    const q = buildQuery({ ...formData, metrics: [] } as any).queries;
    expect(q).toHaveLength(1);
  });
});
