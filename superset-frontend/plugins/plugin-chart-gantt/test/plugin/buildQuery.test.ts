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

describe('PluginChartGantt buildQuery', () => {
  const baseFormData = {
    datasource: '5__table',
    granularity_sqla: 'ds',
    viz_type: 'my_chart',
  };

  it('collects the configured task columns, in declaration order', () => {
    const [query] = buildQuery({
      ...baseFormData,
      task_id_column: 'id',
      task_column: 'task',
      category_column: 'team',
      parent_column: 'parent',
      start_time_column: 'starts',
      end_time_column: 'ends',
      progress_column: 'pct',
    }).queries;

    expect(query.columns).toEqual([
      'id',
      'task',
      'team',
      'parent',
      'starts',
      'ends',
      'pct',
    ]);
  });

  it('omits columns that were left unconfigured', () => {
    const [query] = buildQuery({
      ...baseFormData,
      task_column: 'task',
      start_time_column: 'starts',
      end_time_column: 'ends',
    }).queries;

    expect(query.columns).toEqual(['task', 'starts', 'ends']);
  });

  it('never groups, since the chart needs one row per task', () => {
    const [query] = buildQuery({
      ...baseFormData,
      task_column: 'task',
      category_column: 'team',
    }).queries;

    expect(query.groupby).toEqual([]);
  });

  it('asks for nothing when no columns are configured', () => {
    const [query] = buildQuery(baseFormData).queries;

    expect(query.columns).toEqual([]);
  });
});
