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
import {
  buildQueryContext,
  ensureIsArray,
  getColumnLabel,
  QueryFormColumn,
  QueryFormOrderBy,
  QueryObject,
} from '@superset-ui/core';
import { PivotGanttFormData } from '../types';

/**
 * Optional dnd column controls hydrate as `[]` (truthy!) when empty, and
 * single selects may hold `''`. Flatten and drop both.
 */
const cleanColumns = (cols: unknown): QueryFormColumn[] =>
  (ensureIsArray(cols) as unknown[])
    .flat()
    .filter(c =>
      typeof c === 'string' ? c !== '' : Boolean(c),
    ) as QueryFormColumn[];

const dedupe = (cols: QueryFormColumn[]): QueryFormColumn[] => {
  const seen = new Set<string>();
  return cols.filter(c => {
    const label = getColumnLabel(c);
    if (seen.has(label)) return false;
    seen.add(label);
    return true;
  });
};

/**
 * Query contract (same as the reference "pivot_gantt" plugin):
 *   Q0            raw rows: hierarchy + date + label columns, no metrics
 *   Q1            grand total: metrics, no columns          (only if metrics)
 *   Q2..Q(N+1)    metrics grouped by each hierarchy prefix   (only if metrics)
 */
export default function buildQuery(formData: PivotGanttFormData) {
  const rows = cleanColumns(formData.groupbyRows);
  const extraCols = cleanColumns([
    formData.date_start_col,
    formData.date_end_col,
    formData.marker_label_left_col,
    formData.marker_label_right_col,
    formData.marker_label_top_col,
    formData.marker_label_bottom_col,
    formData.marker_description_cols,
  ]);
  const orderByCol = ensureIsArray(formData.order_by_col)[0] as
    | string
    | undefined;
  const orderDesc = formData.order_desc ?? true;

  const orderFor = (cols: QueryFormColumn[]): QueryFormOrderBy[] =>
    cols.map(c => [
      c,
      !(orderByCol && getColumnLabel(c) === orderByCol && orderDesc),
    ]);

  return buildQueryContext(formData, baseQueryObject => {
    const { metrics = [], extras = {} } = baseQueryObject;
    // the calendar needs raw dates: never apply a time grain to the rows
    const cleanExtras = Object.fromEntries(
      Object.entries(extras).filter(([k]) => k !== 'time_grain_sqla'),
    );
    const base: QueryObject = { ...baseQueryObject, extras: cleanExtras };
    const queries: QueryObject[] = [
      {
        ...base,
        metrics: [],
        orderby: orderFor(rows),
        columns: dedupe([...rows, ...extraCols]),
      },
    ];
    if (metrics.length) {
      queries.push({ ...base, metrics, orderby: [], columns: [] });
      rows.forEach((_, i) => {
        const prefix = rows.slice(0, i + 1);
        queries.push({
          ...base,
          metrics,
          orderby: orderFor(prefix),
          columns: prefix,
        });
      });
    }
    return queries;
  });
}
