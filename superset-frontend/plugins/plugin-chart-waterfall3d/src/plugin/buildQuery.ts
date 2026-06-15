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
import { buildQueryContext, QueryFormColumn } from '@superset-ui/core';
import { Waterfall3DFormData } from '../types';

/**
 * Query for a 3D waterfall: the step dimension (bridge stages along X) and a
 * series dimension (depth), with one metric aggregated per (step, series)
 * pair. The running totals / floating bars are computed in transformProps.
 *
 * Step order drives the bridge, so it is set explicitly. Following the native
 * 2D waterfall, the sort column (and any tooltip column) is added to the group
 * by so ordering by it is valid SQL; falls back to the metric descending.
 */
export default function buildQuery(formData: Waterfall3DFormData) {
  const {
    stepColumn,
    seriesColumn,
    metric,
    seriesOrderByColumn,
    seriesOrderDirection,
    tooltip_column: tooltipColumn,
  } = formData;

  const columns = [stepColumn, seriesColumn].filter(
    Boolean,
  ) as QueryFormColumn[];
  if (seriesOrderByColumn && !columns.includes(seriesOrderByColumn)) {
    columns.push(seriesOrderByColumn);
  }
  if (tooltipColumn && !columns.includes(tooltipColumn)) {
    columns.push(tooltipColumn);
  }

  const orderby: [QueryFormColumn, boolean][] = seriesOrderByColumn
    ? [[seriesOrderByColumn, seriesOrderDirection !== 'DESC']]
    : metric
      ? [[metric as unknown as QueryFormColumn, false]]
      : [];

  return buildQueryContext(formData, baseQueryObject => [
    {
      ...baseQueryObject,
      columns,
      metrics: metric ? [metric] : baseQueryObject.metrics,
      orderby,
    },
  ]);
}
