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
/**
 * PlaidCloud's address for "Why this number" on the clicked point: its Weave
 * deep link (`weave~<json>`), with the point's filters and the dashboard's
 * own. Dashboards are served from `dashboards.` beside the app.
 */
export const whyThisNumberUrl = (
  dashboardId: number,
  chartId: number,
  filters: { col: unknown; op: string; val?: unknown; grain?: string }[],
  timeRange?: string,
) => {
  // A time-axis point keeps its grain: PlaidCloud then knows it is a bucket,
  // not one value of the column.
  const named = filters.map(({ col, op, val, grain }) => ({
    col:
      typeof col === 'string'
        ? col
        : String((col as { label?: string })?.label || 'computed column'),
    op,
    val,
    ...(grain ? { grain } : {}),
  }));
  if (timeRange && timeRange !== 'No filter') {
    named.push({ col: '__time_range', op: 'TEMPORAL_RANGE', val: timeRange });
  }
  const context = {
    surface: 'link',
    dashboard_id: String(dashboardId),
    selection: {
      kind: 'chart_point',
      dashboard_id: String(dashboardId),
      chart_id: String(chartId),
      filters: named,
    },
  };
  const state = `weave~${JSON.stringify({ context, action: 'why_number' })}`;
  const origin = window.location.origin.replace('://dashboards.', '://');
  return `${origin}/#${encodeURIComponent(state)}`;
};
