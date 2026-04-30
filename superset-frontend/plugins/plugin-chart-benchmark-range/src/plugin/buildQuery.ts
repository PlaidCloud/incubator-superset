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
  QueryFormData,
  QueryFormColumn,
  QueryFormMetric,
} from '@superset-ui/core';

type BenchmarkRangeBuildFormData = QueryFormData & {
  actual_metric?: QueryFormMetric;
  actual_pct?: QueryFormMetric;
  bar_left_pct?: QueryFormMetric;
  bar_width_pct?: QueryFormMetric;
  country_filter?: QueryFormColumn;
  entity_filter?: QueryFormColumn;
  entity_type_filter?: QueryFormColumn;
  function_filter?: QueryFormColumn;
  gap_metric?: QueryFormMetric;
  groupby?: QueryFormColumn[] | QueryFormColumn;
  margin_actual_f?: QueryFormMetric;
  margin_high_f?: QueryFormMetric;
  margin_low_f?: QueryFormMetric;
  margin_median_f?: QueryFormMetric;
  margin_target_f?: QueryFormMetric;
  median_metric?: QueryFormMetric;
  median_pct?: QueryFormMetric;
  period_filter?: QueryFormColumn;
  profit_center_filter?: QueryFormColumn;
  q1_metric?: QueryFormMetric;
  q3_metric?: QueryFormMetric;
  region_filter?: QueryFormColumn;
  show_filter_controls?: boolean;
  target_metric?: QueryFormMetric;
  target_pct?: QueryFormMetric;
};

function withMetricLabel(
  metric: QueryFormMetric | undefined,
  label: string,
): QueryFormMetric | undefined {
  if (!metric || typeof metric === 'string') {
    return metric;
  }
  return {
    ...metric,
    label: (metric as Record<string, any>).label || label,
  } as QueryFormMetric;
}

function withColumnLabel(
  column: QueryFormColumn | undefined,
  fallbackLabel: string,
): QueryFormColumn | undefined {
  if (!column || typeof column === 'string') {
    return column;
  }
  const columnRecord = column as Record<string, any>;
  return {
    ...columnRecord,
    label:
      columnRecord.label ||
      columnRecord.column_name ||
      columnRecord.sqlExpression ||
      columnRecord.expression ||
      fallbackLabel,
  } as QueryFormColumn;
}

function isSelectedColumn(column: QueryFormColumn | undefined) {
  if (!column) {
    return false;
  }
  if (typeof column === 'string') {
    return Boolean(column);
  }
  const columnRecord = column as Record<string, any>;
  return Boolean(
    columnRecord.column_name ||
      columnRecord.sqlExpression ||
      columnRecord.expression,
  );
}

export default function buildQuery(formData: BenchmarkRangeBuildFormData) {
  const {
    actual_metric: actualMetric,
    actual_pct: actualPct,
    bar_left_pct: barLeftPct,
    bar_width_pct: barWidthPct,
    country_filter: countryFilter,
    entity_filter: entityFilter,
    entity_type_filter: entityTypeFilter,
    function_filter: functionFilter,
    gap_metric: gapMetric,
    groupby,
    margin_actual_f: marginActualF,
    margin_high_f: marginHighF,
    margin_low_f: marginLowF,
    margin_median_f: marginMedianF,
    margin_target_f: marginTargetF,
    median_metric: medianMetric,
    median_pct: medianPct,
    period_filter: periodFilter,
    profit_center_filter: profitCenterFilter,
    q1_metric: q1Metric,
    q3_metric: q3Metric,
    region_filter: regionFilter,
    show_filter_controls: showFilterControls,
    target_metric: targetMetric,
    target_pct: targetPct,
  } = formData;
  const metrics = [
    withMetricLabel(barLeftPct, 'Bar Left Pct'),
    withMetricLabel(barWidthPct, 'Bar Width Pct'),
    withMetricLabel(medianPct, 'Median Pct'),
    withMetricLabel(targetPct, 'Target Pct'),
    withMetricLabel(actualPct, 'Actual Pct'),
    withMetricLabel(marginLowF, 'Margin Low F'),
    withMetricLabel(marginHighF, 'Margin High F'),
    withMetricLabel(marginMedianF, 'Margin Median F'),
    withMetricLabel(marginTargetF, 'Margin Target F'),
    withMetricLabel(marginActualF, 'Margin Actual F'),
    withMetricLabel(gapMetric, 'Gap'),
    withMetricLabel(q1Metric, 'IQR Lower'),
    withMetricLabel(q3Metric, 'IQR Upper'),
    withMetricLabel(medianMetric, 'Median'),
    withMetricLabel(targetMetric, 'Target'),
    withMetricLabel(actualMetric, 'Actual'),
  ]
    .filter((metric): metric is QueryFormMetric => Boolean(metric))
    .filter(
      (metric, index, allMetrics) =>
        allMetrics.findIndex(
          candidate => JSON.stringify(candidate) === JSON.stringify(metric),
        ) === index,
    );
  const filterColumns = showFilterControls
    ? [
        withColumnLabel(periodFilter, 'Period'),
        withColumnLabel(entityTypeFilter, 'Entity Type'),
        withColumnLabel(regionFilter, 'Region'),
        withColumnLabel(countryFilter, 'Country'),
        withColumnLabel(entityFilter, 'Entity'),
        withColumnLabel(functionFilter, 'Function'),
        withColumnLabel(profitCenterFilter, 'Profit Center'),
      ].filter((column): column is QueryFormColumn => isSelectedColumn(column))
    : [];
  const groupbyColumns = [
    ...ensureIsArray(groupby).map(column =>
      withColumnLabel(column, 'Profit Center'),
    ),
    ...filterColumns,
  ].filter((column): column is QueryFormColumn => Boolean(column));
  const dedupedGroupby = Array.from(
    new Map(
      groupbyColumns.map(column => [JSON.stringify(column), column]),
    ).values(),
  );

  return buildQueryContext(formData, baseQueryObject => [
    {
      ...baseQueryObject,
      groupby: dedupedGroupby,
      metrics,
    },
  ]);
}
