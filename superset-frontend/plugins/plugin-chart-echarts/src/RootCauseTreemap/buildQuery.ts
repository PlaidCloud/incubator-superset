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
  DataRecordValue,
  ensureIsArray,
  QueryFormData,
  QueryFormMetric,
  QueryObjectFilterClause,
} from '@superset-ui/core';
import { getRootCauseTreemapHierarchy } from './types';

const ATTRIBUTE_FILTERS = [
  ['order_type_values', 'order_type'],
  ['cohort_values', 'cohort'],
  ['l3_customer_values', 'l3_customer'],
  ['product_distance_values', 'product_distance'],
  ['production_plant_values', 'production_plant'],
  ['product_group_ibp_group_2_values', 'product_group_ibp_group_2'],
  ['distribution_channel_values', 'channel'],
  ['kosher_non_kosher_values', 'kosher_non_kosher'],
  ['organic_non_organic_values', 'organic_non_organic'],
  ['non_gmo_indicator_values', 'non_gmo_indicator'],
  ['lactose_free_indicator_values', 'lactose_free_indicator'],
  ['branded_private_label_values', 'branded_private_label'],
] as const;

function uniqMetrics(metrics: QueryFormMetric[]) {
  const seen = new Set<string>();
  return metrics.filter(metric => {
    const key = typeof metric === 'string' ? metric : JSON.stringify(metric);
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function normalizeFilterValue(value: unknown): DataRecordValue {
  if (
    value &&
    typeof value === 'object' &&
    'value' in value &&
    (typeof value.value === 'string' ||
      typeof value.value === 'number' ||
      typeof value.value === 'boolean' ||
      value.value === null)
  ) {
    return value.value;
  }
  return value as DataRecordValue;
}

function getAttributeFilters(
  formData: QueryFormData,
): QueryObjectFilterClause[] {
  return ATTRIBUTE_FILTERS.flatMap(([controlName, column]) => {
    const values = ensureIsArray(formData[controlName])
      .map(normalizeFilterValue)
      .filter(value => value !== undefined && value !== '');
    if (!values.length) {
      return [];
    }
    return [
      {
        col: column,
        op: 'IN' as const,
        val: values,
      },
    ];
  });
}

export default function buildQuery(formData: QueryFormData) {
  const {
    columns = [],
    hierarchy_preset: hierarchyPreset,
    metric,
    secondary_metric: secondaryMetric,
    sort_by_metric: sortByMetric,
    tooltip_metrics: tooltipMetrics = [],
  } = formData as QueryFormData & {
    columns?: string[];
    hierarchy_preset?: string;
    secondary_metric?: QueryFormMetric;
    tooltip_metrics?: QueryFormMetric[];
  };
  const metrics = uniqMetrics(
    [metric, secondaryMetric, ...ensureIsArray(tooltipMetrics)].filter(
      Boolean,
    ) as QueryFormMetric[],
  );
  const attributeFilters = getAttributeFilters(formData);
  const hierarchyColumns = getRootCauseTreemapHierarchy({
    columns,
    hierarchyPreset,
  });

  return buildQueryContext(formData, baseQueryObject => [
    {
      ...baseQueryObject,
      groupby: hierarchyColumns,
      metrics,
      filters: [...ensureIsArray(baseQueryObject.filters), ...attributeFilters],
      ...(sortByMetric && metric && { orderby: [[metric, false]] }),
    },
  ]);
}
