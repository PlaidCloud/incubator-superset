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

const DEFAULT_DROPDOWN_COLUMNS = [
  'Period',
  'Entity Type',
  'Region',
  'Country',
  'Entity',
  'Function',
  'Profit Center',
];

type BenchmarkRangeBuildFormData = QueryFormData & {
  actual_metric?: QueryFormMetric;
  groupby?: unknown;
  median_metric?: QueryFormMetric;
  q1_metric?: QueryFormMetric;
  q3_metric?: QueryFormMetric;
  target_metric?: QueryFormMetric;
};

export default function buildQuery(formData: BenchmarkRangeBuildFormData) {
  const {
    actual_metric: actualMetric,
    groupby,
    median_metric: medianMetric,
    q1_metric: q1Metric,
    q3_metric: q3Metric,
    target_metric: targetMetric,
  } = formData;
  const metrics = [
    q1Metric,
    q3Metric,
    medianMetric,
    targetMetric,
    actualMetric,
  ].filter((metric): metric is QueryFormMetric => Boolean(metric));

  return buildQueryContext(formData, baseQueryObject => [
    {
      ...baseQueryObject,
      groupby: Array.from(
        new Set<QueryFormColumn>([
          ...ensureIsArray(groupby),
          ...DEFAULT_DROPDOWN_COLUMNS,
        ]),
      ),
      metrics,
    },
  ]);
}
