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
  ChartProps,
  ensureIsArray,
  getColumnLabel,
  getMetricLabel,
} from '@superset-ui/core';
import {
  BenchmarkRangeChartProps,
  BenchmarkRangeFilterColumn,
  BenchmarkRangeQueryFormData,
  BenchmarkRangeRecord,
  BenchmarkRangeSortBy,
  BenchmarkRangeSortOrder,
  PercentValueMode,
} from '../types';

const DEFAULT_FILTER_LABELS = [
  'Period',
  'Entity Type',
  'Region',
  'Country',
  'Entity',
  'Function',
  'Profit Center',
];

const AUTO_KEYS = {
  actual: ['actual', 'actual value', 'actual %', 'value'],
  median: ['median', 'p50', '50th percentile'],
  q1: ['iqr lower', 'q1', 'lower quartile', 'p25', '25th percentile'],
  q3: ['iqr upper', 'q3', 'upper quartile', 'p75', '75th percentile'],
  target: ['target', 'target value', 'target %'],
};

function resolveKey(label: string, keys: string[]) {
  if (!label) {
    return '';
  }
  if (keys.includes(label)) {
    return label;
  }
  const normalized = label.toLowerCase();
  return (
    keys.find(
      key =>
        key.toLowerCase() === normalized ||
        key.toLowerCase().includes(normalized) ||
        normalized.includes(key.toLowerCase()),
    ) || ''
  );
}

function normalizeKey(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function resolveAutoKey(candidates: string[], keys: string[]) {
  const normalizedCandidates = candidates.map(normalizeKey);
  return (
    keys.find(key => normalizedCandidates.includes(normalizeKey(key))) ||
    keys.find(key =>
      normalizedCandidates.some(candidate => normalizeKey(key).includes(candidate)),
    ) ||
    ''
  );
}

function toNumber(value: unknown): number | undefined {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === 'string') {
    const parsed = Number(value.replace(/[%,$\s]/g, ''));
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function getMetricKey(
  metric: unknown,
  keys: string[],
  candidates: string[],
) {
  return resolveKey(metric ? getMetricLabel(metric as any) : '', keys) ||
    resolveAutoKey(candidates, keys);
}

function getFilterColumns(keys: string[], dimensionKey: string) {
  const columns = DEFAULT_FILTER_LABELS.map(label => {
    const key = resolveKey(label, keys);
    return key ? { key, label } : null;
  }).filter(Boolean) as BenchmarkRangeFilterColumn[];

  if (dimensionKey && !columns.some(column => column.key === dimensionKey)) {
    columns.push({ key: dimensionKey, label: 'Profit Center' });
  }

  return columns.filter(
    (column, index, allColumns) =>
      allColumns.findIndex(candidate => candidate.key === column.key) === index,
  );
}

export default function transformProps(chartProps: ChartProps) {
  const {
    width,
    height,
    formData,
    queriesData,
    filterState,
    hooks,
  } = chartProps as BenchmarkRangeChartProps;
  const {
    actualMetric,
    groupby: rawGroupby,
    medianMetric,
    percentValueMode = PercentValueMode.Auto,
    q1Metric,
    q3Metric,
    showFilterControls = true,
    showLegend = true,
    sortBy = BenchmarkRangeSortBy.Category,
    sortOrder = BenchmarkRangeSortOrder.Asc,
    targetMetric,
    xAxisLabel = '% Value',
  } = formData as BenchmarkRangeQueryFormData;
  const groupby = ensureIsArray(rawGroupby);
  const rawData = queriesData?.[0]?.data || [];
  const keys = rawData.length ? Object.keys(rawData[0]) : [];
  const dimensionLabel = groupby[0] ? getColumnLabel(groupby[0]) : '';
  const dimensionKey =
    resolveKey(dimensionLabel, keys) ||
    resolveAutoKey(['profit center', 'profit centre', 'category'], keys) ||
    keys[0] ||
    '';
  const q1Key = getMetricKey(q1Metric, keys, AUTO_KEYS.q1);
  const q3Key = getMetricKey(q3Metric, keys, AUTO_KEYS.q3);
  const medianKey = getMetricKey(medianMetric, keys, AUTO_KEYS.median);
  const targetKey = getMetricKey(targetMetric, keys, AUTO_KEYS.target);
  const actualKey = getMetricKey(actualMetric, keys, AUTO_KEYS.actual);
  const filterColumns = getFilterColumns(keys, dimensionKey);

  const records = rawData
    .map(row => {
      const category = String(row[dimensionKey] ?? '');
      const filters = filterColumns.reduce<Record<string, string>>(
        (accumulator, column) => ({
          ...accumulator,
          [column.key]: String(row[column.key] ?? ''),
        }),
        {},
      );
      return {
        ...row,
        actual: actualKey ? toNumber(row[actualKey]) : undefined,
        category,
        filters,
        median: medianKey ? toNumber(row[medianKey]) : undefined,
        q1: q1Key ? toNumber(row[q1Key]) : undefined,
        q3: q3Key ? toNumber(row[q3Key]) : undefined,
        target: targetKey ? toNumber(row[targetKey]) : undefined,
      } as BenchmarkRangeRecord;
    })
    .filter(row => row.category);

  return {
    filterColumns,
    filterState,
    groupby,
    height,
    percentValueMode,
    records,
    sortBy,
    sortOrder,
    setDataMask: hooks?.setDataMask || (() => {}),
    showFilterControls,
    showLegend,
    width,
    xAxisLabel,
  };
}
