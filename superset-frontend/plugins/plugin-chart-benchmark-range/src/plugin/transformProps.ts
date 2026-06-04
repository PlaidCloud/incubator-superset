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

const AUTO_KEYS = {
  actual: [
    'actual',
    'actual value',
    'actual %',
    'actual pct',
    'actual_pct',
    'ebitxpretax pct',
    'value',
  ],
  actualPct: ['actual_pct'],
  barLeft: ['bar_left_pct'],
  barWidth: ['bar_width_pct'],
  median: ['median', 'median pct', 'median_pct', 'p50', '50th percentile'],
  q1: [
    'iqr lower',
    'margin low',
    'margin_low',
    'q1',
    'lower quartile',
    'p25',
    '25th percentile',
    'tp margin low',
    'tp margin - low',
  ],
  q3: [
    'iqr upper',
    'margin high',
    'margin_high',
    'q3',
    'upper quartile',
    'p75',
    '75th percentile',
    'tp margin high',
    'tp margin - high',
  ],
  target: [
    'target',
    'target value',
    'target %',
    'target pct',
    'target_pct',
    'tp margin target',
    'tp margin - target',
  ],
  targetPct: ['target_pct'],
};

const FORMATTED_KEYS = {
  actual: ['margin_actual_f'],
  gap: ['gap_formatted'],
  gapColor: ['gap_color'],
  high: ['margin_high_f'],
  low: ['margin_low_f'],
  median: ['margin_median_f'],
  target: ['margin_target_f'],
};

const POSITION_ALIAS_KEYS = [
  'actual_pct',
  'bar_left_pct',
  'median_pct',
  'target_pct',
];

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

function parseFormattedPercent(value: unknown): number | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const parsed = Number(value.replace(/[▲▼+,%\s]/g, ''));
  return Number.isFinite(parsed) ? parsed / 100 : undefined;
}

function isPositionAlias(key: string) {
  const normalizedAliases = POSITION_ALIAS_KEYS.map(normalizeKey);
  return normalizedAliases.includes(normalizeKey(key));
}

function pctPositionToMargin(value: number) {
  return value / 250 - 0.2;
}

function getMarginValue(row: Record<string, any>, key: string) {
  const value = toNumber(row[key]);
  if (value === undefined) {
    return undefined;
  }
  return isPositionAlias(key) ? pctPositionToMargin(value) : value;
}

function getMetricKey(
  metric: unknown,
  keys: string[],
  candidates: string[],
) {
  return resolveKey(metric ? getMetricLabel(metric as any) : '', keys) ||
    resolveAutoKey(candidates, keys);
}

function getFilterColumns(
  configuredColumns: Array<{ column?: unknown; label: string }>,
  keys: string[],
) {
  const columns = configuredColumns
    .map(({ column, label }) => {
      const columnLabel = column ? getColumnLabel(column as any) : '';
      const key = resolveKey(columnLabel, keys);
      return key ? { key, label } : null;
    })
    .filter(Boolean) as BenchmarkRangeFilterColumn[];

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
    actualPct,
    barLeftPct,
    barWidthPct,
    countryFilter,
    entityFilter,
    entityTypeFilter,
    functionFilter,
    gapMetric,
    groupby: rawGroupby,
    marginActualF,
    marginHighF,
    marginLowF,
    marginMedianF,
    marginTargetF,
    medianMetric,
    medianPct,
    percentValueMode = PercentValueMode.Auto,
    periodFilter,
    profitCenterFilter,
    q1Metric,
    q3Metric,
    regionFilter,
    showFilterControls = true,
    showLegend = true,
    sortBy = BenchmarkRangeSortBy.Category,
    sortOrder = BenchmarkRangeSortOrder.Asc,
    targetMetric,
    targetPct,
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
  const medianKey =
    resolveKey(medianPct ? getMetricLabel(medianPct) : '', keys) ||
    getMetricKey(medianMetric, keys, AUTO_KEYS.median);
  const targetKey =
    resolveKey(targetPct ? getMetricLabel(targetPct) : '', keys) ||
    getMetricKey(targetMetric, keys, AUTO_KEYS.target);
  const actualKey =
    resolveKey(actualPct ? getMetricLabel(actualPct) : '', keys) ||
    getMetricKey(actualMetric, keys, AUTO_KEYS.actual);
  const barLeftKey =
    resolveKey(barLeftPct ? getMetricLabel(barLeftPct) : '', keys) ||
    resolveAutoKey(AUTO_KEYS.barLeft, keys);
  const barWidthKey =
    resolveKey(barWidthPct ? getMetricLabel(barWidthPct) : '', keys) ||
    resolveAutoKey(AUTO_KEYS.barWidth, keys);
  const formattedKeys = {
    actual:
      resolveKey(marginActualF ? getMetricLabel(marginActualF) : '', keys) ||
      resolveAutoKey(FORMATTED_KEYS.actual, keys),
    gap:
      resolveKey(gapMetric ? getMetricLabel(gapMetric) : '', keys) ||
      resolveAutoKey(FORMATTED_KEYS.gap, keys),
    gapColor: resolveAutoKey(FORMATTED_KEYS.gapColor, keys),
    high:
      resolveKey(marginHighF ? getMetricLabel(marginHighF) : '', keys) ||
      resolveAutoKey(FORMATTED_KEYS.high, keys),
    low:
      resolveKey(marginLowF ? getMetricLabel(marginLowF) : '', keys) ||
      resolveAutoKey(FORMATTED_KEYS.low, keys),
    median:
      resolveKey(marginMedianF ? getMetricLabel(marginMedianF) : '', keys) ||
      resolveAutoKey(FORMATTED_KEYS.median, keys),
    target:
      resolveKey(marginTargetF ? getMetricLabel(marginTargetF) : '', keys) ||
      resolveAutoKey(FORMATTED_KEYS.target, keys),
  };
  const filterColumns = getFilterColumns(
    [
      { column: periodFilter, label: 'Period' },
      { column: entityTypeFilter, label: 'Entity Type' },
      { column: regionFilter, label: 'Region' },
      { column: countryFilter, label: 'Country' },
      { column: entityFilter, label: 'Entity' },
      { column: functionFilter, label: 'Function' },
      { column: profitCenterFilter, label: 'Profit Center' },
    ],
    keys,
  );

  const records = rawData
    .map(row => {
      const category = String(row[dimensionKey] ?? '');
      const formattedActual = formattedKeys.actual
        ? String(row[formattedKeys.actual] ?? '')
        : undefined;
      const formattedHigh = formattedKeys.high
        ? String(row[formattedKeys.high] ?? '')
        : undefined;
      const formattedLow = formattedKeys.low
        ? String(row[formattedKeys.low] ?? '')
        : undefined;
      const formattedMedian = formattedKeys.median
        ? String(row[formattedKeys.median] ?? '')
        : undefined;
      const formattedTarget = formattedKeys.target
        ? String(row[formattedKeys.target] ?? '')
        : undefined;
      const actualFromFormatted = parseFormattedPercent(formattedActual);
      const highFromFormatted = parseFormattedPercent(formattedHigh);
      const lowFromFormatted = parseFormattedPercent(formattedLow);
      const medianFromFormatted = parseFormattedPercent(formattedMedian);
      const targetFromFormatted = parseFormattedPercent(formattedTarget);
      const filters = filterColumns.reduce<Record<string, string>>(
        (accumulator, column) => ({
          ...accumulator,
          [column.key]: String(row[column.key] ?? ''),
        }),
        {},
      );
      return {
        ...row,
        actual:
          actualFromFormatted ??
          (actualKey ? getMarginValue(row, actualKey) : undefined),
        category,
        filters,
        formatted: {
          actual: formattedActual,
          gap: formattedKeys.gap ? String(row[formattedKeys.gap] ?? '') : undefined,
          gapColor: formattedKeys.gapColor
            ? String(row[formattedKeys.gapColor] ?? '')
            : undefined,
          high: formattedHigh,
          low: formattedLow,
          median: formattedMedian,
          target: formattedTarget,
        },
        median:
          medianFromFormatted ??
          (medianKey ? getMarginValue(row, medianKey) : undefined),
        q1:
          lowFromFormatted ??
          (q1Key
            ? getMarginValue(row, q1Key)
            : barLeftKey
              ? getMarginValue(row, barLeftKey)
              : undefined),
        q3:
          highFromFormatted ??
          (q3Key
            ? getMarginValue(row, q3Key)
            : barLeftKey && barWidthKey
              ? pctPositionToMargin(
                  (toNumber(row[barLeftKey]) || 0) +
                    (toNumber(row[barWidthKey]) || 0),
                )
              : undefined),
        target:
          targetFromFormatted ??
          (targetKey ? getMarginValue(row, targetKey) : undefined),
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
