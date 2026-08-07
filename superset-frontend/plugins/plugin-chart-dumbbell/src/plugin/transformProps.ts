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
import { getMetricLabel } from '@superset-ui/core';
import {
  DumbbellChartProps,
  DumbbellMetricSeries,
  DumbbellSort,
  DumbbellTransformedProps,
} from '../types';

export default function transformProps(
  chartProps: DumbbellChartProps,
): DumbbellTransformedProps {
  const { width, height, formData, queriesData } = chartProps;
  const {
    dimension,
    metrics,
    symbolSize,
    originSymbol,
    originColor,
    destinationSymbol,
    destinationColor,
    lineWidth,
    lineColor,
    lineArrow,
    showLabels,
    numberFormat,
    valueAxisLabel,
    sortBy,
    chartMargin,
    legendType,
    legendOrientation,
    legendMargin,
    sliceId,
  } = formData;

  // color_scheme arrives camelCased as `colorScheme` (known gotcha).
  const colorScheme =
    (formData as { colorScheme?: string }).colorScheme ??
    (formData as { color_scheme?: string }).color_scheme;

  // The `show_legend` control is camelCased to `showLegend` in form data.
  const showLegend =
    (formData as { showLegend?: boolean }).showLegend ??
    (formData as { show_legend?: boolean }).show_legend ??
    true;

  const rows = (queriesData?.[0]?.data ?? []) as Record<string, unknown>[];
  const metricLabels = ((metrics ?? []) as unknown[]).map(m =>
    getMetricLabel(m as never),
  );

  // Build one row-record per category with each metric's numeric value.
  const records = rows.map(row => {
    const values = metricLabels.map(label => {
      const v = Number(row[label]);
      return Number.isFinite(v) ? v : 0;
    });
    return { name: String(row[dimension] ?? ''), values };
  });

  const gap = (vals: number[]) =>
    vals.length ? Math.max(...vals) - Math.min(...vals) : 0;

  const order = (sortBy as DumbbellSort) || 'none';
  if (order === 'first') {
    records.sort((a, b) => (a.values[0] ?? 0) - (b.values[0] ?? 0));
  } else if (order === 'gap') {
    records.sort((a, b) => gap(a.values) - gap(b.values));
  }

  const categories = records.map(r => r.name);
  const series: DumbbellMetricSeries[] = metricLabels.map((label, mi) => ({
    name: label,
    values: records.map(r => r.values[mi]),
  }));

  return {
    width,
    height,
    categories,
    series,
    symbolSize: Number(symbolSize) || 14,
    originSymbol: originSymbol || 'circle',
    originColor: originColor || '',
    destinationSymbol: destinationSymbol || 'diamond',
    destinationColor: destinationColor || '',
    lineWidth: Number(lineWidth) || 4,
    lineColor: lineColor || '#bbbbbb',
    lineArrow: Boolean(lineArrow),
    showLabels: Boolean(showLabels),
    numberFormat: numberFormat || 'SMART_NUMBER',
    valueAxisLabel: valueAxisLabel || '',
    chartMargin: Number(chartMargin) || 0,
    colorScheme,
    showLegend,
    legendType: (legendType as 'scroll' | 'plain') || 'scroll',
    legendOrientation:
      (legendOrientation as 'top' | 'bottom' | 'left' | 'right') || 'top',
    legendMargin: legendMargin ?? null,
    sliceId,
  };
}
