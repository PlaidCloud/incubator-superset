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
  BarNegativeChartProps,
  BarNegativeSeries,
  BarNegativeTransformedProps,
} from '../types';

export default function transformProps(
  chartProps: BarNegativeChartProps,
): BarNegativeTransformedProps {
  const { width, height, formData, queriesData } = chartProps;
  const {
    dimension,
    metrics,
    positiveColor,
    negativeColor,
    showLabels,
    numberFormat,
    barCategoryLabel,
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

  const categories = rows.map(row => String(row[dimension] ?? ''));
  const series: BarNegativeSeries[] = metricLabels.map(label => ({
    name: label,
    values: rows.map(row => {
      const v = Number(row[label]);
      return Number.isFinite(v) ? v : 0;
    }),
  }));

  return {
    width,
    height,
    categories,
    series,
    positiveColor: positiveColor || '#2e7d32',
    negativeColor: negativeColor || '#c0392b',
    showLabels: showLabels !== false,
    numberFormat: numberFormat || 'SMART_NUMBER',
    barCategoryLabel: barCategoryLabel || '',
    colorScheme,
    showLegend,
    legendType: (legendType as 'scroll' | 'plain') || 'scroll',
    legendOrientation:
      (legendOrientation as 'top' | 'bottom' | 'left' | 'right') || 'top',
    legendMargin: legendMargin ?? null,
    sliceId,
  };
}
