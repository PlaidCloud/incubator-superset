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
  ScatterPoint,
  ScatterRegressionChartProps,
  ScatterRegressionTransformedProps,
} from '../types';
import { RegressionType } from '../regression';

export default function transformProps(
  chartProps: ScatterRegressionChartProps,
): ScatterRegressionTransformedProps {
  const { width, height, formData, queriesData } = chartProps;
  const {
    x,
    y,
    entity,
    series,
    regressionType,
    polynomialOrder,
    pointSize,
    showRegression,
    showEquation,
    logXAxis,
    logYAxis,
    numberFormat,
    xAxisLabel,
    yAxisLabel,
    legendType,
    legendOrientation,
    legendMargin,
    showZoom,
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
  const xLabel = getMetricLabel(x as never);
  const yLabel = getMetricLabel(y as never);

  const points: ScatterPoint[] = rows
    .map(row => ({
      x: Number(row[xLabel]),
      y: Number(row[yLabel]),
      name: entity ? String(row[entity as string] ?? '') : '',
      series: series ? String(row[series as string] ?? '') : 'All',
    }))
    .filter(p => Number.isFinite(p.x) && Number.isFinite(p.y));

  const seriesNames = Array.from(new Set(points.map(p => p.series)));

  return {
    width,
    height,
    points,
    seriesNames,
    regressionType: (regressionType as RegressionType) || 'linear',
    polynomialOrder: Number(polynomialOrder) || 2,
    pointSize: Number(pointSize) || 10,
    showRegression: showRegression !== false,
    showEquation: showEquation !== false,
    logXAxis: Boolean(logXAxis),
    logYAxis: Boolean(logYAxis),
    numberFormat: numberFormat || 'SMART_NUMBER',
    colorScheme,
    xAxisLabel: xAxisLabel || xLabel,
    yAxisLabel: yAxisLabel || yLabel,
    showLegend,
    legendType: (legendType as 'scroll' | 'plain') || 'scroll',
    legendOrientation:
      (legendOrientation as 'top' | 'bottom' | 'left' | 'right') || 'top',
    legendMargin: legendMargin ?? null,
    showZoom: showZoom !== false,
    sliceId,
  };
}
