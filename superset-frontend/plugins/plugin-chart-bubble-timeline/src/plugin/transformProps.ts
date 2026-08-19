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
  Bubble,
  BubbleTimelineChartProps,
  BubbleTimelineTransformedProps,
} from '../types';

export default function transformProps(
  chartProps: BubbleTimelineChartProps,
): BubbleTimelineTransformedProps {
  const { width, height, formData, queriesData } = chartProps;
  const {
    x,
    y,
    size,
    entity,
    series,
    timeColumn,
    maxBubbleSize,
    autoPlay,
    showPeriodLabel,
    chartMargin,
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
  const sizeLabel = getMetricLabel(size as never);

  // Temporal columns often arrive as epoch milliseconds. Decide by the whole
  // series (max abs >= 1e11) rather than per-value, because years near 1970
  // have tiny/negative epochs that a per-value threshold would misclassify.
  const rawPeriods = rows.map(row => row[timeColumn]);
  const isEpoch = rawPeriods.some(
    v => typeof v === 'number' && Math.abs(v) >= 1e11,
  );
  const formatPeriod = (v: unknown): string => {
    if (isEpoch && typeof v === 'number') {
      return String(new Date(v).getUTCFullYear());
    }
    return String(v ?? '');
  };

  const bubblesByPeriod: Record<string, Bubble[]> = {};
  const categorySet = new Set<string>();
  let maxSize = 0;

  rows.forEach(row => {
    const bx = Number(row[xLabel]);
    const by = Number(row[yLabel]);
    const bsize = Number(row[sizeLabel]);
    if (!Number.isFinite(bx) || !Number.isFinite(by)) return;
    const period = formatPeriod(row[timeColumn]);
    const category = series ? String(row[series] ?? '') : 'All';
    categorySet.add(category);
    const safeSize = Number.isFinite(bsize) ? bsize : 0;
    if (safeSize > maxSize) maxSize = safeSize;
    const bubble: Bubble = {
      x: bx,
      y: by,
      size: safeSize,
      name: entity ? String(row[entity] ?? '') : '',
      category,
    };
    (bubblesByPeriod[period] ??= []).push(bubble);
  });

  const periods = Object.keys(bubblesByPeriod).sort((a, b) => {
    const na = Number(a);
    const nb = Number(b);
    if (Number.isFinite(na) && Number.isFinite(nb)) return na - nb;
    return a.localeCompare(b);
  });

  return {
    width,
    height,
    periods,
    bubblesByPeriod,
    categories: Array.from(categorySet),
    maxSize: maxSize || 1,
    maxBubbleSize: Number(maxBubbleSize) || 60,
    autoPlay: autoPlay !== false,
    showPeriodLabel: showPeriodLabel !== false,
    chartMargin: Number(chartMargin) || 0,
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
