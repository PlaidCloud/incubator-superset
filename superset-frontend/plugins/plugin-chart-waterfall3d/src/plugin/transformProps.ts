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
  CurrencyFormatter,
  getColumnLabel,
  getMetricLabel,
  getNumberFormatter,
  RgbaColor,
} from '@superset-ui/core';
import {
  BarType,
  Waterfall3DChartProps,
  Waterfall3DTransformedProps,
  WaterfallBar,
  WaterfallLane,
} from '../types';

const toHex = (c?: RgbaColor) =>
  c ? (c.r << 16) + (c.g << 8) + c.b : 0x888888;

const toRgba = (c: RgbaColor | undefined, fallback: string) =>
  c ? `rgba(${c.r},${c.g},${c.b},${c.a ?? 1})` : fallback;

export default function transformProps(
  chartProps: Waterfall3DChartProps,
): Waterfall3DTransformedProps {
  const { width, height, formData, queriesData } = chartProps;
  const {
    stepColumn,
    seriesColumn,
    metric,
    tooltip_column: tooltipColumn,
    showTotal = true,
    totalLabel = 'Total',
    showConnectors = true,
    stickWidth = 12,
    show_value: showValue = false,
    useFirstValueAsSubtotal = false,
    bold_labels: boldMode = 'both',
    show_legend: showLegend = false,
    increaseColor = { r: 34, g: 197, b: 94, a: 1 },
    decreaseColor = { r: 239, g: 68, b: 68, a: 1 },
    totalColor = { r: 59, g: 130, b: 246, a: 1 },
    subtotalColor = { r: 139, g: 92, b: 246, a: 1 },
    labelColor,
    autoRotate = false,
    valueFormat = 'SMART_NUMBER',
    currency_format: currencyFormat,
    xAxisLabel,
    yAxisLabel,
    zAxisLabel,
  } = formData;

  const data = (queriesData[0]?.data ?? []) as Record<string, any>[];
  const stepLabel = getColumnLabel(stepColumn);
  const seriesLabel = getColumnLabel(seriesColumn);
  const mLabel = getMetricLabel(metric);
  const tipColumnLabel = tooltipColumn ? getColumnLabel(tooltipColumn) : '';

  const numFmt = getNumberFormatter(valueFormat);
  const curFmt = currencyFormat?.symbol
    ? new CurrencyFormatter({ d3Format: valueFormat, currency: currencyFormat })
    : null;
  const fmt = (v: number) => (curFmt ? curFmt.format(v) : numFmt(v));

  // First-seen step order (shared X positions) and series categories (depth).
  const stepOrder: string[] = [];
  const stepSeen = new Set<string>();
  const seriesCats: string[] = [];
  const catSeen = new Set<string>();
  const agg = new Map<string, Map<string, number>>();
  const tipByCell: Record<string, string> = {};
  const cellKey = (cat: string, step: string) => `${cat} ${step}`;

  data.forEach(row => {
    const step = String(row[stepLabel] ?? '');
    const cat = String(row[seriesLabel] ?? '');
    if (!stepSeen.has(step)) {
      stepSeen.add(step);
      stepOrder.push(step);
    }
    if (!catSeen.has(cat)) {
      catSeen.add(cat);
      seriesCats.push(cat);
    }
    if (!agg.has(cat)) agg.set(cat, new Map());
    agg
      .get(cat)!
      .set(step, (agg.get(cat)!.get(step) ?? 0) + (Number(row[mLabel]) || 0));
    if (tipColumnLabel) {
      tipByCell[cellKey(cat, step)] = String(row[tipColumnLabel] ?? '');
    }
  });

  let minVal = 0;
  let maxVal = 0;
  const lanes: WaterfallLane[] = seriesCats.map(cat => {
    const byStep = agg.get(cat)!;
    const bars: WaterfallBar[] = [];
    let running = 0;
    let first = true;
    stepOrder.forEach(step => {
      if (!byStep.has(step)) return;
      const value = byStep.get(step)!;
      const isSubtotal = useFirstValueAsSubtotal && first;
      let base: number;
      let top: number;
      if (isSubtotal) {
        running += value;
        base = 0;
        top = running;
      } else {
        base = running;
        running += value;
        top = running;
      }
      first = false;
      const type: BarType = isSubtotal
        ? 'subtotal'
        : value >= 0
          ? 'positive'
          : 'negative';
      bars.push({ step, value, running, type, base, top });
      minVal = Math.min(minVal, base, top);
      maxVal = Math.max(maxVal, base, top);
    });
    if (showTotal && bars.length) {
      bars.push({
        step: totalLabel,
        value: running,
        running,
        type: 'total',
        base: 0,
        top: running,
      });
      minVal = Math.min(minVal, 0, running);
      maxVal = Math.max(maxVal, 0, running);
    }
    return { cat, bars };
  });

  return {
    formData,
    width,
    height,
    refs: {},
    lanes,
    stepOrder: showTotal ? [...stepOrder, totalLabel] : [...stepOrder],
    totalLabel,
    colors: {
      positive: toHex(increaseColor),
      negative: toHex(decreaseColor),
      total: toHex(totalColor),
      subtotal: toHex(subtotalColor),
    },
    // Empty means "unset" — the renderer then falls back to the theme's text
    // color, which a hard-coded default could not do.
    labelColor: toRgba(labelColor, ''),
    showValue: Boolean(showValue),
    boldMode: String(boldMode),
    showLegend: Boolean(showLegend),
    showConnectors: Boolean(showConnectors),
    barWidth: stickWidth,
    autoRotate: Boolean(autoRotate),
    fmt,
    axisLabels: {
      x: xAxisLabel || stepLabel,
      y: zAxisLabel || mLabel,
      z: yAxisLabel || seriesLabel,
    },
    minVal,
    maxVal,
    tipColumnLabel,
    tipByCell,
  };
}
