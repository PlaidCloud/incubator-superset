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
  getColumnLabel,
  getMetricLabel,
  getNumberFormatter,
  rgbToHex,
} from '@superset-ui/core';
import {
  Waterfall3DChartProps,
  Waterfall3DTransformedProps,
  WaterfallStep,
} from '../types';

const hex = (c: { r: number; g: number; b: number }) => rgbToHex(c.r, c.g, c.b);

export default function transformProps(
  chartProps: Waterfall3DChartProps,
): Waterfall3DTransformedProps {
  const { width, height, formData, queriesData } = chartProps;
  const {
    stepColumn,
    seriesColumn,
    metric,
    showTotal = true,
    totalLabel = 'Total',
    showConnectors = true,
    stickWidth = 10,
    increaseColor = { r: 90, g: 193, b: 137, a: 1 },
    decreaseColor = { r: 224, g: 67, b: 85, a: 1 },
    totalColor = { r: 102, g: 102, b: 102, a: 1 },
    autoRotate = false,
    valueFormat = 'SMART_NUMBER',
    xAxisLabel,
    yAxisLabel,
    zAxisLabel,
    xAxisNameGap = 25,
    yAxisNameGap = 25,
  } = formData;

  const data = (queriesData[0]?.data ?? []) as Record<string, any>[];
  const stepLabel = getColumnLabel(stepColumn);
  const seriesLabel = getColumnLabel(seriesColumn);
  const mLabel = getMetricLabel(metric);
  const fmt = getNumberFormatter(valueFormat);

  const incHex = hex(increaseColor);
  const decHex = hex(decreaseColor);
  const totHex = hex(totalColor);

  // Global ordered list of step labels (first-seen) shared by all series, so
  // every waterfall lines up on the same X positions.
  const stepOrder: string[] = [];
  const stepSeen = new Set<string>();
  // Series categories (depth axis), first-seen order.
  const seriesCats: string[] = [];
  const catSeen = new Set<string>();
  // Aggregate metric per (category, step).
  const agg = new Map<string, Map<string, number>>();

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
    const byStep = agg.get(cat)!;
    byStep.set(step, (byStep.get(step) ?? 0) + (Number(row[mLabel]) || 0));
  });

  // X axis labels: the bridge steps, plus an optional trailing Total.
  const axisSteps = showTotal ? [...stepOrder, totalLabel] : [...stepOrder];
  const stepIndex = new Map<string, number>(
    axisSteps.map((s, i) => [s, i]),
  );

  // Build per-category waterfall steps (running totals → floating bars).
  const stepsByCat = new Map<string, WaterfallStep[]>();
  let minZ = 0;
  let maxZ = 0;
  seriesCats.forEach(cat => {
    const byStep = agg.get(cat)!;
    const steps: WaterfallStep[] = [];
    let total = 0;
    stepOrder.forEach(step => {
      if (!byStep.has(step)) return;
      const value = byStep.get(step)!;
      const base = total;
      total += value;
      steps.push({ step, base, top: total, value, isTotal: false });
      minZ = Math.min(minZ, base, total);
      maxZ = Math.max(maxZ, base, total);
    });
    if (showTotal) {
      steps.push({
        step: totalLabel,
        base: 0,
        top: total,
        value: total,
        isTotal: true,
      });
      minZ = Math.min(minZ, 0, total);
      maxZ = Math.max(maxZ, 0, total);
    }
    stepsByCat.set(cat, steps);
  });

  const series: any[] = [];
  // Markers at each bar top double as reliable hover targets for the tooltip,
  // since the thin line3D sticks are hard to hover directly.
  const caps: any[] = [];
  seriesCats.forEach((cat, j) => {
    const steps = stepsByCat.get(cat)!;
    let prevXi: number | null = null;
    let prevTop: number | null = null;
    steps.forEach(s => {
      const xi = stepIndex.get(s.step)!;
      const color = s.isTotal ? totHex : s.value >= 0 ? incHex : decHex;

      // Connector from the previous step's top across to this step.
      if (showConnectors && prevXi !== null && prevTop !== null) {
        series.push({
          type: 'line3D',
          name: '',
          silent: true,
          data: [
            [prevXi, j, prevTop],
            [xi, j, prevTop],
          ],
          lineStyle: { width: 1, color: totHex, opacity: 0.5 },
        });
      }

      // The floating bar itself (a thick vertical stick from base to top).
      const label = [
        `${cat} · ${s.step}`,
        `${s.isTotal ? 'Total' : s.value >= 0 ? 'Increase' : 'Decrease'}: ${fmt(s.value)}`,
        `Running total: ${fmt(s.top)}`,
      ].join('<br/>');
      series.push({
        type: 'line3D',
        name: label,
        data: [
          [xi, j, s.base],
          [xi, j, s.top],
        ],
        lineStyle: { width: stickWidth, color },
      });
      caps.push({ value: [xi, j, s.top], label, itemStyle: { color } });

      prevXi = xi;
      prevTop = s.top;
    });
  });

  series.push({
    type: 'scatter3D',
    name: 'caps',
    symbolSize: Math.max(6, stickWidth + 2),
    data: caps,
  });

  const zName = zAxisLabel || mLabel;
  const nCats = seriesCats.length;
  const pad = (maxZ - minZ) * 0.05 || 1;

  const echartOptions: any = {
    tooltip: {
      formatter: (params: any) =>
        params?.data?.label || params?.seriesName || '',
    },
    xAxis3D: {
      type: 'value',
      name: xAxisLabel || stepLabel,
      min: -0.5,
      max: axisSteps.length - 0.5,
      interval: 1,
      nameGap: xAxisNameGap,
      axisLabel: {
        formatter: (v: number) => axisSteps[Math.round(v)] ?? '',
      },
    },
    yAxis3D: {
      type: 'value',
      name: yAxisLabel || seriesLabel,
      min: 0,
      max: Math.max(0, nCats - 1),
      interval: 1,
      nameGap: yAxisNameGap,
      axisLabel: {
        formatter: (v: number) => seriesCats[Math.round(v)] ?? '',
      },
    },
    zAxis3D: {
      type: 'value',
      name: zName,
      min: minZ - pad,
      max: maxZ + pad,
      axisLabel: { formatter: (v: number) => fmt(v) },
    },
    grid3D: {
      boxWidth: 120,
      boxDepth: 80,
      viewControl: { autoRotate, projection: 'perspective' },
      light: {
        main: { intensity: 1.2, shadow: true },
        ambient: { intensity: 0.3 },
      },
    },
    series,
  };

  return { echartOptions, formData, height, width, refs: {} };
}
