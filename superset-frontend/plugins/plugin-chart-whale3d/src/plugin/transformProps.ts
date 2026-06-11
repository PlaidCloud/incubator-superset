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
  CategoricalColorNamespace,
  getColumnLabel,
  getMetricLabel,
  getNumberFormatter,
} from '@superset-ui/core';
import {
  Whale3DChartProps,
  Whale3DTransformedProps,
  Whale3DZMode,
  WhalePoint,
} from '../types';

const GRADIENT = [
  '#313695',
  '#4575b4',
  '#74add1',
  '#abd9e9',
  '#e0f3f8',
  '#ffffbf',
  '#fee090',
  '#fdae61',
  '#f46d43',
  '#d73027',
  '#a50026',
];

const PARETO_COLOR = '#FF6B6B';

/**
 * Build the cumulative whale curve for one series category: sort entities by
 * the metric descending, then accumulate. Returns points ordered by ascending
 * percentile, with a leading origin point so the curve starts at zero.
 */
function computeWhale(
  rows: Record<string, any>[],
  entityLabel: string,
  mLabel: string,
  zMode: Whale3DZMode,
): WhalePoint[] {
  const sorted = [...rows].sort(
    (a, b) => (Number(b[mLabel]) || 0) - (Number(a[mLabel]) || 0),
  );
  const total = sorted.reduce((s, r) => s + (Number(r[mLabel]) || 0), 0);
  const n = sorted.length;

  const points: WhalePoint[] = [
    { percentile: 0, z: 0, cumulative: 0, name: '' },
  ];
  let cumulative = 0;
  sorted.forEach((row, i) => {
    cumulative += Number(row[mLabel]) || 0;
    const percentile = ((i + 1) / n) * 100;
    const z =
      zMode === 'absolute'
        ? cumulative
        : total !== 0
          ? (cumulative / total) * 100
          : 0;
    points.push({
      percentile,
      z,
      cumulative,
      name: String(row[entityLabel] ?? ''),
    });
  });
  return points;
}

/**
 * Linearly interpolate the curve's z value at an arbitrary percentile, used to
 * resample irregular curves onto a common grid for the surface.
 */
function interpAt(curve: WhalePoint[], x: number): number {
  if (curve.length === 0) return 0;
  if (x <= curve[0].percentile) return curve[0].z;
  const last = curve[curve.length - 1];
  if (x >= last.percentile) return last.z;
  for (let i = 1; i < curve.length; i += 1) {
    if (x <= curve[i].percentile) {
      const a = curve[i - 1];
      const b = curve[i];
      const span = b.percentile - a.percentile || 1;
      const tt = (x - a.percentile) / span;
      return a.z + tt * (b.z - a.z);
    }
  }
  return last.z;
}

export default function transformProps(
  chartProps: Whale3DChartProps,
): Whale3DTransformedProps {
  const { width, height, formData, queriesData } = chartProps;
  const {
    entityColumn,
    seriesColumn,
    metric,
    displayMode = 'ribbons',
    zMode = 'percent',
    colorMode = 'gradient',
    color_scheme,
    showVisualMap = true,
    showPareto = false,
    fillCurves = false,
    fillOpacity = 0.7,
    autoRotate = false,
    gridResolution = 20,
    valueFormat = 'SMART_NUMBER',
    xAxisLabel,
    yAxisLabel,
    zAxisLabel,
    xAxisNameGap = 25,
    yAxisNameGap = 25,
  } = formData;

  const data = (queriesData[0]?.data ?? []) as Record<string, any>[];
  const entityLabel = getColumnLabel(entityColumn);
  const seriesLabel = getColumnLabel(seriesColumn);
  const mLabel = getMetricLabel(metric);
  const numberFormatter = getNumberFormatter(valueFormat);
  const percentFormatter = getNumberFormatter(',.1f');

  // Group rows by series category, preserving first-seen order for the depth
  // axis.
  const seriesCats: string[] = [];
  const groups = new Map<string, Record<string, any>[]>();
  data.forEach(row => {
    const cat = String(row[seriesLabel] ?? '');
    if (!groups.has(cat)) {
      groups.set(cat, []);
      seriesCats.push(cat);
    }
    groups.get(cat)!.push(row);
  });

  const curves = new Map<string, WhalePoint[]>();
  seriesCats.forEach(cat => {
    curves.set(cat, computeWhale(groups.get(cat)!, entityLabel, mLabel, zMode));
  });

  // Z range for the gradient visual map.
  let minZ = 0;
  let maxZ = 0;
  curves.forEach(curve =>
    curve.forEach(p => {
      if (p.z < minZ) minZ = p.z;
      if (p.z > maxZ) maxZ = p.z;
    }),
  );

  const isSurface = displayMode === 'surface';
  const byCategory = colorMode === 'category' && !isSurface;
  const colorFn = CategoricalColorNamespace.getScale(color_scheme as string);

  const zName = zAxisLabel || (zMode === 'percent' ? `${mLabel} (cum %)` : mLabel);
  const nCats = seriesCats.length;

  const series: any[] = [];

  if (isSurface) {
    // Resample every curve onto a shared percentile grid so the surface has a
    // regular lattice; iterate categories (Y) outer, percentile (X) inner.
    const steps = Math.max(2, Math.round(gridResolution));
    const gridXs: number[] = [];
    for (let i = 0; i <= steps; i += 1) gridXs.push((i / steps) * 100);

    const surfaceData: number[][] = [];
    seriesCats.forEach((cat, j) => {
      const curve = curves.get(cat)!;
      gridXs.forEach(gx => {
        surfaceData.push([gx, j, interpAt(curve, gx)]);
      });
    });

    series.push({
      type: 'surface',
      data: surfaceData,
      shading: 'color',
      wireframe: { show: nCats <= 12 },
    });
  } else {
    // One 3D line (ribbon) per category at its depth index.
    seriesCats.forEach((cat, j) => {
      const curve = curves.get(cat)!;
      series.push({
        type: 'line3D',
        name: cat,
        data: curve.map(p => [p.percentile, j, p.z]),
        lineStyle: {
          width: 4,
          ...(byCategory ? { color: colorFn(cat) } : {}),
        },
      });
    });

    if (fillCurves) {
      // Vertical "curtain" under each curve: a parametric surface where u runs
      // along the percentile axis and v scales the height from baseline (0) to
      // the curve. Keeps the curve at constant depth j while filling the area.
      const uStep = 100 / Math.max(2, Math.round(gridResolution));
      seriesCats.forEach((cat, j) => {
        const curve = curves.get(cat)!;
        series.push({
          type: 'surface',
          name: `fill (${cat})`,
          silent: true,
          parametric: true,
          wireframe: { show: false },
          itemStyle: {
            opacity: fillOpacity,
            ...(byCategory ? { color: colorFn(cat) } : {}),
          },
          ...(byCategory ? { shading: 'color' } : {}),
          parametricEquation: {
            u: { min: 0, max: 100, step: uStep },
            v: { min: 0, max: 1, step: 1 },
            x: (u: number) => u,
            y: () => j,
            z: (u: number, v: number) => v * interpAt(curve, u),
          },
        });
      });
    }

    if (showPareto) {
      // Classic 80/20 reference, replicated at each category depth.
      const pareto = [
        [0, 0],
        [20, 80],
        [100, 100],
      ];
      const paretoMax = zMode === 'absolute' ? maxZ : 100;
      seriesCats.forEach((cat, j) => {
        series.push({
          type: 'line3D',
          name: `80/20 (${cat})`,
          silent: true,
          data: pareto.map(([px, py]) => [px, j, (py / 100) * paretoMax]),
          lineStyle: { width: 1, color: PARETO_COLOR, opacity: 0.6 },
        });
      });
    }
  }

  // A value Y axis (rather than category) keeps line3D and surface consistent
  // and lets the surface interpolate between adjacent categories; labels map
  // the integer index back to the category name.
  const echartOptions: any = {
    tooltip: {
      formatter: (params: any) => {
        const value = params?.value;
        if (!value) return '';
        const [x, y, z] = value;
        const cat = seriesCats[Math.round(y)] ?? '';
        return [
          `${seriesLabel}: ${cat}`,
          `${xAxisLabel || 'Percentile'}: ${percentFormatter(x)}%`,
          `${zName}: ${numberFormatter(z)}`,
        ].join('<br/>');
      },
    },
    ...(byCategory
      ? {}
      : {
          visualMap: {
            show: showVisualMap,
            dimension: 2,
            min: minZ,
            max: maxZ || 1,
            inRange: { color: GRADIENT },
          },
        }),
    xAxis3D: {
      type: 'value',
      name: xAxisLabel || 'Percentile',
      min: 0,
      max: 100,
      nameGap: xAxisNameGap,
      axisLabel: { formatter: '{value}%' },
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
      axisLabel: {
        formatter: (v: number) =>
          zMode === 'percent' ? `${percentFormatter(v)}%` : numberFormatter(v),
      },
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
