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
import { Bar3DChartProps, Bar3DTransformedProps } from '../types';

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

export default function transformProps(
  chartProps: Bar3DChartProps,
): Bar3DTransformedProps {
  const { width, height, formData, queriesData } = chartProps;
  const {
    x_axis,
    y_axis,
    metric,
    colorMode = 'gradient',
    colorByAxis = 'x',
    color_scheme,
    showVisualMap = true,
    showLabel = false,
    autoRotate = false,
    yAxisFormat = 'SMART_NUMBER',
    xAxisLabel,
    yAxisLabel,
    zAxisLabel,
    xAxisNameGap = 25,
    yAxisNameGap = 25,
  } = formData;

  const data = (queriesData[0]?.data ?? []) as Record<string, any>[];
  const mLabel = getMetricLabel(metric);
  const numberFormatter = getNumberFormatter(yAxisFormat);

  // Resolve the X/Y dimension labels. `x_axis` is a reserved control name in
  // Superset and may be stripped from formData by standardized-control
  // processing, so fall back to the actual non-metric columns in the result.
  const sampleRow = data[0] ?? {};
  const dimKeys = Object.keys(sampleRow).filter(k => k !== mLabel);
  let xLabel = x_axis ? getColumnLabel(x_axis) : undefined;
  let yLabel = y_axis ? getColumnLabel(y_axis) : undefined;
  if (!xLabel || !(xLabel in sampleRow)) [xLabel] = dimKeys;
  if (!yLabel || !(yLabel in sampleRow)) yLabel = dimKeys[1] ?? dimKeys[0];
  xLabel = xLabel || '';
  yLabel = yLabel || '';

  // Build category axes preserving first-seen order of the query rows.
  const xCats: string[] = [];
  const yCats: string[] = [];
  const xSeen = new Set<string>();
  const ySeen = new Set<string>();
  data.forEach(row => {
    const xv = String(row[xLabel]);
    const yv = String(row[yLabel]);
    if (!xSeen.has(xv)) {
      xSeen.add(xv);
      xCats.push(xv);
    }
    if (!ySeen.has(yv)) {
      ySeen.add(yv);
      yCats.push(yv);
    }
  });

  const byCategory = colorMode === 'category';
  const colorFn = CategoricalColorNamespace.getScale(color_scheme as string);

  const seriesData = data.map(row => {
    const item: { value: (number | string)[]; itemStyle?: { color: string } } =
      {
        value: [
          xCats.indexOf(String(row[xLabel])),
          yCats.indexOf(String(row[yLabel])),
          Number(row[mLabel]) || 0,
        ],
      };
    if (byCategory) {
      const categoryValue = String(
        colorByAxis === 'y' ? row[yLabel] : row[xLabel],
      );
      item.itemStyle = { color: colorFn(categoryValue) };
    }
    return item;
  });

  const values = data.map(row => Number(row[mLabel]) || 0);
  const maxV = values.length ? Math.max(...values) : 1;
  const minV = values.length ? Math.min(...values) : 0;

  const echartOptions: any = {
    tooltip: {
      formatter: (params: any) => {
        const [xi, yi, v] = params.value;
        return [
          `${xLabel}: ${xCats[xi]}`,
          `${yLabel}: ${yCats[yi]}`,
          `${mLabel}: ${numberFormatter(v)}`,
        ].join('<br/>');
      },
    },
    // Gradient-by-value coloring; omitted in category mode so per-bar
    // itemStyle colors from the color scheme take effect.
    ...(byCategory
      ? {}
      : {
          visualMap: {
            show: showVisualMap,
            dimension: 2,
            min: minV,
            max: maxV,
            inRange: { color: GRADIENT },
          },
        }),
    xAxis3D: {
      type: 'category',
      data: xCats,
      name: xAxisLabel || xLabel,
      nameGap: xAxisNameGap,
    },
    yAxis3D: {
      type: 'category',
      data: yCats,
      name: yAxisLabel || yLabel,
      nameGap: yAxisNameGap,
    },
    zAxis3D: { type: 'value', name: zAxisLabel || mLabel },
    grid3D: {
      boxWidth: 100,
      boxDepth: 100,
      viewControl: { autoRotate, projection: 'perspective' },
      light: {
        main: { intensity: 1.2, shadow: true },
        ambient: { intensity: 0.3 },
      },
    },
    series: [
      {
        type: 'bar3D',
        data: seriesData,
        shading: 'lambert',
        label: {
          show: showLabel,
          formatter: (params: any) => numberFormatter(params.value[2]),
        },
        emphasis: { label: { show: false } },
      },
    ],
  };

  return { echartOptions, formData, height, width, refs: {} };
}
