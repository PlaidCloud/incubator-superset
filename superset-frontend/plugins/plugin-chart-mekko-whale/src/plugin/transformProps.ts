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
  getMetricLabel,
  getColumnLabel,
  rgbToHex,
} from '@superset-ui/core';
import { MekkoWhaleDataItem, PluginChartMekkoWhaleQueryFormData } from '../types';

export default function transformProps(chartProps: ChartProps) {
  const { width, height, formData, queriesData } = chartProps as ChartProps<PluginChartMekkoWhaleQueryFormData>;
  const {
    groupby,
    metric,
    secondary_metric,
    sortBy,
    sortOrder,
    positiveColor,
    negativeColor,
    xAxisFormat,
    yAxisFormat,
  } = formData;

  const rawData = (queriesData && queriesData[0] && queriesData[0].data) ? queriesData[0].data : [];

  // 1. Key Resolution
  const dimensionLabel = Array.isArray(groupby) ? getColumnLabel(groupby[0]) : getColumnLabel(groupby);
  const m1Label = metric ? getMetricLabel(metric) : '';
  const m2Label = secondary_metric ? getMetricLabel(secondary_metric) : '';

  const getActualKey = (target: string, allKeys: string[]) => {
    if (!target) return '';
    if (allKeys.includes(target)) return target;
    const lower = target.toLowerCase();
    return allKeys.find(k => k.toLowerCase() === lower || k.toLowerCase().includes(lower) || lower.includes(k.toLowerCase())) || '';
  };

  const allKeys = rawData.length > 0 ? Object.keys(rawData[0]) : [];
  const actualDimKey = getActualKey(dimensionLabel, allKeys) || (allKeys.length > 0 ? allKeys[0] : '');
  const remainingKeys = allKeys.filter(k => k !== actualDimKey);

  let actualM1Key = getActualKey(m1Label, remainingKeys);
  let actualM2Key = getActualKey(m2Label, remainingKeys);

  if (!actualM1Key && remainingKeys.length > 0) actualM1Key = remainingKeys[0];
  if (!actualM2Key && remainingKeys.length > 1) actualM2Key = remainingKeys[1];
  else if (!actualM2Key && remainingKeys.length === 1 && actualM1Key !== remainingKeys[0]) actualM2Key = remainingKeys[0];

  // 2. Sorting
  const sortedData = [...rawData].sort((a, b) => {
    const val1A = Number(a[actualM1Key]) || 0;
    const val1B = Number(b[actualM1Key]) || 0;
    const val2A = Number(a[actualM2Key]) || 0;
    const val2B = Number(b[actualM2Key]) || 0;

    let aSort = 0;
    let bSort = 0;
    if (sortBy === 'profit') {
      aSort = val1A;
      bSort = val1B;
    } else if (sortBy === 'revenue') {
      aSort = val2A;
      bSort = val2B;
    } else { // profit_margin
      aSort = val2A !== 0 ? val1A / val2A : 0;
      bSort = val2B !== 0 ? val1B / val2B : 0;
    }
    return sortOrder === 'ASC' ? aSort - bSort : bSort - aSort;
  });

  // 3. Accumulate
  const interpolateColor = (color1: string, color2: string, factor: number) => {
    const r1 = parseInt(color1.substring(1, 3), 16) || 0;
    const g1 = parseInt(color1.substring(3, 5), 16) || 0;
    const b1 = parseInt(color1.substring(5, 7), 16) || 0;
    const r2 = parseInt(color2.substring(1, 3), 16) || 0;
    const g2 = parseInt(color2.substring(3, 5), 16) || 0;
    const b2 = parseInt(color2.substring(5, 7), 16) || 0;
    const r = Math.round(r1 + factor * (r2 - r1));
    const g = Math.round(g1 + factor * (g2 - g1));
    const b = Math.round(b1 + factor * (b2 - b1));
    return `#${((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1)}`;
  };

  const posColor = positiveColor ? rgbToHex(positiveColor.r, positiveColor.g, positiveColor.b) : '#5ac189';
  const negColor = negativeColor ? rgbToHex(negativeColor.r, negativeColor.g, negativeColor.b) : '#e04355';

  let currentX = 0;
  let currentY = 0;
  let yMin = 0;
  let yMax = 0;

  const chartData: MekkoWhaleDataItem[] = sortedData.map((item, index) => {
    // Robust parsing for possible string numbers (currency, etc)
    const m1Val = typeof item[actualM1Key] === 'number' ?
      item[actualM1Key] as number :
      Number(String(item[actualM1Key] || 0).replace(/[$,]/g, '')) || 0;
    const m2Val = typeof item[actualM2Key] === 'number' ?
      item[actualM2Key] as number :
      Number(String(item[actualM2Key] || 0).replace(/[$,]/g, '')) || 0;

    const yStartVal = 0;
    const yEnd = currentY + m1Val;

    const xStart = currentX;
    const xEnd = currentX + m2Val;

    currentX = xEnd;
    currentY = yEnd;

    yMin = Math.min(yMin, yEnd);
    yMax = Math.max(yMax, yEnd);

    const factor = sortedData.length > 1 ? index / (sortedData.length - 1) : 0;
    const color = interpolateColor(posColor, negColor, factor);

    return {
      name: String(item[actualDimKey] || 'N/A'),
      value: [xStart, xEnd, yStartVal, yEnd, m1Val, m2Val],
      itemStyle: { color },
    };
  });

  return {
    width,
    height,
    data: chartData,
    xAxisLabel: m2Label || actualM2Key || 'Revenue',
    yAxisLabel: `Cumulative ${m1Label || actualM1Key || 'Profit'}`,
    xAxisFormat: xAxisFormat,
    yAxisFormat: yAxisFormat,
    yMin,
    yMax,
    xMax: currentX,
  };
}
