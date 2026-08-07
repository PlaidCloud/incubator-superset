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
import { useMemo } from 'react';
import ReactECharts from 'echarts-for-react';
import { CategoricalColorNamespace, getNumberFormatter } from '@superset-ui/core';
import { DumbbellTransformedProps } from './types';
import { buildLegend, padGridForLegend } from './legend';

export default function PluginChartDumbbell(props: DumbbellTransformedProps) {
  const {
    width,
    height,
    categories,
    series,
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
    chartMargin,
    colorScheme,
    showLegend,
    legendType,
    legendOrientation,
    legendMargin,
    sliceId,
  } = props;

  const option = useMemo(() => {
    const formatter = getNumberFormatter(numberFormat);
    const colorFn = CategoricalColorNamespace.getScale(colorScheme);
    const legendNames = series.map(s => s.name);
    const lastIdx = series.length - 1;

    const legendOn = showLegend && series.length > 1;
    const legendOpts = {
      show: legendOn,
      type: legendType,
      orientation: legendOrientation,
      margin: legendMargin,
    };

    // Connector: a line per category from origin (first metric) to
    // destination (last metric), with an optional directional arrowhead.
    const connectorSeries = {
      type: 'lines' as const,
      coordinateSystem: 'cartesian2d',
      silent: true,
      // Keep the bar behind the dots normally; lift it above so the
      // arrowhead stays visible when the directional arrow is enabled.
      z: lineArrow ? 4 : 2,
      symbol: lineArrow ? ['none', 'arrow'] : ['none', 'none'],
      symbolSize: lineArrow ? Math.max(12, lineWidth * 3) : 0,
      lineStyle: { color: lineColor, width: lineWidth, cap: 'round', opacity: 1 },
      data: categories.map((_, i) => ({
        coords: [
          [series[0].values[i], i],
          [series[lastIdx].values[i], i],
        ],
      })),
    };

    // Dots: one scatter series per metric. Origin (first) and destination
    // (last) get their own icon + color; middle metrics fall back to scheme.
    const dotSeries = series.map((s, mi) => {
      const isOrigin = mi === 0;
      const isDest = mi === lastIdx;
      const symbol = isOrigin
        ? originSymbol
        : isDest
          ? destinationSymbol
          : 'circle';
      const explicit = isOrigin ? originColor : isDest ? destinationColor : '';
      return {
        name: s.name,
        type: 'scatter' as const,
        symbol,
        symbolSize,
        z: 3,
        itemStyle: { color: explicit || colorFn(s.name, sliceId) },
        label: {
          show: showLabels,
          position: 'top',
          formatter: (p: { value: [number, number] }) => formatter(p.value[0]),
        },
        data: s.values.map((v, i) => [v, i]),
      };
    });

    return {
      grid: padGridForLegend(legendOpts, {
        left: 80 + chartMargin,
        right: 24 + chartMargin,
        top: 24 + chartMargin,
        bottom: 40 + chartMargin,
      }),
      legend: legendOn ? buildLegend(legendOpts, legendNames) : { show: false },
      tooltip: {
        trigger: 'item',
        confine: true,
        formatter: (p: {
          seriesName: string;
          value: [number, number];
          marker: string;
        }) => {
          const [val, idx] = p.value;
          return `${categories[idx]}<br/>${p.marker}${p.seriesName}: <b>${formatter(
            val,
          )}</b>`;
        },
      },
      xAxis: {
        type: 'value',
        name: valueAxisLabel,
        nameLocation: 'middle',
        nameGap: 28,
        axisLabel: { formatter: (v: number) => formatter(v) },
        splitLine: { lineStyle: { type: 'dashed' } },
      },
      yAxis: {
        type: 'category',
        data: categories,
        axisTick: { show: false },
      },
      series: [connectorSeries, ...dotSeries],
    };
  }, [
    categories,
    series,
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
    chartMargin,
    colorScheme,
    showLegend,
    legendType,
    legendOrientation,
    legendMargin,
    sliceId,
  ]);

  return (
    <ReactECharts
      option={option}
      notMerge
      lazyUpdate
      style={{ width, height }}
    />
  );
}
