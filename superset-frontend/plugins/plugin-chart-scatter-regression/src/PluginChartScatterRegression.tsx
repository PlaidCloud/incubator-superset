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
import {
  CategoricalColorNamespace,
  getNumberFormatter,
} from '@superset-ui/core';
import { ScatterRegressionTransformedProps } from './types';
import { fitRegression, sampleCurve } from './regression';
import { buildLegend, padGridForLegend } from './legend';

const REG_COLOR =
  // eslint-disable-next-line theme-colors/no-literal-colors
  '#c0392b';

export default function PluginChartScatterRegression(
  props: ScatterRegressionTransformedProps,
) {
  const {
    width,
    height,
    points,
    seriesNames,
    regressionType,
    polynomialOrder,
    pointSize,
    showRegression,
    showEquation,
    logXAxis,
    logYAxis,
    numberFormat,
    colorScheme,
    xAxisLabel,
    yAxisLabel,
    showLegend,
    legendType,
    legendOrientation,
    legendMargin,
    showZoom,
    sliceId,
  } = props;

  const option = useMemo(() => {
    const formatter = getNumberFormatter(numberFormat);
    const colorFn = CategoricalColorNamespace.getScale(colorScheme);

    const scatterSeries = seriesNames.map(name => ({
      name,
      type: 'scatter' as const,
      symbolSize: pointSize,
      itemStyle: { color: colorFn(name, sliceId), opacity: 0.8 },
      data: points.filter(p => p.series === name).map(p => [p.x, p.y, p.name]),
      emphasis: { focus: 'series' },
    }));

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const regSeries: any[] = [];
    let eqText = '';
    if (showRegression && points.length >= 2) {
      const fit = fitRegression(
        points.map(p => [p.x, p.y] as [number, number]),
        regressionType,
        polynomialOrder,
      );
      if (fit) {
        const xs = points.map(p => p.x);
        const curve = sampleCurve(fit, Math.min(...xs), Math.max(...xs));
        regSeries.push({
          name: 'Regression',
          type: 'line',
          showSymbol: false,
          smooth: regressionType !== 'linear',
          lineStyle: {
            width: 2.5,
            color: REG_COLOR,
            type: regressionType === 'linear' ? 'solid' : 'dashed',
          },
          data: curve,
          tooltip: { show: false },
          silent: true,
          z: 5,
        });
        eqText = `${fit.equation}   (R² = ${fit.r2.toFixed(3)})`;
      }
    }

    const legendOn = showLegend && seriesNames.length > 1;
    const legendOpts = {
      show: legendOn,
      type: legendType,
      orientation: legendOrientation,
      margin: legendMargin,
    };
    const baseGrid = { left: 56, right: 24, top: 24, bottom: 56 };

    // Zoom: scroll/drag on both axes (filterMode 'none' keeps points visible),
    // plus a toolbox with box-zoom, restore and save-as-image.
    const zoomExtras = showZoom
      ? {
          toolbox: {
            right: 12,
            top: 4,
            itemSize: 13,
            feature: {
              dataZoom: { yAxisIndex: 'all' },
              restore: {},
              saveAsImage: {},
            },
          },
          dataZoom: [
            { type: 'inside', xAxisIndex: 0, filterMode: 'none' },
            { type: 'inside', yAxisIndex: 0, filterMode: 'none' },
          ],
        }
      : {};

    return {
      ...zoomExtras,
      grid: padGridForLegend(legendOpts, baseGrid),
      legend: legendOn ? buildLegend(legendOpts, seriesNames) : { show: false },
      tooltip: {
        trigger: 'item',
        confine: true,
        formatter: (p: {
          seriesName: string;
          value: [number, number, string];
        }) => {
          const [vx, vy, nm] = p.value;
          const head = nm ? `<b>${nm}</b><br/>` : '';
          return `${head}${p.seriesName}<br/>${xAxisLabel}: ${formatter(
            vx,
          )}<br/>${yAxisLabel}: ${formatter(vy)}`;
        },
      },
      xAxis: {
        type: logXAxis ? 'log' : 'value',
        name: xAxisLabel,
        nameLocation: 'middle',
        nameGap: 30,
        scale: true,
        axisLabel: { formatter: (v: number) => formatter(v) },
      },
      yAxis: {
        type: logYAxis ? 'log' : 'value',
        name: yAxisLabel,
        nameLocation: 'middle',
        nameGap: 42,
        scale: true,
        axisLabel: { formatter: (v: number) => formatter(v) },
      },
      graphic:
        showEquation && eqText
          ? [
              {
                type: 'text',
                left: 64,
                top: 8,
                style: {
                  text: eqText,
                  fill: REG_COLOR,
                  fontSize: 12,
                  fontWeight: 'bold',
                },
                z: 10,
              },
            ]
          : [],
      series: [...scatterSeries, ...regSeries],
    };
  }, [
    points,
    seriesNames,
    regressionType,
    polynomialOrder,
    pointSize,
    showRegression,
    showEquation,
    logXAxis,
    logYAxis,
    numberFormat,
    colorScheme,
    xAxisLabel,
    yAxisLabel,
    showLegend,
    legendType,
    legendOrientation,
    legendMargin,
    showZoom,
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
