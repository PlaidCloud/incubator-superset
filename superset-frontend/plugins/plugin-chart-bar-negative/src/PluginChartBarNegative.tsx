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
import { BarNegativeTransformedProps } from './types';
import { buildLegend, padGridForLegend } from './legend';

export default function PluginChartBarNegative(
  props: BarNegativeTransformedProps,
) {
  const {
    width,
    height,
    categories,
    series,
    positiveColor,
    negativeColor,
    showLabels,
    numberFormat,
    barCategoryLabel,
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
    const single = series.length <= 1;

    // Single metric: keep the classic look — sort categories by value and
    // color each bar by its sign. Multiple metrics: preserve order and color
    // each series by the color scheme (legend distinguishes them).
    let cats = categories;
    let ser = series;
    if (single && series.length === 1) {
      const order = categories
        .map((_, i) => i)
        .sort((a, b) => series[0].values[a] - series[0].values[b]);
      cats = order.map(i => categories[i]);
      ser = [{ name: series[0].name, values: order.map(i => series[0].values[i]) }];
    }

    const legendNames = ser.map(s => s.name);
    const legendOn = showLegend && ser.length > 1;
    const legendOpts = {
      show: legendOn,
      type: legendType,
      orientation: legendOrientation,
      margin: legendMargin,
    };

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const label: any = {
      show: showLabels,
      position: 'right',
      formatter: (p: { value: number }) => formatter(p.value),
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const labelLayout = (p: { rect: { x: number; width: number } }) => ({
      x: p.rect.width < 0 ? p.rect.x - 4 : undefined,
      align: p.rect.width < 0 ? ('right' as const) : ('left' as const),
    });

    const echartsSeries = ser.map(s => ({
      name: s.name,
      type: 'bar' as const,
      data: single
        ? s.values.map(v => ({
            value: v,
            itemStyle: { color: v < 0 ? negativeColor : positiveColor },
          }))
        : s.values,
      itemStyle: single ? undefined : { color: colorFn(s.name, sliceId) },
      label,
      labelLayout,
    }));

    return {
      grid: padGridForLegend(legendOpts, {
        left: 8,
        right: 8,
        top: 16,
        bottom: 40,
      }),
      legend: legendOn ? buildLegend(legendOpts, legendNames) : { show: false },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow' },
        confine: true,
      },
      xAxis: {
        type: 'value',
        name: barCategoryLabel,
        nameLocation: 'middle',
        nameGap: 28,
        axisLabel: { formatter: (v: number) => formatter(v) },
        splitLine: { lineStyle: { type: 'dashed' } },
      },
      yAxis: {
        type: 'category',
        data: cats,
        axisTick: { show: false },
      },
      series: echartsSeries,
    };
  }, [
    categories,
    series,
    positiveColor,
    negativeColor,
    showLabels,
    numberFormat,
    barCategoryLabel,
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
