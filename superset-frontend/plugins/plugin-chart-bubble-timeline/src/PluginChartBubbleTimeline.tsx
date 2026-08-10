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
import { BubbleTimelineTransformedProps } from './types';
import { buildLegend, padGridForLegend } from './legend';

// Bubble datum encoded positionally: [x, y, size, name].
type BubbleValue = [number, number, number, string];

export default function PluginChartBubbleTimeline(
  props: BubbleTimelineTransformedProps,
) {
  const {
    width,
    height,
    periods,
    bubblesByPeriod,
    categories,
    maxSize,
    maxBubbleSize,
    autoPlay,
    showPeriodLabel,
    chartMargin,
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

    const legendOn =
      showLegend && categories.length > 1 && categories[0] !== 'All';
    const legendOpts = {
      show: legendOn,
      type: legendType,
      orientation: legendOrientation,
      margin: legendMargin,
    };

    const symbolSize = (val: BubbleValue) => {
      const [, , s] = val;
      // Area-proportional scaling with a small floor so tiny bubbles stay visible.
      return Math.sqrt(Math.max(s, 0) / maxSize) * maxBubbleSize + 4;
    };

    const baseSeries = categories.map(cat => ({
      name: cat,
      type: 'scatter' as const,
      itemStyle: { color: colorFn(cat, sliceId), opacity: 0.7 },
      symbolSize,
      emphasis: { focus: 'series', label: { show: true } },
      data: [] as BubbleValue[],
    }));

    // Large faded "current period" watermark (Gapminder style), updated per
    // frame. A stable id lets ECharts replace it in place across the timeline.
    const watermarkSize = Math.max(
      28,
      Math.min(Math.round(height * 0.32), Math.round(width * 0.22)),
    );
    const timelineOptions = periods.map(period => ({
      series: categories.map(cat => ({
        data: (bubblesByPeriod[period] ?? [])
          .filter(b => b.category === cat)
          .map(b => [b.x, b.y, b.size, b.name] as BubbleValue),
      })),
      graphic: showPeriodLabel
        ? [
            {
              id: 'periodLabel',
              type: 'text',
              right: 24,
              bottom: 48,
              silent: true,
              z: 0,
              style: {
                text: String(period),
                fill: '#9aa0a6',
                opacity: 0.35,
                fontSize: watermarkSize,
                fontWeight: 'bolder',
              },
            },
          ]
        : [{ id: 'periodLabel', type: 'text', style: { text: '' } }],
    }));

    return {
      baseOption: {
        graphic: [{ id: 'periodLabel', type: 'text', style: { text: '' } }],
        ...(showZoom
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
          : {}),
        timeline: {
          axisType: 'category',
          data: periods,
          autoPlay,
          playInterval: 1500,
          currentIndex: 0,
          bottom: 4,
          label: { color: '#666' },
        },
        color: categories.map((cat, i) => colorFn(cat, sliceId) || i),
        legend: legendOn
          ? buildLegend(legendOpts, categories)
          : { show: false },
        grid: padGridForLegend(legendOpts, {
          left: 56 + chartMargin,
          right: 24 + chartMargin,
          top: 24 + chartMargin,
          bottom: 64 + chartMargin,
        }),
        tooltip: {
          trigger: 'item',
          confine: true,
          formatter: (p: { seriesName: string; value: BubbleValue }) => {
            const [vx, vy, vs, nm] = p.value;
            const head = nm ? `<b>${nm}</b><br/>` : '';
            return (
              `${head}${p.seriesName}<br/>` +
              `${xAxisLabel}: ${formatter(vx)}<br/>` +
              `${yAxisLabel}: ${formatter(vy)}<br/>` +
              `Size: ${formatter(vs)}`
            );
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
        series: baseSeries,
      },
      options: timelineOptions,
    };
  }, [
    periods,
    bubblesByPeriod,
    categories,
    maxSize,
    maxBubbleSize,
    autoPlay,
    showPeriodLabel,
    chartMargin,
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
    width,
    height,
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
