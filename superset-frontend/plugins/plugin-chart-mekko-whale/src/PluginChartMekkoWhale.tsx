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
// @ts-ignore-next-line
import React from 'react';
import ReactECharts from 'echarts-for-react';
import { getNumberFormatter } from '@superset-ui/core';
import { PluginChartMekkoWhaleProps } from './types';

export default function PluginChartMekkoWhale(props: PluginChartMekkoWhaleProps) {
  const {
    data,
    height,
    width,
    xAxisLabel,
    yAxisLabel,
    xAxisFormat,
    yAxisFormat,
    yMin,
    yMax,
    xMax,
    setDataMask,
    groupby,
    filterState,
  } = props;

  const onChartClick = (params: any) => {
    const selectedName = params.data.name;
    if (!selectedName || !groupby || groupby.length === 0) return;

    const col = groupby[0];
    const currentSelectedValues = filterState?.selectedValues || [];
    let nextSelectedValues = [selectedName];

    if (params.event?.event?.ctrlKey || params.event?.event?.metaKey) {
      if (currentSelectedValues.includes(selectedName)) {
        nextSelectedValues = currentSelectedValues.filter((v: any) => v !== selectedName);
      } else {
        nextSelectedValues = [...currentSelectedValues, selectedName];
      }
    } else if (
      currentSelectedValues.length === 1 &&
      currentSelectedValues[0] === selectedName
    ) {
      nextSelectedValues = [];
    }

    setDataMask({
      extraFormData: {
        filters: [
          {
            col,
            op: nextSelectedValues.length ? 'IN' : 'IS NOT NULL',
            val: nextSelectedValues.length ? nextSelectedValues : null,
          } as any,
        ],
      },
      filterState: {
        value: nextSelectedValues.length ? nextSelectedValues : null,
        selectedValues: nextSelectedValues.length ? nextSelectedValues : null,
      },
    });
  };

  const yFormatter = getNumberFormatter(yAxisFormat || 'SMART_NUMBER');
  const xFormatter = getNumberFormatter(xAxisFormat || 'SMART_NUMBER');

  // Intelligent padding: only dip below 0 if the data actually does.
  // Otherwise, floor the axis at 0 to avoid confusing 'ghost' negative labels.
  const yRange = yMax - yMin;
  const yPadding = yRange * 0.05 || 1000;

  const forcedYMin = yMin < -yPadding ? yMin - yPadding : (yMin < 0 ? yMin * 1.1 : 0);
  const forcedYMax = yMax + yPadding;

  const option: any = {
    grid: {
      top: 40,
      right: 40,
      bottom: 60,
      left: 100,
      containLabel: true,
    },
    tooltip: {
      trigger: 'item',
      formatter: (params: any) => {
        const { name, value, itemStyle } = params.data;
        const [, xEnd, , yEnd, m1, m2] = value;
        return `
          <div style="border-left: 4px solid ${itemStyle.color}; padding-left: 8px;">
            <div style="font-weight: bold;">${name}</div>
            <div style="margin-top: 4px;">Profit: <b>${yFormatter(m1)}</b></div>
            <div>Revenue: <b>${xFormatter(m2)}</b></div>
            <hr style="margin: 4px 0; border: 0; border-top: 1px solid #eee;"/>
            <div>Cum. Profit: <b>${yFormatter(yEnd)}</b></div>
            <div>Cum. Revenue: <b>${xFormatter(xEnd)}</b></div>
          </div>
        `;
      },
    },
    xAxis: {
      name: xAxisLabel,
      nameLocation: 'middle',
      nameGap: 35,
      type: 'value',
      min: 0,
      max: xMax,
      axisLabel: { formatter: (v: number) => xFormatter(v) },
      splitLine: { lineStyle: { type: 'dashed', opacity: 0.3 } },
    },
    yAxis: {
      name: yAxisLabel,
      nameLocation: 'middle',
      nameGap: 70,
      type: 'value',
      min: forcedYMin,
      max: forcedYMax,
      axisLabel: { formatter: (v: number) => yFormatter(v) },
      splitLine: { lineStyle: { type: 'dashed', opacity: 0.3 } },
    },
    legend: {
      show: false,
      bottom: 0,
      type: 'scroll',
    },
    series: [
      {
        name: 'Mekko Whale',
        type: 'custom',
        renderItem: (params: any, api: any) => {
          const xStart = api.value(0);
          const xEnd = api.value(1);
          const yStart = api.value(2);
          const yEnd = api.value(3);

          const start = api.coord([xStart, yStart]);
          const end = api.coord([xEnd, yEnd]);

          if (isNaN(start[0]) || isNaN(start[1]) || isNaN(end[0]) || isNaN(end[1])) {
            return null;
          }

          const rectX = start[0];
          const rectY = Math.min(start[1], end[1]);
          const rectWidth = end[0] - start[0];
          const rectHeight = Math.abs(end[1] - start[1]);

          const yTopCoord = api.coord([xStart, forcedYMax]);
          const yBottomCoord = api.coord([xStart, forcedYMin]);
          const fullHeight = Math.abs(yBottomCoord[1] - yTopCoord[1]);
          const fullY = Math.min(yTopCoord[1], yBottomCoord[1]);

          return {
            type: 'group',
            children: [
              {
                type: 'rect',
                shape: {
                  x: rectX,
                  y: fullY,
                  width: rectWidth,
                  height: fullHeight,
                },
                style: {
                  fill: 'rgba(0,0,0,0)',
                },
              },
              {
                type: 'rect',
                shape: {
                  x: rectX,
                  y: rectY,
                  width: rectWidth,
                  height: rectHeight,
                },
                style: api.style(),
              },
            ],
          };
        },
        label: {
          show: false,
          position: 'inside',
          formatter: (params: any) => params.data.name,
          overflow: 'truncate',
          color: '#fff',
        },
        data,
      },
    ],
  };

  return (
    <div style={{ height: `${height}px`, width: `${width}px` }}>
      <ReactECharts
        option={option}
        style={{ height: '100%', width: '100%' }}
        onEvents={{ click: onChartClick }}
      />
    </div>
  );
}
