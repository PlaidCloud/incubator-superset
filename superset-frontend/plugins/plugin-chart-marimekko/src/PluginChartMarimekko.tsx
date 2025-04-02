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
import { useTheme } from '@superset-ui/core';
import React from "react";
import ReactECharts from 'echarts-for-react';
import { PluginChartMarimekkoProps } from './types';

// The following Styles component is a <div> element, which has been styled using Emotion
// For docs, visit https://emotion.sh/docs/styled

// Theming variables are provided for your use via a ThemeProvider
// imported from @superset-ui/core. For variables available, please visit
// https://github.com/apache-superset/superset-ui/blob/master/packages/superset-ui-core/src/style/index.ts

export default function PluginChartMarimekko(props: PluginChartMarimekkoProps) {
  // height and width are the height and width of the DOM element as it exists in the dashboard.
  // There is also a `data` prop, which is, of course, your DATA 🎉
  // const { data, height, width } = props;
  const {
    data: propsData,
    height: chartHeight,
    width: chartWidth,
    heightKey: heightKeyProp,
    widthKey: widthKeyProp,
    showPercentage = false,
    title: chartTitle,
  } = props;

  const theme = useTheme();

  // Often, you just want to access the DOM and do whatever you want.
  // Here, you can do that with createRef, and the useEffect hook.

  if (!heightKeyProp || !widthKeyProp) {
    throw new Error(
      `Height and width keys are required. The "Height key" (Customize -> Height Key) will be converted to "height" and "Width Key" (Customize -> Width Key) will be converted to "width" internally.`,
    );
  }

  // check if rawData exists and has data
  if (propsData.length === 0) {
    throw new Error('No data available');
  }

  let rawData: any[] = [];
  rawData = propsData.map(item => ({
    ...item,
    height: item[heightKeyProp],
    width: item[widthKeyProp],
  }));

  const flipKeys = false; // Set to false to maintain original order

  // Get the keys dynamically
  const keys = Object.keys(rawData[0]); // Extract keys from the first object

  // Auto-detect grouping key (e.g., Brand)
  const groupKey = flipKeys ? keys[1] : keys[0]; // x axis

  // Auto-detect secondary category key (e.g., Region)
  const categoryKey = flipKeys ? keys[0] : keys[1];

  // Auto-detect numeric fields (e.g., Revenue)
  const numericKeys = keys.slice(2);
  const heightKey = heightKeyProp || numericKeys[0];
  const widthKey = widthKeyProp || numericKeys[1];

  interface GroupData {
    total: number;
    values: any[];
  }

  // Group data dynamically by the primary key
  const groups: { [key: string]: GroupData } = {};
  rawData.forEach(item => {
    const group = item[groupKey];
    if (!groups[group]) {
      groups[group] = { total: 0, values: [] };
    }
    groups[group].values.push(item);
    groups[group].total += item[widthKey];
  });

  // Prepare x-axis & y-axis data dynamically
  let currentXStart = 0;
  interface MarimekkoDataItem {
    value: [
      string,
      string,
      number,
      number,
      number,
      number,
      number,
      string,
      number,
    ];
    name: string;
    itemStyle: {
      color: string;
    };
    raw: any;
  }
  const data: MarimekkoDataItem[] = [];
  const colorList = [
    '#5470c6',
    '#91cc75',
    '#fac858',
    '#ee6666',
    '#73c0de',
    '#3ba272',
    '#fc8452',
    '#9a60b4',
    '#ea7ccc',
    '#66ac52',
    '#ffb845',
    '#d7504b',
    '#3f557e',
    '#4682b4',
    '#4f7942',
  ];

  // yOffsetMap to track yStart when showPercentage = false
  const yOffsetMap: { [key: string]: number } = {};

  Object.keys(groups).forEach(group => {
    const groupWidth = groups[group].total;
    let currentYStart = 0;

    // Calculate total for 100% stacking
    const totalHeight = groups[group].values.reduce(
      (sum, item) => sum + item[heightKey],
      0,
    );

    if (!yOffsetMap[group]) {
      yOffsetMap[group] = 0;
    }

    groups[group].values.forEach((item, categoryIndex) => {
      const value = item[heightKey];
      const percentage = ((value / totalHeight) * 100).toFixed(1); // % height
      const segmentArea = (value / groupWidth) * 100; // Proportional area

      // Correct yStart when showPercentage = false using yOffsetMap
      const yStartAbsolute = yOffsetMap[group];
      const yEndAbsolute = yStartAbsolute + value;

      data.push({
        value: [
          item[groupKey], // Group name (e.g., Brand)
          item[categoryKey], // Category name (e.g., Region)
          currentXStart, // xStart
          currentXStart + groupWidth, // xEnd
          showPercentage ? currentYStart : yStartAbsolute, // yStart (in % or absolute)
          showPercentage
            ? currentYStart + parseFloat(percentage)
            : yEndAbsolute, // yEnd (in % or absolute)
          value, // Absolute value
          percentage, // Percentage height
          segmentArea, // Area for proportional visualization
        ],
        name: item[categoryKey],
        itemStyle: {
          color: colorList[categoryIndex % colorList.length],
        },
        raw: item,
      });

      // Increment yOffset for absolute stacking
      if (!showPercentage) {
        yOffsetMap[group] += value;
      } else {
        currentYStart += parseFloat(percentage);
      }
    });

    currentXStart += groupWidth;
  });

  // Calculate dynamic axisTick values and labels at the center of each block
  const xAxisValues: number[] = [];
  const xAxisLabels: string[] = [];
  let cumulativeWidth = 0;

  Object.keys(groups).forEach(group => {
    const groupWidth = groups[group].total;
    const midpoint = cumulativeWidth + groupWidth / 2; // Center of the block
    xAxisValues.push(midpoint);
    xAxisLabels.push(group);
    cumulativeWidth += groupWidth;
  });

  // Determine yAxis max based on mode
  const yAxisMax = showPercentage
    ? 100
    : (() => {
        const allHeights = Object.values(groups).map(group =>
          group.values.reduce((acc, curr) => acc + curr.height, 0),
        );
        const maxHeight = Math.max(...allHeights);
        return Math.round(maxHeight / 10) * 10;
      })();
  // Final ECharts option
  const option: echarts.EChartsOption = {
    title: {
      text: chartTitle,
      left: 'center',
    },
    legend: {
      show: true,
      top: 'bottom', // Position of the legend
      data: [...new Set(rawData.map(item => item[categoryKey]))], // Unique categories
    },
    tooltip: {
      trigger: 'item',
      formatter: params => {
        const typedParams =
          params as echarts.DefaultLabelFormatterCallbackParams;
        const values = typedParams.value as any[];
        const [group, category, , , , , value, percentage] = values;

        return `
        <b>${category} - ${group}</b><br/>
        ${heightKeyProp} (height): ${value} <br/>
        ${widthKeyProp} (width): ${(typedParams.data as any).raw[widthKeyProp]} <br/>
        Percentage: ${percentage}%<br/>
      `;
      },
    },
    xAxis: {
      type: 'value' as const,
      min: 0,
      max: cumulativeWidth,
      axisTick: {
        show: true,
        length: 8,
        customValues: xAxisValues, // Dynamically generated tick values
      },
      axisLabel: {
        formatter(value: number): string {
          const epsilon = 1; // Small tolerance for floating-point differences
          for (let i = 0; i < xAxisValues.length; i += 1) {
            if (Math.abs(value - xAxisValues[i]) < epsilon) {
              return xAxisLabels[i];
            }
          }
          return '';
        },
        customValues: xAxisValues,
        align: 'center',
      },
    },
    yAxis: {
      type: 'value',
      min: 0,
      max: yAxisMax,
      axisLabel: {
        formatter: showPercentage ? '{value}%' : '{value}',
      },
    },
    series: data.map(item => ({
      name: item.name,
      type: 'custom',
      renderItem(params: any, api: any) {
        const xStart = api.value(2);
        const xEnd = api.value(3);
        const yStart = api.value(5);
        const yEnd = api.value(4);
        const start = api.coord([xStart, yStart]);
        const size = api.size([xEnd - xStart, yEnd - yStart]);
        const shape = {
          x: start[0],
          y: start[1],
          width: size[0],
          height: size[1],
        };
        return {
          type: 'rect',
          shape,
          style: api.style(),
        };
      },
      label: {
        show: true,
        position: 'inside',
        // @ts-ignore
        formatter(params: { value: any[] }) {
          const value = params.value[6]; // Absolute value
          const percentage = params.value[7]; // Percentage
          return showPercentage ? `${percentage}%` : value;
        },
        color: theme.colors.grayscale.light5,
        fontSize: 14,
      },
      dimensions: [
        'group',
        'category',
        'xStart',
        'xEnd',
        'yStart',
        'yEnd',
        'value',
        'percentage',
        'area',
      ],
      encode: {
        x: [2, 3],
        y: [4, 5],
        tooltip: [0, 1, 2, 3, 4],
        itemName: 7,
      },
      data: [item],
    })),
  };

  return (
    <ReactECharts
      style={{ height: chartHeight, width: chartWidth }}
      option={option}
    />
  );
}
