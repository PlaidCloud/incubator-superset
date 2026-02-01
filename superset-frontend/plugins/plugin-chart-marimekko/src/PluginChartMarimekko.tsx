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
import { getNumberFormatter } from '@superset-ui/core';
import ReactECharts from 'echarts-for-react';
import { PluginChartMarimekkoProps } from './types';
import React from 'react';

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
    tooltipIncludeColumn,
    tooltipNumberFormat,
    tooltipShowPercentage,
    xAxisLabel,
    yAxisLabel,
    showLegend,
    showLabels,
    labelColor,
    sortByColumn,
    sortOrder = 'DESC',
    showXAxisLabels = true,
  } = props;

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

  // Detect if we have 3-column data (1 dimension + 2 metrics)
  // This happens when the second column matches one of the metric keys
  const secondColumnIsMetric =
    keys[1] === heightKeyProp || keys[1] === widthKeyProp;

  // Auto-detect grouping key (e.g., Brand)
  const groupKey = flipKeys ? keys[1] : keys[0]; // x axis

  // Auto-detect secondary category key (e.g., Region)
  // For 3-column data, use the same column as groupKey (each row is its own category)
  const categoryKey = secondColumnIsMetric
    ? groupKey
    : flipKeys
      ? keys[0]
      : keys[1];

  // Auto-detect numeric fields (e.g., Revenue)
  // For 3-column data, numeric keys start at index 1
  const numericKeys = secondColumnIsMetric ? keys.slice(1) : keys.slice(2);
  const heightKey = heightKeyProp || numericKeys[0];
  const widthKey = widthKeyProp || numericKeys[1];

  interface GroupData {
    group: string;
    total: number;
    values: any[];
  }

  // Group data dynamically by the primary key
  const groups: GroupData[] = [];
  const processedGroups = new Set<string>();

  rawData.forEach(item => {
    const group = item[groupKey];

    // If this group hasn't been processed yet, create a new entry
    if (!processedGroups.has(group)) {
      groups.push({
        group,
        total: 0,
        values: [],
      });
      processedGroups.add(group);
    }

    // Find the group and update it
    const groupIndex = groups.findIndex(g => g.group === group);
    groups[groupIndex].values.push(item);
    groups[groupIndex].total += item[widthKey];
  });

  // Apply sorting based on different column types
  if (sortByColumn) {
    if (sortByColumn === groupKey) {
      // Sort groups by their names, ensuring string comparison
      groups.sort((a, b) => {
        const aStr = String(a.group);
        const bStr = String(b.group);

        if (sortOrder === 'DESC') {
          return bStr.localeCompare(aStr);
        }
        return aStr.localeCompare(bStr);
      });
    } else {
      // Handle existing sorting logic for height/width
      groups.forEach(group => {
        group.values.sort((a, b) => {
          const aValue = sortByColumn === heightKeyProp ? a.height : a.width;
          const bValue = sortByColumn === heightKeyProp ? b.height : b.width;
          return sortOrder === 'DESC' ? bValue - aValue : aValue - bValue;
        });
      });

      // If sorting by width, also sort the groups
      if (sortByColumn === widthKeyProp) {
        groups.sort((a, b) =>
          sortOrder === 'DESC' ? b.total - a.total : a.total - b.total,
        );
      }
    }
  }

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

  // Track group index for color assignment in 3-column mode
  let groupIndex = 0;

  Object.values(groups).forEach(({ group, total: groupWidth, values }) => {
    let currentYStartPositive = 0;
    let currentYStartNegative = 0;

    // Calculate totals for 100% stacking (only positive values contribute to total)
    const totalPositiveHeight = values.reduce(
      (sum, item) => sum + Math.max(0, item[heightKey]),
      0,
    );
    const totalNegativeHeight = values.reduce(
      (sum, item) => sum + Math.min(0, item[heightKey]),
      0,
    );
    const totalHeight = totalPositiveHeight - totalNegativeHeight; // Absolute total for percentage

    // Track positive and negative offsets separately for absolute mode
    if (!yOffsetMap[`${group}_positive`]) {
      yOffsetMap[`${group}_positive`] = 0;
    }
    if (!yOffsetMap[`${group}_negative`]) {
      yOffsetMap[`${group}_negative`] = 0;
    }

    values.forEach((item, categoryIndex) => {
      const value = item[heightKey];
      const isNegative = value < 0;
      const absValue = Math.abs(value);
      const percentage = ((absValue / totalHeight) * 100).toFixed(1); // % height

      const segmentArea = (absValue / groupWidth) * 100; // Proportional area

      let yStart: number;
      let yEnd: number;

      if (showPercentage) {
        // Percentage mode: stack from 0, negatives go down
        if (isNegative) {
          yEnd = currentYStartNegative;
          yStart = currentYStartNegative - parseFloat(percentage);
          currentYStartNegative = yStart;
        } else {
          yStart = currentYStartPositive;
          yEnd = currentYStartPositive + parseFloat(percentage);
          currentYStartPositive = yEnd;
        }
      } else {
        // Absolute mode: negatives extend down from 0, positives extend up from 0
        if (isNegative) {
          yEnd = yOffsetMap[`${group}_negative`];
          yStart = yEnd + value; // value is negative, so this goes down
          yOffsetMap[`${group}_negative`] = yStart;
        } else {
          yStart = yOffsetMap[`${group}_positive`];
          yEnd = yStart + value;
          yOffsetMap[`${group}_positive`] = yEnd;
        }
      }

      data.push({
        value: [
          item[groupKey], // Group name (e.g., Brand)
          item[categoryKey], // Category name (e.g., Region)
          currentXStart, // xStart
          currentXStart + groupWidth, // xEnd
          yStart, // yStart (starting point)
          yEnd, // yEnd (ending point)
          value, // Absolute value (can be negative)
          percentage, // Percentage height (always positive)
          segmentArea, // Area for proportional visualization
        ],
        name: item[categoryKey],
        itemStyle: {
          // For 3-column data (single segment per group), use group index for distinct colors
          // For multi-segment groups, use category index within the group
          color:
            secondColumnIsMetric && values.length === 1
              ? colorList[groupIndex % colorList.length]
              : colorList[categoryIndex % colorList.length],
        },
        raw: item,
      });
    });

    currentXStart += groupWidth;
    groupIndex += 1;
  });

  const getLabelColor = (color: {
    r: number;
    g: number;
    b: number;
    a: number;
  }) => `rgba(${color.r}, ${color.g}, ${color.b}, ${color.a})`;

  // Calculate dynamic axisTick values and labels at the center of each block
  const xAxisValues: number[] = [];
  const xAxisLabels: string[] = [];
  let cumulativeWidth = 0;

  Object.values(groups).forEach(({ group, total: groupWidth }) => {
    const midpoint = cumulativeWidth + groupWidth / 2; // Center of the block
    xAxisValues.push(midpoint);
    xAxisLabels.push(group);
    cumulativeWidth += groupWidth;
  });

  // Determine yAxis min and max based on mode
  // For percentage mode: 0 to 100
  // For absolute mode: calculate from data, including negative values
  const { yAxisMin, yAxisMax } = showPercentage
    ? { yAxisMin: 0, yAxisMax: 100 }
    : (() => {
      // For each group, sum up all heights (which can be negative)
      const groupTotals = Object.values(groups).map(group =>
        group.values.reduce((acc, curr) => acc + curr.height, 0),
      );
      // Also consider individual segment values for proper min/max
      const allHeights = rawData.map(item => item.height);
      const maxHeight = Math.max(...groupTotals, ...allHeights, 0);
      const minHeight = Math.min(...groupTotals, ...allHeights, 0);
      return {
        yAxisMin: minHeight < 0 ? Math.floor(minHeight / 10) * 10 : 0,
        yAxisMax: Math.ceil(maxHeight / 10) * 10,
      };
    })();

  // Final ECharts option
  const option: echarts.EChartsOption = {
    title: {
      text: chartTitle,
      left: 'center',
    },
    legend: {
      show: showLegend,
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
        const { raw } = typedParams.data as any;

        // Create number formatter based on props
        const numberFormatter = getNumberFormatter(tooltipNumberFormat);

        // Format the values using the configured options
        const formattedValue = numberFormatter(value);
        const formattedWidth = numberFormatter(raw[widthKeyProp]);

        // Build tooltip content based on configuration
        let tooltipContent = '';

        // Add header
        tooltipContent += `<b>${category} - ${group}</b><br/>`;

        // Add column names if enabled
        if (tooltipIncludeColumn) {
          tooltipContent += `${heightKeyProp}: ${formattedValue}<br/>`;
          tooltipContent += `${widthKeyProp}: ${formattedWidth}<br/>`;
        }

        // Add percentage if enabled
        if (tooltipShowPercentage) {
          tooltipContent += `Percentage: ${percentage}%`;
        }

        return tooltipContent;
      },
    },
    xAxis: {
      name: xAxisLabel,
      nameLocation: 'middle',
      nameGap: 30,
      type: 'value' as const,
      min: 0,
      max: cumulativeWidth,
      axisTick: {
        show: true,
        length: 8,
        customValues: xAxisValues, // Dynamically generated tick values
      },
      axisLabel: {
        show: showXAxisLabels,
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
      name: yAxisLabel,
      nameLocation: 'middle',
      nameGap: 40,
      type: 'value',
      min: yAxisMin,
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
      labelLayout(params) {
        const rectWidth = params.rect.width;
        const rectHeight = params.rect.height;

        // Base font size on the smaller dimension to ensure text fits
        const widthBasedSize = rectWidth / 8;
        const heightBasedSize = rectHeight / 4;

        // Use the smaller of the two sizes to ensure text fits in both dimensions
        const fontSize = Math.min(
          widthBasedSize,
          heightBasedSize,
          // Set maximum font size
          24,
        );
        const MIN_FONT_SIZE = 6;

        return {
          fontSize: fontSize < MIN_FONT_SIZE ? 0 : fontSize, // Hide text if too small
        };
      },
      label: {
        show: showLabels,
        position: 'inside',
        // @ts-ignore
        formatter(params: any) {
          const text = params.value[1];
          return text;
        },
        color: getLabelColor(labelColor ?? { r: 246, g: 246, b: 246, a: 1 }),
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
