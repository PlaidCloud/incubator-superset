/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import {
  getNumberFormatter,
  QueryFormMetric,
  CategoricalColorNamespace,
  SupersetTheme,
  getMetricLabel,
  getColumnLabel,
  tooltipHtml,
  FilterState,
  rgbToHex,
} from '@superset-ui/core';
import { EChartsCoreOption } from 'echarts/core';
import {
  SupersetPluginChartWhaleProps,
  ProcessedDataRecord,
  WhaleChartType,
  WhaleChartTransformedProps,
  Refs,
  ChartColors,
  AxisOptions,
  TooltipParam,
} from '../types';
import {
  extractGroupbyLabel,
  getColtypesMapping,
} from '../../../plugin-chart-echarts/src/utils/series';

const PARETO_COLOR = '#FF6B6B';
const PARETO_REFERENCE_LINE_NAME = '80/20 Pareto Reference';

/**
 * Get chart colors from theme or use defaults
 */
function getChartColors(
  positiveColor?: { r: number; g: number; b: number; },
  neutralColor?: { r: number; g: number; b: number; },
  negativeColor?: { r: number; g: number; b: number; },
  colorScale?: any,
  useManualColors: boolean = true,
): ChartColors {
  // Default colors to use if not provided through controls
  const defaultPositiveColor = '#5AC189'; // green
  const defaultNeutralColor = '#666666'; // gray
  const defaultNegativeColor = '#E04355'; // red

  let posColor: string;
  let neuColor: string;
  let negColor: string;

  if (useManualColors) {
    // If manual colors are enabled, use the specified colors or defaults
    posColor = positiveColor
      ? rgbToHex(positiveColor.r, positiveColor.g, positiveColor.b)
      : defaultPositiveColor;
    
    neuColor = neutralColor
      ? rgbToHex(neutralColor.r, neutralColor.g, neutralColor.b)
      : defaultNeutralColor;
    
    negColor = negativeColor
      ? rgbToHex(negativeColor.r, negativeColor.g, negativeColor.b)
      : defaultNegativeColor;
  } else {
    // If not using manual colors, use the first color from the color scale for all values
    const firstColor = colorScale?.colors?.[0] || defaultPositiveColor;
    posColor = firstColor;
    neuColor = firstColor;
    negColor = firstColor;
  }

  return {
    pareto: PARETO_COLOR,
    positive: posColor,
    neutral: neuColor,
    negative: negColor,
  };
}

/**
 * Transform data for a single metric
 */
function transformSingleMetric(
  data: Record<string, any>[],
  metricLabel: string,
): ProcessedDataRecord[] {
  // Sort by metric in descending order
  const sortedData = [...data].sort((a, b) => b[metricLabel] - a[metricLabel]);

  // Calculate total metric value
  const totalMetric = sortedData.reduce(
    (sum, item) => sum + (item[metricLabel] || 0),
    0,
  );

  // Calculate cumulative metric and percentages
  let cumulativeMetric = 0;
  return sortedData.map((item, index) => {
    cumulativeMetric += item[metricLabel] || 0;
    return {
      ...item,
      cumulativeMetric,
      metricPct: (item[metricLabel] / totalMetric) * 100,
      cumulativeMetricPct: (cumulativeMetric / totalMetric) * 100,
      entityPercentile: ((index + 1) / sortedData.length) * 100,
    };
  });
}

/**
 * Transform data for multiple metrics
 */
function multiMetricTransform(
  data: Record<string, any>[],
  metricColumns: string[],
): ProcessedDataRecord[] {
  if (metricColumns.length === 0) {
    return [];
  }

  // Create independent transformations for each metric
  const firstMetric = metricColumns[0];
  let transformedData = transformSingleMetric(data, firstMetric);
  
  // Process all other metrics independently
  if (metricColumns.length > 1) {
    for (let i = 1; i < metricColumns.length; i += 1) {
      const metricLabel = metricColumns[i];
      const metricData = transformSingleMetric(data, metricLabel);

      // Merge metric data into transformed data
      transformedData = transformedData.map((item, idx) => {
        if (idx < metricData.length) {
          const metricItem = metricData[idx];
          return {
            ...item,
            [`${metricLabel}_cumulativeMetric`]: metricItem.cumulativeMetric,
            [`${metricLabel}_metricPct`]: metricItem.metricPct,
            [`${metricLabel}_cumulativeMetricPct`]: metricItem.cumulativeMetricPct,
          };
        }
        return item;
      });
    }
  }

  return transformedData;
}

/**
 * Create X axis options
 */
function createXAxisOptions(chartType: WhaleChartType): AxisOptions {
  const baseOptions = {
    nameLocation: 'middle',
    nameGap: 52,
    boundaryGap: true,
    axisTick: { show: true },
    axisLine: { show: true, onZero: false },
  };

  if (chartType === WhaleChartType.Whale) {
    return {
      ...baseOptions,
      type: 'value',
      min: 0,
      max: 100,
      splitArea: { show: true },
      axisLabel: { show: true, formatter: '{value}%' },
      splitLine: { show: true },
      interval: 20, // Ensures ticks at 0, 20, 40, 60, 80, 100
    };
  }

  return {
    ...baseOptions,
    type: 'category',
    splitArea: { show: true },
    axisLabel: { show: true, formatter: '{value}' },
    splitLine: { show: false },
  };
}

/**
 * Create Y axis options
 */
function createYAxisOptions(
  metrics: QueryFormMetric[],
  chartType: WhaleChartType,
  themeColors?: SupersetTheme['colors'],
  yAxisFormat?: string,
  processedData?: ProcessedDataRecord[],
) {
  // Get formatter based on format string selected in the control panel
  const formatter = chartType === WhaleChartType.Whale 
    ? '{value}%' 
    : (value: number) => {
        // Use the getNumberFormatter utility for consistent formatting
        if (yAxisFormat) {
          return getNumberFormatter(yAxisFormat)(value);
        }
        return getNumberFormatter()(value);
      };

  // Primary Y axis (percentage - right side)
  const primaryAxis = {
    type: 'value',
    nameLocation: 'middle',
    nameGap: 52,
    name: 'Percentage',
    nameTextStyle: { color: themeColors?.text?.label },
    min: chartType === WhaleChartType.Whale ? 0 : undefined,
    axisLabel: {
      formatter,
      color: themeColors?.text?.label,
    },
    splitLine: {
      show: true,
      lineStyle: { type: 'dashed' },
    },
    position: 'right',
  };
  
  // For whale chart, add a second Y axis on the left side showing absolute values
  const axes = [primaryAxis];
  
  if (chartType === WhaleChartType.Whale && processedData && processedData.length > 0) {
    // Find the total metric value (100%) to use as max value
    const totalMetricValue = processedData.length > 0 ? 
      processedData[processedData.length - 1].cumulativeMetric : 0;
      
    const secondaryAxis = {
      type: 'value',
      nameLocation: 'middle',
      nameGap: 52,
      name: 'Absolute Value',
      nameTextStyle: { color: themeColors?.text?.label },
      min: 0,
      max: totalMetricValue || undefined,
      // Align with the percentage axis intervals
      splitNumber: 5,
      interval: totalMetricValue ? totalMetricValue / 5 : undefined,
      axisLabel: {
        formatter: (value: number) => getNumberFormatter(yAxisFormat || 'SMART_NUMBER')(value),
        color: themeColors?.text?.label,
      },
      splitLine: {
        show: false,
        lineStyle: { type: 'dashed' }, // Required property
      },
      position: 'left',
    };
    
    axes.push(secondaryAxis);
  }

  return axes;
}

/**
 * Create series data for whale chart type
 */
function createWhaleChartSeries(
  processedData: ProcessedDataRecord[],
  columns: string,
  metrics: QueryFormMetric[],
  colors: ChartColors,
  showPareto: boolean,
  colorScale: any,
): any[] {
  const series: any[] = [];
  // Process each metric
  metrics.forEach((metric, i) => {
    const metricLabel = getMetricLabel(metric);
    
    // Determine data keys based on metric index
    const isFirstMetric = i === 0;
    const dataKey = isFirstMetric ? 'cumulativeMetricPct' : `${metricLabel}_cumulativeMetricPct`;
    const absoluteDataKey = isFirstMetric ? 'cumulativeMetric' : `${metricLabel}_cumulativeMetric`;
    
    // Combine all data points into a single array for gradient coloring
    const allData: any[] = [];

    let lastPositivePercentile = 0;
    let firstNegativePercentile = 0;    
    
    // First pass to collect all data points and determine min/max
    for (const item of processedData) {

      // Skip items without a valid entity name
      if (!item[columns]) {
        continue;
      }
      const value = Number(item[metricLabel] || 0);

      if (value > 0) {
        lastPositivePercentile = item.entityPercentile / 100;
      }
      if (value < 0 && firstNegativePercentile === 0) {
        firstNegativePercentile = item.entityPercentile / 100;
      }
      
      const dataPoint = {
        name: String(item[columns] || ''),
        value: [item.entityPercentile, isFirstMetric ? item.cumulativeMetricPct : (item[dataKey] || 0)],
        absoluteValue: item[metricLabel],
        cumulativeTotal: isFirstMetric ? item.cumulativeMetric : (item[absoluteDataKey] || 0),
        originalValue: value,
      };
      
      allData.push(dataPoint);
    }
    
    // Create a single series with gradient coloring
    if (allData.length > 0) {
      const colorStops = (() => {
        // All positive values case
        if (lastPositivePercentile === 1) {
          return [
            { offset: 0, color: colors.positive },
            { offset: 1, color: colors.positive }
          ];
        }

        // All negative values case
        if (firstNegativePercentile === 0) {
          return [
            { offset: 0, color: colors.negative },
            { offset: 1, color: colors.negative }
          ];
        }

        // Mixed values case - handle ordering issues
        if (lastPositivePercentile > firstNegativePercentile) {
          const midpoint = (lastPositivePercentile + firstNegativePercentile) / 2;
          return [
            { offset: 0, color: colors.positive },
            { offset: midpoint, color: colors.neutral },
            { offset: 1, color: colors.negative }
          ];
        }

        // Standard case with proper ordering
        return [
          { offset: 0, color: colors.positive },
          { offset: lastPositivePercentile, color: colors.neutral },
          { offset: firstNegativePercentile, color: colors.neutral },
          { offset: 1, color: colors.negative }
        ];
      })();

      series.push({
        type: 'line' as const,
        yAxisIndex: 0,
        smooth: 0.7,
        symbol: 'circle',
        name: metricLabel,
        itemStyle: {
          color: colorStops[0].color, // Match legend color with the start of the gradient
        },
        showSymbol: false, // Hide symbols to make the gradient look smoother
        lineStyle: {
          width: 2,
          color: {
            type: 'linear',
            x: 0,
            y: 0, 
            x2: 1,
            y2: 0,
            colorStops: [
              { offset: 0, color: colorStops[0].color },
              { offset: 1, color: colorStops[colorStops.length - 1].color }
            ]
          }
        },
        areaStyle: {
          opacity: 0.8,
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 1,
            y2: 0,
            colorStops,
          }
        },
        data: allData,
        legendHoverLink: true,
      });
    }
  });

  // Add Pareto reference line if enabled
  if (showPareto) {
    series.push({
      name: PARETO_REFERENCE_LINE_NAME,
      type: 'line',
      smooth: false,
      symbol: 'none',
      lineStyle: {
        width: 1,
        type: 'dashed',
        color: colors.pareto,
      },
      data: [
        [0, 0],
        [20, 80],
        [100, 100],
      ],
    });
  }

  return series;
}

/**
 * Create series data for bar chart type
 */
function createBarChartSeries(
  processedData: ProcessedDataRecord[],
  columns: string,
  metrics: QueryFormMetric[],
  colorScale: any,
  colors: ChartColors,
): any[] {
  const series: any[] = [];

  // Filter out artificial data points (ones without a valid entity name)
  const filteredData = processedData.filter(item => item[columns]);

  // Process metrics
  metrics.forEach((metric, index) => {
    const metricLabel = getMetricLabel(metric);
    // Use the metric's position in the metrics array to pick a color from the scheme
    const metricColorIndex = index % (colorScale?.colors?.length || 1);
    const metricColor = colorScale?.colors?.[metricColorIndex] || colorScale(metricLabel);
    
    series.push({
      name: metricLabel,
      type: 'bar',
      yAxisIndex: 0,
      itemStyle: {
        color: (params: any) => {
          const itemIndex = params.dataIndex;
          if (itemIndex !== undefined && itemIndex < filteredData.length) {
            const value = Number(filteredData[itemIndex][metricLabel]);
            
            // Use the proper colors based on value sign
            if (value > 0) {
              return colors.positive;
            } else if (value < 0) {
              return colors.negative;
            } else {
              // For zero values, use neutral color
              return colors.neutral;
            }
          }
          // Use the metric's color as fallback
          return metricColor;
        },
      },
      data: filteredData.map(item => ({
        name: item[columns] ? String(item[columns]) : '',
        value: [item[columns], item[metricLabel]], // Use raw value
      })),
    });
  });

  return series;
}

/**
 * Create chart series
 */
function createSeries(
  processedData: ProcessedDataRecord[],
  columns: string,
  metrics: QueryFormMetric[],
  chartType: WhaleChartType,
  colors: ChartColors,
  showPareto: boolean,
  colorScale: any,
): any[] {
  if (chartType === WhaleChartType.Whale) {
    return createWhaleChartSeries(
      processedData,
      columns,
      metrics,
      colors,
      showPareto,
      colorScale,
    );
  }

  return createBarChartSeries(
    processedData,
    columns,
    metrics,
    colorScale,
    colors,
  );
}

/**
 * Create tooltip configuration
 */
function createTooltip(
  chartType: WhaleChartType,
  tooltipOnlyMetrics: QueryFormMetric[] = [],
  processedData: ProcessedDataRecord[],
  yAxisFormat?: string,
) {
  // Use the getNumberFormatter utility for consistent formatting
  const valueFormatter = getNumberFormatter(yAxisFormat || 'SMART_NUMBER');
  const percentFormatter = getNumberFormatter(',.1f');
  const isWhaleChart = chartType === WhaleChartType.Whale;
  
  return {
    trigger: 'axis',
    formatter: (params: TooltipParam[]) => {
      if (!params || params.length === 0) return '';
      
      const firstParam = params[0];
      const entityName = firstParam.data?.name ?? 'N/A';
      const dataIndex = firstParam.dataIndex;
      
      // Quick access to data record if available
      const record = typeof dataIndex === 'number' && dataIndex < processedData.length 
                   ? processedData[dataIndex] 
                   : null;
      
      // Create rows array with initial capacity to avoid resizing
      const rows: string[][] = [
        ['Rank', typeof dataIndex === 'number' && (!isWhaleChart || entityName !== '') 
               ? `${dataIndex + 1}` 
               : 'N/A']
      ];
      
      // Add percentile row for whale chart type
      if (isWhaleChart) {
        rows.push(['Percentile', `${percentFormatter(firstParam.value[0])}%`]);
      }
      
      // Process series parameters more efficiently
      for (const param of params) {
        const seriesName = param.seriesName;
        
        // Skip Pareto reference line
        if (isWhaleChart && seriesName === PARETO_REFERENCE_LINE_NAME) {
          continue;
        }
        
        if (isWhaleChart) {
          // For whale chart, combine percentage and absolute value
          const percentValue = param.value[1];
          const percentFormatted = `${percentFormatter(percentValue)}%`;
          
          // Only lookup absolute value if we have a valid record
          let valueText = percentFormatted;
          if (record) {
            const absoluteValue = record[seriesName];
            if (absoluteValue !== undefined && absoluteValue !== null) {
              valueText = `${percentFormatted} (${typeof absoluteValue === 'number' 
                ? valueFormatter(absoluteValue) 
                : String(absoluteValue)})`;
            }
          }
            
          rows.push([seriesName, valueText]);
          
          // Add a row for cumulative total if available
          const cumulativeTotal = param.data?.cumulativeTotal;
          if (cumulativeTotal !== undefined) {
            const cumulativeTotalLabel = `Cumulative Total (${seriesName})`;
            rows.push([
              cumulativeTotalLabel,
              typeof cumulativeTotal === 'number' 
                ? valueFormatter(cumulativeTotal) 
                : String(cumulativeTotal)
            ]);
          }
        } else {
          // For bar chart, use number formatter from control panel
          const value = param.value[1];
          rows.push([seriesName, typeof value === 'number' 
            ? valueFormatter(value) 
            : String(value)]);
        }
      }
      
      if (tooltipOnlyMetrics.length > 0 && record) {
        for (const metric of tooltipOnlyMetrics) {
          const metricLabel = getMetricLabel(metric);
          const value = record[metricLabel];
          
          if (value !== undefined && value !== null) {
            rows.push([
              metricLabel, 
              typeof value === 'number' ? valueFormatter(value) : String(value)
            ]);
          }
        }
      }

      return tooltipHtml(rows, entityName);
    },
  };
}

/**
 * Create data zoom options
 */
function createDataZoomOptions(zoomable: boolean) {
  if (!zoomable) return undefined;

  return [
    {
      type: 'slider',
      show: true,
      xAxisIndex: [0],
      start: 0,
      end: 100,
    },
    {
      type: 'inside',
      xAxisIndex: [0],
      start: 0,
      end: 100,
    },
  ];
}

/**
 * Build full ECharts options
 */
function buildEChartOptions(
  chartType: WhaleChartType,
  processedData: ProcessedDataRecord[],
  columns: string,
  metrics: QueryFormMetric[],
  colors: ChartColors,
  showPareto?: boolean,
  showValueOnHover?: boolean,
  colorScale?: any,
  themeColors?: SupersetTheme['colors'],
  zoomable?: boolean,
  tooltipOnlyMetrics?: QueryFormMetric[],
  yAxisFormat?: string,
): EChartsCoreOption {
  return {
    tooltip: showValueOnHover
      ? createTooltip(chartType, tooltipOnlyMetrics, processedData, yAxisFormat)
      : { show: false },
    xAxis: createXAxisOptions(chartType),
    yAxis: createYAxisOptions(
      metrics,
      chartType,
      themeColors,
      yAxisFormat,
      processedData,
    ),
    legend: {
      show: true,
      type: 'scroll',
      orient: 'horizontal',
      align: 'auto',
    },
    series: createSeries(
      processedData,
      columns,
      metrics,
      chartType,
      colors,
      !!showPareto,
      colorScale,
    ),
    grid: {
      left: '5%',
      right: '5%',
      bottom: zoomable? '15%': '5%',
      top: '10%',
      containLabel: true,
    },
    dataZoom: createDataZoomOptions(!!zoomable),
  };
}

/**
 * Create label map for cross-filtering
 */
function createLabelMap(
  data: Record<string, any>[],
  groupbyLabels: string[],
  coltypeMapping: Record<string, any>,
): Record<string, string[]> {
  return data.reduce((acc: Record<string, string[]>, datum) => {
    const label = extractGroupbyLabel({
      datum,
      groupby: groupbyLabels,
      coltypeMapping,
    });
    return {
      ...acc,
      [label]: groupbyLabels.map(col => datum[col] as string),
    };
  }, {});
}

/**
 * Process selected values for filtering
 */
function processSelectedValues(
  filterState: FilterState,
  transformedData: ProcessedDataRecord[],
): Record<number, string> {
  return (filterState.selectedValues || []).reduce(
    (acc: Record<string, number>, selectedValue: string) => {
      const index = transformedData.findIndex(
        ({ name }) => name === selectedValue,
      );
      return {
        ...acc,
        [index]: selectedValue,
      };
    },
    {},
  );
}

/**
 * Transform function for Whale Chart
 * Processes data to create a cumulative distribution chart
 */
export default function transformProps(
  chartProps: SupersetPluginChartWhaleProps,
): WhaleChartTransformedProps {
  const {
    width,
    height,
    formData,
    queriesData,
    theme,
    hooks,
    filterState,
    emitCrossFilters = true,
  } = chartProps;

  const {
    metrics = [],
    tooltipOnlyMetrics = [],
    columns = '',
    chartType = WhaleChartType.Whale,
    showPareto = false,
    showValueOnHover = true,
    colorScheme,
    groupby = [columns],
    zoomable = false,
    yAxisFormat,
    positiveColor,
    neutralColor,
    negativeColor,
    useManualColors = true, // Default to true for backward compatibility
  } = formData;

  const colorScale = CategoricalColorNamespace.getScale(colorScheme as string);
  
  const colors = getChartColors(
    positiveColor,
    neutralColor,
    negativeColor,
    colorScale,
    useManualColors,
  );

  // Process data
  const { data = [] } = queriesData?.[0] || {};
  const refs: Refs = {};

  let processedData: ProcessedDataRecord[] = [];
  
  // Get primary metrics that need full transformation (sorting, cumulative values).
  const primaryMetricLabels = metrics.map((m: QueryFormMetric) => getMetricLabel(m));
  
  // Transform data using only primary metrics for the main calculations.
  // Raw values for tooltipOnlyMetrics are carried through via `...item` in `transformSingleMetric`
  // and are available on `processedData` items for tooltip creation.
  processedData = multiMetricTransform(data, primaryMetricLabels);

  // Build the full ECharts options
  const echartOptions = buildEChartOptions(
    chartType,
    processedData,
    columns,
    metrics,
    colors,
    showPareto,
    showValueOnHover,
    colorScale,
    theme?.colors,
    zoomable,
    tooltipOnlyMetrics,
    yAxisFormat
  );

  // Cross-filtering support
  const groupbyLabels = groupby.map(getColumnLabel);
  const coltypeMapping = getColtypesMapping(queriesData[0]);
  const labelMap = createLabelMap(data, groupbyLabels, coltypeMapping);
  const { setDataMask = () => {}, onContextMenu } = hooks;
  const selectedValues = processSelectedValues(filterState, processedData);

  return {
    width,
    height,
    data: processedData,
    formData,
    echartOptions,
    setDataMask,
    labelMap,
    selectedValues,
    onContextMenu,
    refs,
    emitCrossFilters,
    groupby,
  };
}
