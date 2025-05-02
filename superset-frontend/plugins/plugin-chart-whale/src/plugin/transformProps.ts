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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS,
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
  MetricRange,
} from '../types';
import {
  extractGroupbyLabel,
  getColtypesMapping,
} from '../../../plugin-chart-echarts/src/utils/series';

// ===== Constants =====
// Theme and styling constants
const LIGHT_BLUE = '#1E66F522';
const PARETO_COLOR = '#FF6B6B';
const KEY_PERCENTILES = [0, 20, 40, 60, 80, 100];
const PERCENTILE_EPSILON = 0.001; // Threshold for percentile equality
const SCALE_DIFFERENCE_THRESHOLD = 50; // Threshold for setting secondary axis
const SCALE_MAGNITUDE_MIN_THRESHOLD = 0.02; // Lower threshold for magnitude difference
const DEFAULT_FONT_SIZE = 16;
const PARETO_REFERENCE_LINE_NAME = '80/20 Pareto Reference';

// Font size mapping
const FONT_SIZES: Record<string, number> = {
  xxs: 10,
  xs: 12,
  s: 14,
  m: 16,
  l: 18,
  xl: 22,
  xxl: 24,
};
// ===== Helper Functions =====
/**
 * Get font size in pixels from named size
 */
function getFontSize(size: string): number {
  return FONT_SIZES[size] || DEFAULT_FONT_SIZE;
}

/**
 * Get chart colors from theme or use defaults
 */
function getChartColors(themeColors?: SupersetTheme['colors']): ChartColors {
  return {
    primary: themeColors?.primary?.base || '#66CCFF',
    areaTop: themeColors?.primary?.light1 || '#99DDFF',
    areaBottom: LIGHT_BLUE,
    secondary: themeColors?.info?.base || '#FFCC66',
    pareto: PARETO_COLOR,
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
  primaryMetric: string,
): ProcessedDataRecord[] {
  // Process for the primary metric
  let transformedData = transformSingleMetric(data, primaryMetric);

  // Process secondary metrics if available
  if (metricColumns.length > 1) {
    for (let i = 1; i < metricColumns.length; i += 1) {
      const secondaryMetric = metricColumns[i];
      const secondaryData = transformSingleMetric(data, secondaryMetric);

      // Merge secondary metric data into primary data
      transformedData = transformedData.map((item, idx) => {
        if (idx < secondaryData.length) {
          const secondaryItem = secondaryData[idx];
          return {
            ...item,
            [`${secondaryMetric}_cumulativeMetric`]:
              secondaryItem.cumulativeMetric,
            [`${secondaryMetric}_metricPct`]: secondaryItem.metricPct,
            [`${secondaryMetric}_cumulativeMetricPct`]:
              secondaryItem.cumulativeMetricPct,
          };
        }
        return item;
      });
    }
  }

  return transformedData;
}

/**
 * Ensure we have data points at exactly 0%, 20%, 40%, 60%, 80%, 100%
 */
function ensureKeyPercentiles(
  data: ProcessedDataRecord[],
): ProcessedDataRecord[] {
  if (!data.length) return [];

  // Sort data once by percentile (ascending order)
  const sortedData = [...data].sort((a, b) => a.entityPercentile - b.entityPercentile);
  const result: ProcessedDataRecord[] = [];
  
  // Process key percentiles in order (they're already sorted)
  let dataIndex = 0;
  
  // Handle first data point or create 0% point if needed
  if (sortedData[0].entityPercentile > PERCENTILE_EPSILON) {
    // We need to create a 0% point
    const entityKey = Object.keys(sortedData[0])[0];
    result.push({
      ...sortedData[0],
      entityPercentile: 0,
      cumulativeMetricPct: 0,
      cumulativeMetric: 0,
      [entityKey]: null,
    });
  }
  
  // Process all data points and insert key percentiles where needed
  for (const targetPercentile of KEY_PERCENTILES) {
    // Skip 0% as we've already handled it
    if (targetPercentile === 0) continue;
    
    // Add all data points that come before current target percentile
    while (dataIndex < sortedData.length && 
           sortedData[dataIndex].entityPercentile < targetPercentile - PERCENTILE_EPSILON) {
      result.push(sortedData[dataIndex++]);
    }
    
    // Check if we have an exact match for the current percentile
    if (dataIndex < sortedData.length && 
        Math.abs(sortedData[dataIndex].entityPercentile - targetPercentile) < PERCENTILE_EPSILON) {
      // We have a matching point, add it
      result.push(sortedData[dataIndex++]);
    } else if (result.length > 0 && dataIndex < sortedData.length) {
      // Need to interpolate - we have points before and after
      const before = result[result.length - 1];
      const after = sortedData[dataIndex];
      
      // Only interpolate if we have valid before/after points
      const ratio = (targetPercentile - before.entityPercentile) / 
                  (after.entityPercentile - before.entityPercentile);
      
      // Create interpolated point with minimal cloning
      const interpolated = { ...before };
      interpolated.entityPercentile = targetPercentile;
      interpolated.cumulativeMetricPct = before.cumulativeMetricPct + 
        ratio * (after.cumulativeMetricPct - before.cumulativeMetricPct);
      interpolated.cumulativeMetric = before.cumulativeMetric + 
        ratio * (after.cumulativeMetric - before.cumulativeMetric);
      
      result.push(interpolated);
    }
  }
  
  // Add any remaining data points
  while (dataIndex < sortedData.length) {
    result.push(sortedData[dataIndex++]);
  }
  
  return result;
}

/**
 * Calculate metric ranges for determining axis scaling
 */
function calculateMetricRanges(
  data: ProcessedDataRecord[],
  metricColumns: string[],
): MetricRange[] {
  return metricColumns.map((metric, index) => {
    const values = data
      .map(item => item[metric])
      .filter(val => val !== null && val !== undefined) as number[];
    const min = Math.min(...values);
    const max = Math.max(...values);
    return {
      min,
      max,
      range: max - min,
      index,
    };
  });
}

/**
 * Determine if metrics should be displayed on different axes based on their scale
 */
function detectMetricsForSecondaryAxis(
  data: ProcessedDataRecord[],
  metricColumns: string[],
  chartType: WhaleChartType,
): number[] {
  if (metricColumns.length <= 1 || chartType === WhaleChartType.Whale) {
    return []; // No need for secondary axis with only one metric
  }

  // Calculate ranges for each metric
  const ranges = calculateMetricRanges(data, metricColumns);

  // Sort by range (largest first)
  ranges.sort((a, b) => b.range - a.range);

  const secondaryAxisIndices: number[] = [];

  if (ranges.length >= 2) {
    const largestRange = ranges[0];

    for (let i = 1; i < ranges.length; i += 1) {
      const currentRange = ranges[i];

      // Calculate range difference ratio
      const rangeDifference = largestRange.range / currentRange.range;

      // Calculate magnitude difference
      const largestMagnitude = Math.max(
        Math.abs(largestRange.max),
        Math.abs(largestRange.min),
      );
      const currentMagnitude = Math.max(
        Math.abs(currentRange.max),
        Math.abs(currentRange.min),
      );
      const magnitudeDifference = largestMagnitude / currentMagnitude;

      // Determine if this metric should use secondary axis
      if (
        rangeDifference > SCALE_DIFFERENCE_THRESHOLD ||
        magnitudeDifference > SCALE_DIFFERENCE_THRESHOLD ||
        magnitudeDifference < SCALE_MAGNITUDE_MIN_THRESHOLD
      ) {
        secondaryAxisIndices.push(currentRange.index);
      }
    }
  }

  return secondaryAxisIndices;
}

// ===== Chart Option Creators =====
/**
 * Create chart title options
 */
function createTitleOptions(
  headerText?: string,
  boldText?: boolean,
  headerFontSize?: string,
  themeColors?: SupersetTheme['colors'],
) {
  return {
    text: headerText,
    left: 'center',
    textStyle: {
      color: themeColors?.text?.label,
      fontWeight: boldText ? 'bold' : 'normal',
      fontSize: getFontSize(headerFontSize || 'm'),
    },
  };
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
  secondaryMetricIndices: number[] = [],
  useSecondaryAxis = false,
) {
  // Format label based on chart type
  const formatter = chartType === WhaleChartType.Whale ? '{value}%' : '{value}';

  // Primary Y axis
  const primaryAxis = {
    type: 'value',
    nameLocation: 'middle',
    nameGap: 52,
    nameTextStyle: { color: themeColors?.text?.label },
    min: 0,
    axisLabel: {
      formatter,
      color: themeColors?.text?.label,
    },
    splitLine: {
      show: true,
      lineStyle: { type: 'dashed' },
    },
  };

  // If we don't need a secondary axis, just return the primary
  if (!useSecondaryAxis || secondaryMetricIndices.length === 0) {
    return [primaryAxis];
  }

  // Secondary Y axis
  const secondaryAxis = {
    ...primaryAxis,
    position: 'right',
    splitLine: { show: false },
  };

  return [primaryAxis, secondaryAxis];
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
  secondaryMetricIndices: number[] = [],
): any[] {
  const series = [];
  const primaryMetricLabel = getMetricLabel(metrics[0]);

  // Filter out artificial data points (ones without a valid entity name)
  const filteredData = processedData.filter(item => item[columns]);

  // Primary metric series
  series.push({
    name: primaryMetricLabel,
    type: 'line',
    yAxisIndex: 0,
    smooth: 0.7,
    symbol: 'circle',
    lineStyle: {
      width: 1,
      color: colorScale(primaryMetricLabel),
    },
    itemStyle: {
      color: colorScale(primaryMetricLabel),
    },
    data: filteredData.map(item => ({
      name: item[columns] ? String(item[columns]) : '',
      value: [item.entityPercentile, item.cumulativeMetricPct],
    })),
    areaStyle: { opacity: 0.8 },
  });

  // Add secondary metrics if available
  if (metrics.length > 1) {
    for (let i = 1; i < metrics.length; i += 1) {
      const metricLabel = getMetricLabel(metrics[i]);
      const metricColor = colorScale(metricLabel);
      const yAxisIndex = secondaryMetricIndices.includes(i) ? 1 : 0;

      series.push({
        name: metricLabel,
        type: 'line',
        areaStyle: { opacity: 0.7 },
        yAxisIndex,
        smooth: 0.7,
        symbol: 'circle',
        lineStyle: {
          width: 1,
          color: metricColor,
        },
        itemStyle: {
          color: metricColor,
        },
        data: filteredData.map(item => ({
          name: item[columns] ? String(item[columns]) : '',
          value: [
            item.entityPercentile,
            item[`${metricLabel}_cumulativeMetricPct`] || 0,
          ],
        })),
      });
    }
  }

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
  secondaryMetricIndices: number[] = [],
): any[] {
  const series = [];
  const primaryMetricLabel = getMetricLabel(metrics[0]);

  // Filter out artificial data points (ones without a valid entity name)
  const filteredData = processedData.filter(item => item[columns]);

  // Primary metric series
  series.push({
    name: primaryMetricLabel,
    type: 'bar',
    yAxisIndex: 0,
    itemStyle: {
      color: colorScale(primaryMetricLabel),
    },
    data: filteredData.map(item => ({
      name: item[columns] ? String(item[columns]) : '',
      value: [item[columns], item[primaryMetricLabel]], // Use raw value
    })),
  });

  // Add secondary metrics if available
  if (metrics.length > 1) {
    for (let i = 1; i < metrics.length; i += 1) {
      const metricLabel = getMetricLabel(metrics[i]);
      const metricColor = colorScale(metricLabel);
      const yAxisIndex = secondaryMetricIndices.includes(i) ? 1 : 0;

      series.push({
        name: metricLabel,
        type: 'bar',
        yAxisIndex,
        itemStyle: {
          color: metricColor,
        },
        data: filteredData.map(item => ({
          name: item[columns] ? String(item[columns]) : '',
          value: [
            item[columns],
            item[metricLabel], // Use raw value
          ],
        })),
      });
    }
  }

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
  secondaryMetricIndices: number[] = [],
): any[] {
  if (chartType === WhaleChartType.Whale) {
    return createWhaleChartSeries(
      processedData,
      columns,
      metrics,
      colors,
      showPareto,
      colorScale,
      secondaryMetricIndices,
    );
  }

  return createBarChartSeries(
    processedData,
    columns,
    metrics,
    colorScale,
    secondaryMetricIndices,
  );
}

/**
 * Create tooltip configuration with optimized processing
 */
function createTooltip(
  chartType: WhaleChartType,
  tooltipOnlyMetrics: QueryFormMetric[] = [],
  processedData: ProcessedDataRecord[],
) {
  return {
    trigger: 'axis',
    formatter: (params: TooltipParam[]) => {
      const firstParam = params[0];
      const entityName = firstParam.data.name ?? 'N/A';
      const formatter = getNumberFormatter(',.1f');
      const dataIndex = firstParam.dataIndex;
      
      // Pre-calculate values for frequently accessed conditions
      const isWhaleChart = chartType === WhaleChartType.Whale;
      const hasValidDataIndex = dataIndex !== undefined;
      const valueHasSuffix = isWhaleChart ? '%' : '';
      
      // Create tooltip rows array
      const rows: string[][] = [];
      
      // Add rank information
      rows.push([
        'Rank', 
        hasValidDataIndex && (!isWhaleChart || entityName !== '') 
          ? `${dataIndex + 1}` 
          : 'N/A'
      ]);
      
      // Add percentile row for whale chart type
      if (isWhaleChart) {
        rows.push(['Percentile', `${formatter(firstParam.value[0])}%`]);
      }
      
      // Add series data rows
      for (const param of params) {
        // Skip Pareto reference line in whale chart
        if (isWhaleChart && param.seriesName === PARETO_REFERENCE_LINE_NAME) {
          continue;
        }
        
        rows.push([
          param.seriesName, 
          `${formatter(param.value[1])}${valueHasSuffix}`
        ]);
      }
      
      // Add tooltip-only metrics if applicable
      if (tooltipOnlyMetrics.length > 0 && hasValidDataIndex) {
        const record = processedData[dataIndex];
        
        if (record) {
          for (const metric of tooltipOnlyMetrics) {
            const metricLabel = getMetricLabel(metric);
            const value = record[metricLabel];
            
            if (value !== undefined && value !== null) {
              rows.push([
                metricLabel, 
                typeof value === 'number' ? formatter(value) : String(value)
              ]);
            }
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
      height: 20,
      bottom: 0,
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
  headerText?: string,
  boldText?: boolean,
  headerFontSize?: string,
  showPareto?: boolean,
  showValueOnHover?: boolean,
  colorScale?: any,
  colors?: ChartColors,
  themeColors?: SupersetTheme['colors'],
  secondaryMetricIndices?: number[],
  useSecondaryAxis?: boolean,
  zoomable?: boolean,
  tooltipOnlyMetrics?: QueryFormMetric[], // Include tooltip-only metrics
): EChartsCoreOption {
  return {
    title: createTitleOptions(
      headerText,
      boldText,
      headerFontSize,
      themeColors,
    ),
    tooltip: showValueOnHover
      ? createTooltip(chartType, tooltipOnlyMetrics, processedData)
      : { show: false },
    xAxis: createXAxisOptions(chartType),
    yAxis: createYAxisOptions(
      metrics,
      chartType,
      themeColors,
      secondaryMetricIndices,
      useSecondaryAxis,
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
      colors || getChartColors(),
      !!showPareto,
      colorScale,
      secondaryMetricIndices,
    ),
    grid: {
      left: '5%',
      right: '5%',
      bottom: '5%',
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
    boldText,
    headerFontSize,
    headerText,
    metrics = [],
    tooltipOnlyMetrics = [], // Extract tooltip-only metrics
    columns = '',
    chartType = WhaleChartType.Whale,
    showPareto = false,
    showValueOnHover = true,
    autoDetectYAxisScale = true,
    colorScheme,
    groupby = [columns],
    zoomable = false,
  } = formData;

  // Get colors and color scale
  const colors = getChartColors(theme?.colors);
  const colorScale = CategoricalColorNamespace.getScale(colorScheme as string);

  // Process data
  const { data = [] } = queriesData?.[0] || {};
  const refs: Refs = {};
  
  // Process metrics and tooltip-only metrics
  const metricColumns = metrics.map((m: QueryFormMetric) => getMetricLabel(m));
  const tooltipMetricColumns = tooltipOnlyMetrics.map((m: QueryFormMetric) => getMetricLabel(m));
  const allMetricColumns = [...metricColumns, ...tooltipMetricColumns];
  const primaryMetric = metricColumns[0];

  // Transform data with multiple metrics support (including tooltip-only metrics)
  const transformedData = multiMetricTransform(
    data,
    allMetricColumns,
    primaryMetric,
  );

  // Ensure we have points at key percentiles
  const processedData = ensureKeyPercentiles(transformedData);

  // Detect metrics for secondary axis if auto-detection is enabled
  // Note: We only consider visible metrics for axis detection, not tooltip-only metrics
  const secondaryMetricIndices = autoDetectYAxisScale
    ? detectMetricsForSecondaryAxis(processedData, metricColumns, chartType)
    : [];

  // Build the full ECharts options
  const echartOptions = buildEChartOptions(
    chartType,
    processedData,
    columns,
    metrics,
    headerText,
    boldText,
    headerFontSize,
    showPareto,
    showValueOnHover,
    colorScale,
    colors,
    theme?.colors,
    secondaryMetricIndices,
    autoDetectYAxisScale && secondaryMetricIndices.length > 0,
    zoomable,
    tooltipOnlyMetrics, // Pass tooltip-only metrics to ECharts options builder
  );

  // Cross-filtering support
  const groupbyLabels = groupby.map(getColumnLabel);
  const coltypeMapping = getColtypesMapping(queriesData[0]);
  const labelMap = createLabelMap(data, groupbyLabels, coltypeMapping);
  const { setDataMask = () => {}, onContextMenu } = hooks;
  const selectedValues = processSelectedValues(filterState, transformedData);

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
    boldText,
    headerFontSize,
    headerText,
    emitCrossFilters,
    groupby,
  };
}
