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
  DataRecord,
  DataRecordValue,
  getColumnLabel,
  getMetricLabel,
  getNumberFormatter,
  getTimeFormatter,
  getValueFormatter,
  isAdhocMetricSimple,
  QueryFormMetric,
  NumberFormats,
  tooltipHtml,
  ValueFormatter,
} from '@superset-ui/core';
import { t } from '@apache-superset/core/translation';
import type { EChartsCoreOption } from 'echarts/core';
import type { TreemapSeriesOption } from 'echarts/charts';
import type { TreemapSeriesNodeItemOption } from 'echarts/types/src/chart/treemap/TreemapSeries';
import { NULL_STRING } from '../constants';
import { Refs } from '../types';
import { getDefaultTooltip } from '../utils/tooltip';
import { formatSeriesName, getColtypesMapping } from '../utils/series';
import {
  DEFAULT_FORM_DATA,
  getRootCauseTreemapHierarchy,
  PerformanceAggregation,
  RootCauseMetricMap,
  RootCauseTreeNode,
  RootCauseTreemapCallbackDataParams,
  RootCauseTreemapChartProps,
  RootCauseTreemapFormData,
  RootCauseTreemapLabelType,
  RootCauseTreemapTransformedProps,
} from './types';

const BORDER_COLOR = '#ffffff';
const BORDER_RADIUS = 2;
const BLOCK_BORDER_WIDTH = 1;
const GAP_WIDTH = 4;
const PARENT_PADDING = 8;
const ROOT_BORDER_WIDTH = 4;
const TITLE_BORDER_WIDTH = 2;
const COLOR_NEGATIVE = '#a50f15';
const COLOR_NEUTRAL = '#d6d3c8';
const COLOR_POSITIVE = '#0b7d3b';
const LEGEND_BAR_WIDTH = 34;
const LEGEND_LABEL_OFFSET = 40;
const LEGEND_TOP = 36;
const LEGEND_TITLE_HEIGHT = 54;

function hexToRgb(hex: string) {
  const normalized = hex.replace('#', '');
  return {
    r: parseInt(normalized.slice(0, 2), 16),
    g: parseInt(normalized.slice(2, 4), 16),
    b: parseInt(normalized.slice(4, 6), 16),
  };
}

function interpolateColor(
  startColor: string,
  endColor: string,
  percent: number,
) {
  const start = hexToRgb(startColor);
  const end = hexToRgb(endColor);
  const ratio = Math.min(Math.max(percent, 0), 1);
  const r = Math.round(start.r + (end.r - start.r) * ratio);
  const g = Math.round(start.g + (end.g - start.g) * ratio);
  const b = Math.round(start.b + (end.b - start.b) * ratio);
  return `rgb(${r}, ${g}, ${b})`;
}

function getPerformanceColor(value: number, min: number, max: number) {
  if (value < 0) {
    return interpolateColor(
      COLOR_NEGATIVE,
      COLOR_NEUTRAL,
      (value - min) / (0 - min || 1),
    );
  }
  return interpolateColor(COLOR_NEUTRAL, COLOR_POSITIVE, value / (max || 1));
}

function getLabelColor({
  darkTextColor,
  lightTextColor,
  max,
  min,
  value,
}: {
  darkTextColor: string;
  lightTextColor: string;
  max: number;
  min: number;
  value: number;
}) {
  const strongestColorValue = Math.max(Math.abs(min), Math.abs(max));
  if (!strongestColorValue) {
    return darkTextColor;
  }
  return Math.abs(value) / strongestColorValue >= 0.72
    ? lightTextColor
    : darkTextColor;
}

function toNumber(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

function getMetricValue(datum: DataRecord, metricLabel: string): number {
  return toNumber(datum[metricLabel]);
}

function cleanMetricLabel(label: string) {
  return label
    .replace(/^[A-Z_][A-Z0-9_]*\(([^()]+)\)$/i, '$1')
    .replace(/^["'`]|["'`]$/g, '');
}

function getDisplayMetricLabel({
  metric,
  metricLabel,
  verboseMap,
}: {
  metric?: QueryFormMetric;
  metricLabel: string;
  verboseMap: Record<string, string>;
}) {
  const verboseLabel = verboseMap[metricLabel];
  if (verboseLabel) {
    return cleanMetricLabel(verboseLabel);
  }
  if (metric && isAdhocMetricSimple(metric)) {
    return cleanMetricLabel(
      metric.column.columnName || metric.column.column_name || metricLabel,
    );
  }
  return cleanMetricLabel(metricLabel);
}

function getTileMetricLabel(label: string) {
  return label
    .trim()
    .replace(/_/g, ' ')
    .replace(/\b\w/g, character => character.toUpperCase());
}

function getGroupedRows(data: DataRecord[], column: string) {
  return data.reduce((acc, datum) => {
    const key = datum[column] ?? NULL_STRING;
    const mapKey = String(key);
    if (!acc.has(mapKey)) {
      acc.set(mapKey, { name: key, rows: [] });
    }
    acc.get(mapKey)!.rows.push(datum);
    return acc;
  }, new Map<string, { name: DataRecordValue; rows: DataRecord[] }>());
}

function aggregatePerformance(
  nodes: RootCauseTreeNode[],
  aggregation: PerformanceAggregation,
) {
  if (!nodes.length) {
    return 0;
  }
  if (aggregation === PerformanceAggregation.Sum) {
    return nodes.reduce((sum, node) => sum + node.performance, 0);
  }
  if (aggregation === PerformanceAggregation.Average) {
    return (
      nodes.reduce((sum, node) => sum + node.performance, 0) / nodes.length
    );
  }
  const totalWeight = nodes.reduce((sum, node) => sum + node.areaValue, 0);
  if (!totalWeight) {
    return (
      nodes.reduce((sum, node) => sum + node.performance, 0) / nodes.length
    );
  }
  return (
    nodes.reduce(
      (sum, node) => sum + node.performance * Math.max(node.areaValue, 0),
      0,
    ) / totalWeight
  );
}

function sumMetrics(
  rows: DataRecord[],
  metricLabels: string[],
): RootCauseMetricMap {
  return metricLabels.reduce<RootCauseMetricMap>((acc, metricLabel) => {
    acc[metricLabel] = rows.reduce(
      (sum, datum) => sum + getMetricValue(datum, metricLabel),
      0,
    );
    return acc;
  }, {});
}

function buildTree({
  data,
  columns,
  contributionMetricLabel,
  performanceMetricLabel,
  tooltipMetricLabels,
  aggregation,
  dateFormat,
  numberFormatter,
  coltypeMapping,
  pathRecords = [],
}: {
  data: DataRecord[];
  columns: string[];
  contributionMetricLabel: string;
  performanceMetricLabel: string;
  tooltipMetricLabels: string[];
  aggregation: PerformanceAggregation;
  dateFormat: string;
  numberFormatter: ValueFormatter;
  coltypeMapping: Record<string, number>;
  pathRecords?: DataRecordValue[];
}): RootCauseTreeNode[] {
  const [column, ...restColumns] = columns;
  if (!column) {
    return [];
  }

  return Array.from(getGroupedRows(data, column).values()).map(
    ({ name, rows }) => {
      const formattedName = formatSeriesName(name, {
        numberFormatter,
        timeFormatter: getTimeFormatter(dateFormat),
        ...(coltypeMapping[column] && {
          coltype: coltypeMapping[column],
        }),
      });
      const records = [...pathRecords, name];
      if (restColumns.length) {
        const children = buildTree({
          data: rows,
          columns: restColumns,
          contributionMetricLabel,
          performanceMetricLabel,
          tooltipMetricLabels,
          aggregation,
          dateFormat,
          numberFormatter,
          coltypeMapping,
          pathRecords: records,
        });
        const value = children.reduce((sum, child) => sum + child.value, 0);
        const areaValue = children.reduce(
          (sum, child) => sum + child.areaValue,
          0,
        );
        const metrics = tooltipMetricLabels.reduce<RootCauseMetricMap>(
          (acc, metricLabel) => {
            acc[metricLabel] = children.reduce(
              (sum, child) => sum + (child.metrics[metricLabel] || 0),
              0,
            );
            return acc;
          },
          {},
        );
        return {
          name,
          formattedName,
          groupBy: column,
          records,
          value,
          areaValue,
          performance: aggregatePerformance(children, aggregation),
          metrics,
          rowCount: children.reduce((sum, child) => sum + child.rowCount, 0),
          children,
        };
      }

      const value = rows.reduce(
        (sum, datum) => sum + getMetricValue(datum, contributionMetricLabel),
        0,
      );
      const areaValue = Math.abs(value);
      const performanceNodes = rows.map(datum => ({
        name,
        formattedName,
        groupBy: column,
        records,
        value: getMetricValue(datum, contributionMetricLabel),
        areaValue: Math.abs(getMetricValue(datum, contributionMetricLabel)),
        performance: getMetricValue(datum, performanceMetricLabel),
        metrics: {},
        rowCount: 1,
      }));
      return {
        name,
        formattedName,
        groupBy: column,
        records,
        value,
        areaValue,
        performance: aggregatePerformance(performanceNodes, aggregation),
        metrics: sumMetrics(rows, tooltipMetricLabels),
        rowCount: rows.length,
      };
    },
  );
}

function quantile(sortedValues: number[], q: number) {
  if (!sortedValues.length) {
    return 0;
  }
  const pos = (sortedValues.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  if (sortedValues[base + 1] !== undefined) {
    return (
      sortedValues[base] + rest * (sortedValues[base + 1] - sortedValues[base])
    );
  }
  return sortedValues[base];
}

function getIqrBounds(values: number[]): [number, number] | undefined {
  if (values.length <= 3) {
    return undefined;
  }
  const sortedValues = [...values].sort((a, b) => a - b);
  const q1 = quantile(sortedValues, 0.25);
  const q3 = quantile(sortedValues, 0.75);
  const iqr = q3 - q1;
  return [q1 - iqr * 1.5, q3 + iqr * 1.5];
}

function getPerformanceExtent(nodes: RootCauseTreeNode[]) {
  const values: number[] = [];
  const collect = (treeNodes: RootCauseTreeNode[]) => {
    treeNodes.forEach(node => {
      if (Number.isFinite(node.performance)) {
        values.push(node.performance);
      }
      if (node.children?.length) {
        collect(node.children);
      }
    });
  };
  collect(nodes);
  if (!values.length) {
    return [-1, 1];
  }
  values.sort((a, b) => a - b);
  return [values[0], values[values.length - 1]];
}

function getSymmetricExtent(min: number, max: number) {
  const absoluteMax = Math.max(Math.abs(min), Math.abs(max));
  if (!absoluteMax) {
    return [-1, 1];
  }
  return [-absoluteMax, absoluteMax];
}

export function formatLabel({
  params,
  contributionDisplayLabel,
  contributionFormatter,
  isLeaf,
  labelType,
  performanceDisplayLabel,
  performanceFormatter,
}: {
  params: RootCauseTreemapCallbackDataParams;
  contributionDisplayLabel: string;
  contributionFormatter: ValueFormatter;
  isLeaf: boolean;
  labelType: RootCauseTreemapLabelType;
  performanceDisplayLabel: string;
  performanceFormatter: ValueFormatter;
}) {
  const custom = params.data?.custom;
  const name = params.name || '';
  const formattedName = isLeaf ? `{leafHeading|${name}}` : name;
  if (!custom) {
    return formattedName;
  }
  if (labelType === RootCauseTreemapLabelType.Name) {
    return formattedName;
  }
  if (labelType === RootCauseTreemapLabelType.NameValue) {
    return `${formattedName}\n${contributionFormatter(custom.value)}`;
  }
  if (custom.contributionShare < 0.005) {
    return formattedName;
  }
  return [
    formattedName,
    `${getTileMetricLabel(performanceDisplayLabel)}: ${performanceFormatter(
      custom.performance,
    )}`,
    `${getTileMetricLabel(contributionDisplayLabel)}: ${contributionFormatter(
      custom.value,
    )}`,
  ].join('\n');
}

export function formatTooltip({
  contributionFormatter,
  contributionMetricLabel,
  params,
  performanceFormatter,
  performanceMetricLabel,
  tooltipMetricFormatter,
}: {
  contributionFormatter: ValueFormatter;
  contributionMetricLabel: string;
  params: RootCauseTreemapCallbackDataParams;
  performanceFormatter: ValueFormatter;
  performanceMetricLabel: string;
  tooltipMetricFormatter: ValueFormatter;
}) {
  const custom = params.data?.custom;
  if (!custom) {
    return '';
  }
  const percentFormatter = getNumberFormatter(NumberFormats.PERCENT_2_POINT);
  const rows = [
    [contributionMetricLabel, contributionFormatter(custom.value)],
    [performanceMetricLabel, performanceFormatter(custom.performance)],
    [t('% of total'), percentFormatter(custom.contributionShare)],
  ];
  if (custom.parentShare !== undefined) {
    rows.push([t('% of parent'), percentFormatter(custom.parentShare)]);
  }
  custom.metricLabels.forEach(metricLabel => {
    rows.push([
      metricLabel,
      tooltipMetricFormatter(custom.metrics[metricLabel]),
    ]);
  });
  return tooltipHtml(rows, custom.formattedName);
}

export default function transformProps(
  chartProps: RootCauseTreemapChartProps,
): RootCauseTreemapTransformedProps {
  const {
    datasource,
    emitCrossFilters,
    filterState,
    formData,
    height,
    hooks,
    inContextMenu,
    queriesData,
    theme,
    width,
  } = chartProps;
  const { data = [] } = queriesData[0];
  const {
    columnFormats = {},
    currencyFormats = {},
    verboseMap = {},
  } = datasource;
  const { setDataMask = () => {}, onContextMenu } = hooks;
  const coltypeMapping = getColtypesMapping(queriesData[0]);
  const textColor = theme.colorText;
  const inverseTextColor = theme.colorTextLightSolid;
  const breadcrumbBackgroundColor = theme.colorBgLayout;
  const refs: Refs = {};
  const {
    colorMax,
    colorMin,
    columns = [],
    currencyFormat,
    dateFormat,
    excludeNegativeContribution,
    hierarchyPreset,
    labelPosition,
    labelType,
    metric,
    numberFormat,
    performanceAggregation,
    performanceFormat,
    removePerformanceOutliers,
    secondaryMetric,
    showLabels,
    showUpperLabels,
    tooltipMetrics = [],
    visibleMin,
  }: RootCauseTreemapFormData = {
    ...DEFAULT_FORM_DATA,
    ...formData,
  };

  const contributionMetricLabel = getMetricLabel(metric || '');
  const performanceMetricLabel = getMetricLabel(secondaryMetric || '');
  const contributionMetricDisplayLabel = getDisplayMetricLabel({
    metric,
    metricLabel: contributionMetricLabel,
    verboseMap,
  });
  const performanceMetricDisplayLabel = getDisplayMetricLabel({
    metric: secondaryMetric,
    metricLabel: performanceMetricLabel,
    verboseMap,
  });
  const tooltipMetricLabels = tooltipMetrics.map(getMetricLabel);
  const hierarchyColumns = getRootCauseTreemapHierarchy({
    columns,
    hierarchyPreset,
  });
  const columnLabels = hierarchyColumns.map(getColumnLabel);
  const contributionFormatter = getValueFormatter(
    metric,
    currencyFormats,
    columnFormats,
    numberFormat,
    currencyFormat,
  );
  const performanceFormatter = getNumberFormatter(performanceFormat);
  const legendFormatter = getNumberFormatter('.1f');
  const tooltipMetricFormatter = getNumberFormatter(numberFormat);
  const contributionFilteredData = excludeNegativeContribution
    ? data.filter(datum => getMetricValue(datum, contributionMetricLabel) >= 0)
    : data;
  const performanceValues = contributionFilteredData
    .map(datum => getMetricValue(datum, performanceMetricLabel))
    .filter(Number.isFinite);
  const outlierBounds = removePerformanceOutliers
    ? getIqrBounds(performanceValues)
    : undefined;
  const filteredData = outlierBounds
    ? contributionFilteredData.filter(datum => {
        const performanceValue = getMetricValue(datum, performanceMetricLabel);
        return (
          performanceValue >= outlierBounds[0] &&
          performanceValue <= outlierBounds[1]
        );
      })
    : contributionFilteredData;
  const treeData = buildTree({
    data: filteredData,
    columns: columnLabels,
    contributionMetricLabel,
    performanceMetricLabel,
    tooltipMetricLabels,
    aggregation: performanceAggregation,
    dateFormat,
    numberFormatter: getNumberFormatter(numberFormat),
    coltypeMapping,
  });
  const totalAreaValue = treeData.reduce(
    (sum, node) => sum + node.areaValue,
    0,
  );
  const [domainMin, domainMax] = getPerformanceExtent(treeData);
  const [autoMin, autoMax] = getSymmetricExtent(domainMin, domainMax);
  const visualMin =
    colorMin === null || colorMin === '' ? autoMin : toNumber(colorMin);
  const visualMax =
    colorMax === null || colorMax === '' ? autoMax : toNumber(colorMax);
  const labelMap = new Map<string, string[]>();
  const rawValueMap = new Map<string, DataRecordValue[]>();

  const traverse = (
    nodes: RootCauseTreeNode[],
    path: string[] = [],
    parentAreaValue?: number,
  ): TreemapSeriesNodeItemOption[] =>
    nodes.map(node => {
      const newPath = [...path, node.formattedName];
      const joinedName = newPath.join(',');
      labelMap.set(joinedName, newPath);
      rawValueMap.set(joinedName, node.records);
      const custom = {
        ...node,
        path: newPath,
        contributionShare: totalAreaValue ? node.areaValue / totalAreaValue : 0,
        parentShare: parentAreaValue
          ? node.areaValue / parentAreaValue
          : undefined,
        metricLabels: tooltipMetricLabels,
      };
      const nodeColor = getPerformanceColor(
        node.performance,
        visualMin,
        visualMax,
      );
      const labelColor = getLabelColor({
        darkTextColor: textColor,
        lightTextColor: inverseTextColor,
        max: visualMax,
        min: visualMin,
        value: node.performance,
      });
      const hasChildren = Boolean(node.children?.length);
      const item: TreemapSeriesNodeItemOption = {
        id: joinedName,
        name: node.formattedName,
        value: [Math.max(node.areaValue, 0), node.performance],
        custom,
        itemStyle: {
          borderColor: hasChildren ? nodeColor : BORDER_COLOR,
          borderWidth: hasChildren ? PARENT_PADDING : BLOCK_BORDER_WIDTH,
          borderRadius: BORDER_RADIUS,
          color: nodeColor,
          gapWidth: GAP_WIDTH,
        },
        label: {
          color: labelColor,
        },
        upperLabel: {
          color: labelColor,
        },
        emphasis: {
          disabled: true,
        },
      } as TreemapSeriesNodeItemOption;
      if (hasChildren) {
        item.children = traverse(node.children || [], newPath, node.areaValue);
      }
      if (
        filterState.selectedValues &&
        !filterState.selectedValues.includes(joinedName)
      ) {
        item.itemStyle = {
          ...item.itemStyle,
          opacity: 0.35,
        };
        item.label = {
          color: `rgba(0, 0, 0, 0.35)`,
        };
      }
      return item;
    });

  const series: TreemapSeriesOption[] = [
    {
      type: 'treemap',
      name: contributionMetricDisplayLabel,
      left: 8,
      top: 8,
      right: 88,
      bottom: 28,
      nodeClick: false,
      roam: false,
      visualDimension: 1,
      animationDurationUpdate: 250,
      breadcrumb: {
        show: true,
        bottom: 0,
        height: 18,
        itemStyle: {
          color: breadcrumbBackgroundColor,
          borderColor: BORDER_COLOR,
          textStyle: {
            color: textColor,
          },
        },
        emphasis: {
          disabled: true,
          itemStyle: {
            color: breadcrumbBackgroundColor,
            borderColor: BORDER_COLOR,
            textStyle: {
              color: textColor,
            },
          },
        },
      },
      visibleMin: toNumber(visibleMin),
      childrenVisibleMin: toNumber(visibleMin),
      label: {
        show: showLabels,
        position: labelPosition,
        formatter: (params: any) =>
          formatLabel({
            params,
            contributionDisplayLabel: contributionMetricDisplayLabel,
            contributionFormatter,
            isLeaf: !params.data?.children?.length,
            performanceDisplayLabel: performanceMetricDisplayLabel,
            performanceFormatter,
            labelType,
          }),
        color: textColor,
        fontSize: 11,
        fontWeight: 400,
        lineHeight: 15,
        overflow: 'truncate',
        padding: [4, 4, 0, 4],
        rich: {
          leafHeading: {
            fontWeight: 700,
          },
        },
      },
      upperLabel: {
        show: showUpperLabels,
        formatter: (params: any) =>
          formatLabel({
            params,
            contributionDisplayLabel: contributionMetricDisplayLabel,
            contributionFormatter,
            isLeaf: false,
            performanceDisplayLabel: performanceMetricDisplayLabel,
            performanceFormatter,
            labelType: RootCauseTreemapLabelType.Name,
          }),
        color: textColor,
        height: 24,
        fontSize: 14,
        fontWeight: 400,
        padding: [4, 4, 0, 4],
      },
      emphasis: {
        disabled: true,
        focus: 'none',
      },
      blur: {
        itemStyle: {
          opacity: 1,
        },
      },
      levels: [
        {
          itemStyle: {
            borderRadius: BORDER_RADIUS,
            borderWidth: ROOT_BORDER_WIDTH,
            gapWidth: GAP_WIDTH,
          },
          upperLabel: {
            show: false,
          },
        },
        {
          itemStyle: {
            borderRadius: BORDER_RADIUS,
            borderWidth: TITLE_BORDER_WIDTH,
            gapWidth: GAP_WIDTH,
          },
        },
      ],
      data: traverse(treeData),
    },
  ];
  const legendHeight = Math.max(240, Math.min(620, height - 110));
  const legendValues = [visualMax, visualMax / 2, 0, visualMin / 2, visualMin];
  const legendY = (value: number) => {
    const domain = visualMax - visualMin || 1;
    return LEGEND_TITLE_HEIGHT + ((visualMax - value) / domain) * legendHeight;
  };

  const echartOptions: EChartsCoreOption = {
    animationThreshold: 2000,
    tooltip: {
      ...getDefaultTooltip(refs),
      show: !inContextMenu,
      trigger: 'item',
      confine: true,
      formatter: (params: any) =>
        formatTooltip({
          params,
          contributionFormatter,
          performanceFormatter,
          tooltipMetricFormatter,
          contributionMetricLabel: contributionMetricDisplayLabel,
          performanceMetricLabel: performanceMetricDisplayLabel,
        }),
    },
    graphic: [
      {
        type: 'group',
        right: 4,
        top: LEGEND_TOP,
        silent: true,
        children: [
          {
            type: 'text',
            left: 0,
            top: 0,
            style: {
              text: t('EP\n(% of sales)'),
              fill: textColor,
              fontSize: 14,
              fontWeight: 400,
              lineHeight: 20,
            },
          },
          {
            type: 'rect',
            left: 0,
            top: LEGEND_TITLE_HEIGHT,
            shape: {
              width: LEGEND_BAR_WIDTH,
              height: legendHeight,
            },
            style: {
              fill: {
                type: 'linear',
                x: 0,
                y: 1,
                x2: 0,
                y2: 0,
                colorStops: [
                  { offset: 0, color: COLOR_NEGATIVE },
                  { offset: 0.5, color: COLOR_NEUTRAL },
                  { offset: 1, color: COLOR_POSITIVE },
                ],
              },
            },
          },
          ...legendValues.map(value => ({
            type: 'text',
            left: LEGEND_LABEL_OFFSET,
            top: legendY(value) - 9,
            style: {
              text: legendFormatter(value * 1000),
              fill: textColor,
              fontSize: 14,
              fontWeight: 400,
            },
          })),
        ],
      },
    ],
    series,
  };

  return {
    formData,
    width,
    height,
    echartOptions,
    setDataMask,
    emitCrossFilters,
    labelMap: Object.fromEntries(rawValueMap),
    groupby: hierarchyColumns,
    selectedValues: filterState.selectedValues || [],
    onContextMenu,
    refs,
    coltypeMapping,
  };
}
