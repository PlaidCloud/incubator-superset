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
  QueryFormData,
  ChartProps,
  QueryFormMetric,
  ChartDataResponseResult,
  PlainObject,
  ContextMenuFilters,
  SetDataMaskHook,
  LegendState,
  FilterState,
  QueryFormColumn,
  HandlerFunction,
  TimeFormatter,
  AxisType,
  DataRecord,
} from '@superset-ui/core';
import { EChartsType, EChartsCoreOption } from 'echarts/core';
import { Ref, RefObject } from 'react';

export enum WhaleChartType {
  Whale = 'whale',
  Bar = 'bar',
}

export type EventHandlers = Record<string, { (props: any): void }>;

export enum LegendOrientation {
  Top = 'top',
  Bottom = 'bottom',
  Left = 'left',
  Right = 'right',
}

export enum LegendType {
  Scroll = 'scroll',
  Plain = 'plain',
}

export type LegendFormData = {
  legendMargin: number | null | string;
  legendOrientation: LegendOrientation;
  legendType: LegendType;
  showLegend: boolean;
};

export type Refs = {
  echartRef?: Ref<EchartsHandler>;
  divRef?: RefObject<HTMLDivElement>;
};

export type WhaleFormData = QueryFormData &
  LegendFormData & {
    columns: string;
    metrics: QueryFormMetric[];
    headerText: string;
    headerFontSize: string;
    boldText: boolean;
    // New properties
    chartType: WhaleChartType;
    useSecondaryAxis: boolean;
    autoDetectYAxisScale: boolean;
    secondaryMetricAxis?: number[];
    tooltipOnlyMetrics?: string[]; // List of metrics to only show in tooltip
    showPareto: boolean;
    showValueOnHover: boolean;
  };

export interface ProcessedDataRecord extends DataRecord {
  cumulativeMetric: number;
  metricPct: number;
  cumulativeMetricPct: number;
  entityPercentile: number;
}

export interface EchartsStylesProps {
  height: number;
  width: number;
}

export interface EchartsHandler {
  getEchartInstance: () => EChartsType | undefined;
}

// Props for Echarts component
export interface EchartsProps {
  height: number;
  width: number;
  echartOptions: any;
  eventHandlers?: EventHandlers;
  zrEventHandlers?: EventHandlers;
  selectedValues?: Record<string, string>;
  refs?: Record<string, any>;
}

interface BaseChartProps<T extends PlainObject> extends ChartProps<T> {
  queriesData: ChartDataResponseResult[];
}

// ChartProps for this plugin
export interface SupersetPluginChartWhaleProps
  extends BaseChartProps<WhaleFormData> {
  // These are optional additions to the props
  queriesData: ChartDataResponseResult[];
  formData: WhaleFormData;
}

export interface BaseTransformedProps<F> {
  echartOptions: EChartsCoreOption;
  formData: F;
  height: number;
  onContextMenu?: (
    clientX: number,
    clientY: number,
    filters?: ContextMenuFilters,
  ) => void;
  setDataMask?: SetDataMaskHook;
  onLegendStateChanged?: (state: LegendState) => void;
  filterState?: FilterState;
  refs: Refs;
  width: number;
  emitCrossFilters?: boolean;
  coltypeMapping?: Record<string, number>;
}

export type CrossFilterTransformedProps = {
  groupby: QueryFormColumn[];
  labelMap: Record<string, string[]>;
  setControlValue?: HandlerFunction;
  setDataMask: SetDataMaskHook;
  selectedValues: Record<number, string>;
  emitCrossFilters?: boolean;
};

export type ContextMenuTransformedProps = {
  onContextMenu?: (
    clientX: number,
    clientY: number,
    filters?: ContextMenuFilters,
  ) => void;
  setDataMask?: SetDataMaskHook;
};

export declare type OptionName = string | number;

export type WhaleChartTransformedProps = BaseTransformedProps<WhaleFormData> &
  ContextMenuTransformedProps &
  CrossFilterTransformedProps & {
    data: ProcessedDataRecord[];
    legendData?: OptionName[];
    boldText: boolean;
    headerFontSize: string;
    headerText: string;
    xValueFormatter?: TimeFormatter | StringConstructor;
    xAxis?: {
      label: string;
      type: AxisType;
    };
    onFocusedSeries?: (series: string | null) => void;
  };

export interface ChartColors {
  primary: string;
  areaTop: string;
  areaBottom: string;
  secondary: string;
  pareto: string;
}

export interface MetricRange {
  min: number;
  max: number;
  range: number;
  index: number;
}

export interface TooltipParam {
  seriesName: string;
  value: [number, number];
  data: {
    name?: string;
  };
  dataIndex: number;
}

export interface AxisOptions {
  type: 'value' | 'category';
  nameLocation: string;
  nameGap: number;
  [key: string]: any; // For additional properties
}
