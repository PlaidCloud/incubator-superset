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
  ChartDataResponseResult,
  ChartProps,
  QueryFormColumn,
  QueryFormData,
  QueryFormMetric,
} from '@superset-ui/core';
import { EChartsType, EChartsCoreOption } from 'echarts/core';
import { Ref, RefObject } from 'react';

export type Whale3DDisplayMode = 'ribbons' | 'surface';
export type Whale3DColorMode = 'gradient' | 'category';
export type Whale3DZMode = 'percent' | 'absolute';

export type Whale3DFormData = QueryFormData & {
  // Entity ranked along the X axis (e.g. customer / product).
  entityColumn: QueryFormColumn;
  // Third dimension placed on the depth (Y) axis — one whale curve per value.
  seriesColumn: QueryFormColumn;
  // Metric accumulated into the curve height (Z).
  metric: QueryFormMetric;
  displayMode: Whale3DDisplayMode;
  zMode: Whale3DZMode;
  colorMode: Whale3DColorMode;
  color_scheme?: string;
  showVisualMap: boolean;
  showPareto: boolean;
  fillCurves: boolean;
  fillOpacity?: number;
  autoRotate: boolean;
  gridResolution?: number;
  valueFormat?: string;
  xAxisLabel?: string;
  yAxisLabel?: string;
  zAxisLabel?: string;
  xAxisNameGap?: number;
  yAxisNameGap?: number;
};

export interface EchartsStylesProps {
  height: number;
  width: number;
}

export interface EchartsHandler {
  getEchartInstance: () => EChartsType | undefined;
}

export type EventHandlers = Record<string, { (props: any): void }>;

export type Refs = {
  echartRef?: Ref<EchartsHandler>;
  divRef?: RefObject<HTMLDivElement>;
};

export interface EchartsProps {
  height: number;
  width: number;
  echartOptions: any;
  eventHandlers?: EventHandlers;
  zrEventHandlers?: EventHandlers;
  selectedValues?: Record<string, string>;
  refs?: Record<string, any>;
}

export interface Whale3DChartProps extends ChartProps<Whale3DFormData> {
  queriesData: ChartDataResponseResult[];
  formData: Whale3DFormData;
}

export type Whale3DTransformedProps = {
  echartOptions: EChartsCoreOption;
  formData: Whale3DFormData;
  height: number;
  width: number;
  refs: Refs;
};

// A single point of a cumulative (whale) curve for one series category.
export interface WhalePoint {
  percentile: number;
  z: number;
  cumulative: number;
  name: string;
}
