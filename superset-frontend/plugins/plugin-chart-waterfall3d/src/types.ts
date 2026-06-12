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
  RgbaColor,
} from '@superset-ui/core';
import { EChartsType, EChartsCoreOption } from 'echarts/core';
import { Ref, RefObject } from 'react';

export type Waterfall3DFormData = QueryFormData & {
  // Steps of the bridge along the X axis (e.g. cost/activity leaves, margin stages).
  stepColumn: QueryFormColumn;
  // Third dimension placed on the depth (Y) axis — one waterfall per value.
  seriesColumn: QueryFormColumn;
  // Metric whose signed increments build the bridge.
  metric: QueryFormMetric;
  showTotal: boolean;
  totalLabel?: string;
  showConnectors: boolean;
  stickWidth?: number;
  increaseColor: RgbaColor;
  decreaseColor: RgbaColor;
  totalColor: RgbaColor;
  autoRotate: boolean;
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

export interface Waterfall3DChartProps extends ChartProps<Waterfall3DFormData> {
  queriesData: ChartDataResponseResult[];
  formData: Waterfall3DFormData;
}

export type Waterfall3DTransformedProps = {
  echartOptions: EChartsCoreOption;
  formData: Waterfall3DFormData;
  height: number;
  width: number;
  refs: Refs;
};

// One bridge step for a given series category.
export interface WaterfallStep {
  step: string;
  base: number;
  top: number;
  value: number;
  isTotal: boolean;
}
