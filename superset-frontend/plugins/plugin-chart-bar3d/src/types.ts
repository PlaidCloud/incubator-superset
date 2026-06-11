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

export type Bar3DFormData = QueryFormData & {
  x_axis: QueryFormColumn;
  y_axis: QueryFormColumn;
  metric: QueryFormMetric;
  colorMode: 'gradient' | 'category';
  colorByAxis: 'x' | 'y';
  color_scheme?: string;
  showVisualMap: boolean;
  showLabel: boolean;
  autoRotate: boolean;
  yAxisFormat?: string;
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

export interface Bar3DChartProps extends ChartProps<Bar3DFormData> {
  queriesData: ChartDataResponseResult[];
  formData: Bar3DFormData;
}

export type Bar3DTransformedProps = {
  echartOptions: EChartsCoreOption;
  formData: Bar3DFormData;
  height: number;
  width: number;
  refs: Refs;
};
