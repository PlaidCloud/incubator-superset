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
import { ChartProps, QueryFormData, QueryFormMetric } from '@superset-ui/core';
import { LegendOrientation, LegendType } from './legend';

export type DumbbellSort = 'none' | 'first' | 'gap';

export interface DumbbellFormData extends QueryFormData {
  dimension: string;
  metrics: QueryFormMetric[];
  symbolSize?: number;
  originSymbol?: string;
  originColor?: string;
  destinationSymbol?: string;
  destinationColor?: string;
  lineWidth?: number;
  lineColor?: string;
  lineArrow?: boolean;
  showLabels?: boolean;
  numberFormat?: string;
  valueAxisLabel?: string;
  sortBy?: DumbbellSort;
  chartMargin?: number;
  colorScheme?: string;
  showLegend?: boolean;
  legendType?: LegendType;
  legendOrientation?: LegendOrientation;
  legendMargin?: number | null;
}

// One series per metric; values aligned to `categories` by index.
export interface DumbbellMetricSeries {
  name: string;
  values: number[];
}

export interface DumbbellTransformedProps {
  width: number;
  height: number;
  categories: string[];
  series: DumbbellMetricSeries[];
  symbolSize: number;
  originSymbol: string;
  originColor: string;
  destinationSymbol: string;
  destinationColor: string;
  lineWidth: number;
  lineColor: string;
  lineArrow: boolean;
  showLabels: boolean;
  numberFormat: string;
  valueAxisLabel: string;
  chartMargin: number;
  colorScheme?: string;
  showLegend: boolean;
  legendType: LegendType;
  legendOrientation: LegendOrientation;
  legendMargin: number | null;
  sliceId?: number;
}

export type DumbbellChartProps = ChartProps<DumbbellFormData>;
