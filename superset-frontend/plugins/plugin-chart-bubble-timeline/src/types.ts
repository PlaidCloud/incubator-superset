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
import { ChartProps, QueryFormData } from '@superset-ui/core';
import { LegendOrientation, LegendType } from './legend';

export interface BubbleTimelineFormData extends QueryFormData {
  x: string | object;
  y: string | object;
  size: string | object;
  entity: string;
  series?: string;
  timeColumn: string;
  maxBubbleSize?: number;
  autoPlay?: boolean;
  showPeriodLabel?: boolean;
  chartMargin?: number;
  logXAxis?: boolean;
  logYAxis?: boolean;
  numberFormat?: string;
  colorScheme?: string;
  xAxisLabel?: string;
  yAxisLabel?: string;
  showLegend?: boolean;
  legendType?: LegendType;
  legendOrientation?: LegendOrientation;
  legendMargin?: number | null;
  showZoom?: boolean;
}

export interface Bubble {
  x: number;
  y: number;
  size: number;
  name: string;
  category: string;
}

export interface BubbleTimelineTransformedProps {
  width: number;
  height: number;
  periods: string[];
  bubblesByPeriod: Record<string, Bubble[]>;
  categories: string[];
  maxSize: number;
  maxBubbleSize: number;
  autoPlay: boolean;
  showPeriodLabel: boolean;
  chartMargin: number;
  logXAxis: boolean;
  logYAxis: boolean;
  numberFormat: string;
  colorScheme?: string;
  xAxisLabel: string;
  yAxisLabel: string;
  showLegend: boolean;
  legendType: LegendType;
  legendOrientation: LegendOrientation;
  legendMargin: number | null;
  showZoom: boolean;
  sliceId?: number;
}

export type BubbleTimelineChartProps = ChartProps<BubbleTimelineFormData>;
