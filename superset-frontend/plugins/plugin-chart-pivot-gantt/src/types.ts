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
import type {
  DataRecord,
  NumberFormatter,
  QueryFormColumn,
  QueryFormData,
  QueryFormMetric,
  SetDataMaskHook,
  TimeFormatter,
} from '@superset-ui/core';

/** ISO-8601 durations, same vocabulary as Superset time grains. */
export type Granularity = 'P1D' | 'P1W' | 'P1M' | 'P3M' | 'P1Y';
export const GRANULARITY_ORDER: Granularity[] = [
  'P1Y',
  'P3M',
  'P1M',
  'P1W',
  'P1D',
];
export const DAY_MS = 864e5;

export type HAlign = 'left' | 'center' | 'right';

export interface RgbaColor {
  r: number;
  g: number;
  b: number;
  a?: number;
}

/** Raw (snake_case) form data as seen by buildQuery. */
export interface PivotGanttFormData extends QueryFormData {
  groupbyRows?: QueryFormColumn[];
  metrics?: QueryFormMetric[];
  date_start_col?: QueryFormColumn | QueryFormColumn[];
  date_end_col?: QueryFormColumn | QueryFormColumn[];
  marker_label_left_col?: QueryFormColumn | QueryFormColumn[];
  marker_label_right_col?: QueryFormColumn | QueryFormColumn[];
  marker_label_top_col?: QueryFormColumn | QueryFormColumn[];
  marker_label_bottom_col?: QueryFormColumn | QueryFormColumn[];
  marker_description_cols?: QueryFormColumn[];
  order_by_col?: string | string[];
  order_desc?: boolean;
}

export interface MarkerLabelColumns {
  left?: string;
  right?: string;
  top?: string;
  bottom?: string;
  description: string[];
}

export interface MarkerOptions {
  height: number;
  fontSize: number;
  fontColor: string;
  labelAlign: HAlign;
  showLabel: boolean;
}

export interface TextStyle {
  fontSize: number;
  color: string;
  align?: HAlign;
}

export interface HintOptions {
  show: boolean;
  fontSize: number;
  trigger: 'hover' | 'click';
  wrap: boolean;
}

export interface TimelineOptions {
  granularity: Granularity[];
  fontSize: number;
}

export interface LegendOptions {
  show: boolean;
  name: string;
  fontSize: number;
}

export interface MarkerColor {
  value: string;
  color: string;
}

export interface PivotGanttProps {
  width: number;
  height: number;
  /** query 0: one record per leaf (already ordered by the hierarchy) */
  data: DataRecord[];
  /** hierarchy column labels, outer → inner */
  rows: string[];
  metricNames: string[];
  /** queries 2..N+1: one array per hierarchy prefix (level) */
  totals: DataRecord[][];
  /** query 1 */
  grandTotals: DataRecord;
  dateStartCol?: string;
  dateEndCol?: string;
  progressMetric?: string;
  labelCols: MarkerLabelColumns;
  metricFormatters: Record<string, NumberFormatter>;
  dateFormatter: TimeFormatter;
  markersColors: MarkerColor[];
  markerOptions: MarkerOptions;
  descriptionStyle: TextStyle;
  detailsStyle: TextStyle;
  hintOptions: HintOptions;
  timelineOptions: TimelineOptions;
  legendOptions: LegendOptions;
  showDayLine: boolean;
  showGrandTotal: boolean;
  hideExpandedRows: boolean;
  defaultCollapsedLevel: number;
  headerFontSize: number;
  valueFontSize: number;
  labelAlign: HAlign;
  orderByCol?: string;
  orderDesc: boolean;
  sliderStart?: number;
  sliderEnd?: number;
  emitCrossFilters: boolean;
  emitFullHierarchy: boolean;
  selectedFilters?: Record<string, string[]> | null;
  setDataMask: SetDataMaskHook;
  setControlValue?: (name: string, value: unknown) => void;
  sliceId?: number;
}
