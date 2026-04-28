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
  DataRecord,
  FilterState,
  QueryFormColumn,
  QueryFormData,
  QueryFormMetric,
  SetDataMaskHook,
} from '@superset-ui/core';

export enum BenchmarkRangeSortBy {
  Category = 'category',
  Q1 = 'q1',
  Q3 = 'q3',
  Median = 'median',
  Target = 'target',
  Actual = 'actual',
}

export enum BenchmarkRangeSortOrder {
  Asc = 'ASC',
  Desc = 'DESC',
}

export enum PercentValueMode {
  Auto = 'auto',
  Fraction = 'fraction',
  Percent = 'percent',
}

export type BenchmarkRangeQueryFormData = QueryFormData & {
  groupby?: QueryFormColumn[] | QueryFormColumn;
  q1Metric?: QueryFormMetric;
  q3Metric?: QueryFormMetric;
  medianMetric?: QueryFormMetric;
  targetMetric?: QueryFormMetric;
  actualMetric?: QueryFormMetric;
  xAxisLabel?: string;
  sortBy?: BenchmarkRangeSortBy;
  sortOrder?: BenchmarkRangeSortOrder;
  showLegend?: boolean;
  showFilterControls?: boolean;
  percentValueMode?: PercentValueMode;
};

export type BenchmarkRangeChartProps =
  ChartProps<BenchmarkRangeQueryFormData> & {
    queriesData: ChartDataResponseResult[];
    formData: BenchmarkRangeQueryFormData;
  };

export type BenchmarkRangeDatum = DataRecord & {
  actual: number;
  category: string;
  isFiltered: boolean;
  median: number;
  q1: number;
  q3: number;
  range: number;
  target: number;
};

export type BenchmarkRangeFilterColumn = {
  key: string;
  label: string;
};

export type BenchmarkRangeRecord = DataRecord & {
  actual?: number;
  category: string;
  filters: Record<string, string>;
  median?: number;
  q1?: number;
  q3?: number;
  target?: number;
};

export type BenchmarkRangeTransformedProps = {
  filterColumns: BenchmarkRangeFilterColumn[];
  filterState?: FilterState;
  groupby: QueryFormColumn[];
  height: number;
  percentValueMode: PercentValueMode;
  records: BenchmarkRangeRecord[];
  sortBy: BenchmarkRangeSortBy;
  sortOrder: BenchmarkRangeSortOrder;
  setDataMask: SetDataMaskHook;
  showFilterControls: boolean;
  showLegend: boolean;
  width: number;
  xAxisLabel: string;
};
