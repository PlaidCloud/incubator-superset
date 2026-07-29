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
  ChartProps,
  QueryFormData,
  SetDataMaskHook,
  FilterState,
  QueryObjectFilterClause,
} from '@superset-ui/core';

export type FilterBoxModernFormData = QueryFormData & {
  filter_columns: string[];
  instant_filtering: boolean;
  row_limit?: number;
};

export type FilterValue = string | number | boolean;

export type FilterBoxModernChartProps = ChartProps & {
  formData: FilterBoxModernFormData;
};

export interface FilterBoxModernTransformedProps {
  width: number;
  height: number;
  filterColumns: string[];
  /** `${datasourceId}__${datasourceType}` — used for server-side value search */
  datasource: string;
  /** max values fetched per column query / search page */
  rowLimit: number;
  instantFiltering: boolean;
  setDataMask: SetDataMaskHook;
  filterState?: FilterState;
  /**
   * Native filters from the dashboard whose scope includes this chart. They
   * are applied to each column's option query so the dropdown lists are
   * limited by the dashboard's current selections (cross-filter into the box).
   */
  dashboardFilters: QueryObjectFilterClause[];
}
