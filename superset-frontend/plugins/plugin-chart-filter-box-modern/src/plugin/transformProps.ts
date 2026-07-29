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
import { ensureIsArray, getColumnLabel } from '@superset-ui/core';
import {
  FilterBoxModernChartProps,
  FilterBoxModernFormData,
  FilterBoxModernTransformedProps,
} from '../types';

export default function transformProps(
  chartProps: FilterBoxModernChartProps,
): FilterBoxModernTransformedProps {
  const { width, height, formData, hooks, filterState } = chartProps;
  // Custom controls are stripped from the sanitized `formData` but survive on
  // `rawFormData` (same approach the legacy filter_box used).
  const raw = (chartProps as { rawFormData?: Partial<FilterBoxModernFormData> })
    .rawFormData;
  const rawFilterColumns = formData.filter_columns ?? raw?.filter_columns;
  const rawInstant = formData.instant_filtering ?? raw?.instant_filtering;
  const filterColumns = ensureIsArray(rawFilterColumns).map(getColumnLabel);
  const rowLimit = Number(formData.row_limit ?? raw?.row_limit) || 1000;
  // Native filters from the dashboard whose scope includes this chart are
  // merged into `extra_form_data` by the dashboard. Pass their value filters
  // through so the option queries can be scoped by the current selections.
  const dashboardFilters = ensureIsArray(formData.extra_form_data?.filters);

  return {
    width,
    height,
    filterColumns,
    datasource: formData.datasource,
    rowLimit,
    instantFiltering: !!rawInstant,
    setDataMask: hooks?.setDataMask ?? (() => {}),
    filterState,
    dashboardFilters,
  };
}
