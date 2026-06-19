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
import { buildQueryContext, ensureIsArray } from '@superset-ui/core';
import { FilterBoxModernFormData } from '../types';

/**
 * The filter values are fetched on demand by the component (server-side search
 * via /api/v1/chart/data with LOWER(col) LIKE LOWER('%term%') — Databend-safe).
 * The chart still needs a non-empty query to render, so we issue a minimal
 * 1-row query over the first filter column (its result is not used).
 */
export default function buildQuery(formData: FilterBoxModernFormData) {
  const filterColumns = ensureIsArray(formData.filter_columns);
  return buildQueryContext(formData, baseQueryObject => [
    {
      ...baseQueryObject,
      columns: filterColumns.slice(0, 1),
      metrics: [],
      orderby: [],
      row_limit: 1,
    },
  ]);
}
