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
import { buildQueryContext, QueryFormMetric } from '@superset-ui/core';
import { ScatterRegressionFormData } from '../types';

export default function buildQuery(formData: ScatterRegressionFormData) {
  const { x, y, entity, series } = formData;
  return buildQueryContext(formData, baseQueryObject => {
    // Optional dnd controls hydrate as `[]` (truthy in JS) — flatten + drop
    // empties so the backend never receives an empty label ("Missing label").
    const columns = ([entity, series] as unknown[])
      .flat()
      .filter(c => (typeof c === 'string' ? c !== '' : Boolean(c))) as string[];
    const metrics = [x, y].filter(Boolean) as QueryFormMetric[];
    return [
      {
        ...baseQueryObject,
        columns,
        metrics,
      },
    ];
  });
}
