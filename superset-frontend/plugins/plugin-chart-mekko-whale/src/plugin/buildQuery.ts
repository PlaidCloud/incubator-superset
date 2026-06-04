/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  See the License for the specific language
 * governing permissions and limitations under the License.
 */
import { buildQueryContext, QueryFormData, QueryFormColumn, ensureIsArray } from '@superset-ui/core';
import { PluginChartMekkoWhaleQueryFormData } from '../types';

export default function buildQuery(formData: QueryFormData) {
  const { groupby, metric, secondary_metric } = formData as PluginChartMekkoWhaleQueryFormData;

  const metrics = [
    metric,
    secondary_metric,
  ].filter(Boolean);

  // Ensure groupby is an array of columns
  const groupbyArray: QueryFormColumn[] = ensureIsArray(groupby);

  return buildQueryContext(formData, baseQueryObject => [
    {
      ...baseQueryObject,
      groupby: groupbyArray,
      metrics,
    },
  ]);
}
