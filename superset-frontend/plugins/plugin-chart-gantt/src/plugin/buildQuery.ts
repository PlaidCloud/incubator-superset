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
import { buildQueryContext, QueryFormData } from '@superset-ui/core';

/**
 * The buildQuery function is used to create an instance of QueryContext that's
 * sent to the chart data endpoint.
 *
 * For the Gantt chart, we need to query columns for:
 * - task_column: The task name
 * - category_column: The category/grouping for y-axis
 * - start_time_column: Start time of each task
 * - end_time_column: End time of each task
 */
export default function buildQuery(formData: QueryFormData) {
  const {
    task_id_column: taskIdColumn,
    task_column: taskColumn,
    category_column: categoryColumn,
    parent_column: parentColumn,
    start_time_column: startTimeColumn,
    end_time_column: endTimeColumn,
    progress_column: progressColumn,
  } = formData;

  // Collect all columns needed for the query
  const columns: string[] = [];
  if (taskIdColumn) columns.push(taskIdColumn);
  if (taskColumn) columns.push(taskColumn);
  if (categoryColumn) columns.push(categoryColumn);
  if (parentColumn) columns.push(parentColumn);
  if (startTimeColumn) columns.push(startTimeColumn);
  if (endTimeColumn) columns.push(endTimeColumn);
  if (progressColumn) columns.push(progressColumn);

  return buildQueryContext(formData, baseQueryObject => [
    {
      ...baseQueryObject,
      columns,
      // No grouping needed - we want raw data for each task
      groupby: [],
    },
  ]);
}
