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
import { QueryFormData } from '@superset-ui/core';
import { EChartsOption } from 'echarts';

/**
 * Represents a single task/bar in the Gantt chart
 */
export interface GanttTask {
  /** Category/row index for y-axis positioning */
  categoryIndex: number;
  /** Task name displayed in the bar */
  taskName: string;
  /** Start time as timestamp or date string */
  startTime: number | string;
  /** End time as timestamp or date string */
  endTime: number | string;
  /** Optional progress percentage (0-100) */
  progress?: number;
  /** Optional custom color for the task bar */
  color?: string;
}

/**
 * Style properties for the Gantt chart
 */
export interface PluginChartGanttStylesProps {
  height: number;
  width: number;
  colorScheme?: string;
}

/**
 * Customization properties for the Gantt chart
 */
export interface PluginChartGanttCustomizeProps {
  /** Chart title */
  title?: string;
  /** Whether to show the legend */
  showLegend?: boolean;
  /** Ratio of bar height to row height (0-1) */
  barHeightRatio?: number;
  /** Whether the chart is zoomable */
  zoomable?: boolean;
}

/**
 * Form data passed from the control panel
 */
export type PluginChartGanttQueryFormData = QueryFormData &
  PluginChartGanttStylesProps &
  PluginChartGanttCustomizeProps & {
    taskColumn?: string;
    startTimeColumn?: string;
    endTimeColumn?: string;
    progressColumn?: string;
    categoryColumn?: string;
  };

/**
 * Props passed to the Gantt chart component
 */
export type PluginChartGanttProps = PluginChartGanttStylesProps &
  PluginChartGanttCustomizeProps & {
    /** The ECharts option object for rendering */
    echartOptions: EChartsOption;
    /** Raw task data for the Gantt chart */
    tasks: GanttTask[];
    /** Category labels for the y-axis */
    categories: string[];
  };
