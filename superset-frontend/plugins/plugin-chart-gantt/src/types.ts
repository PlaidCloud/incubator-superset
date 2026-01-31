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
import type { EChartsOption } from 'echarts';

/**
 * Represents a single task/bar in the Gantt chart with hierarchy support
 */
export interface GanttTask {
  /** Unique identifier for the task */
  id: string;
  /** Parent task ID for nested hierarchy (null for root level) */
  parentId: string | null;
  /** Nesting level (0 = root, 1 = first level child, etc.) */
  level: number;
  /** Whether this task is a group (has children) */
  isGroup: boolean;
  /** Whether the group is expanded (only applicable if isGroup is true) */
  expanded?: boolean;
  /** Category/row index for y-axis positioning (computed dynamically) */
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
  /** Children task IDs */
  children?: string[];
}

/**
 * Flattened task for rendering (includes visibility state)
 */
export interface FlattenedGanttTask extends GanttTask {
  /** Whether this task is visible based on parent expanded state */
  visible: boolean;
  /** Display index in the visible list */
  displayIndex: number;
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
/** Time range preset options */
export type TimeRangePreset =
  | 'all'
  | 'today'
  | 'this_week'
  | 'this_month'
  | 'next_month'
  | 'this_year'
  | 'custom';

/** Time granularity options */
export type TimeGranularity = 'day' | 'week' | 'month';

export interface PluginChartGanttCustomizeProps {
  /** Chart title */
  title?: string;
  /** Whether to show the legend */
  showLegend?: boolean;
  /** Ratio of bar height to row height (0-1) */
  barHeightRatio?: number;
  /** Whether the chart is zoomable */
  zoomable?: boolean;
  /** Default expand level (-1 = all collapsed, 0 = root expanded, etc.) */
  defaultExpandLevel?: number;
  /** Whether to show y-axis labels */
  showYAxisLabels?: boolean;
  /** Whether to show labels on bars */
  showBarLabels?: boolean;
  showGroupSummary?: boolean;
  indentSize?: number;
  /** Time range preset for filtering */
  timeRangePreset?: TimeRangePreset;
  /** Custom start date (YYYY-MM-DD) */
  customStartDate?: string;
  /** Custom end date (YYYY-MM-DD) */
  customEndDate?: string;
  /** Time granularity for x-axis */
  timeGranularity?: TimeGranularity;
  /** Task name filter string */
  taskFilter?: string;
  /** Show only group tasks */
  showOnlyGroups?: boolean;
  /** Show today marker line */
  showTodayMarker?: boolean;
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
    parentColumn?: string;
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
    /** Flattened visible tasks for rendering */
    flattenedTasks: FlattenedGanttTask[];
    /** Category labels for the y-axis */
    categories: string[];
    /** Callback to toggle task expansion */
    onToggleExpand?: (taskId: string) => void;
    /** Map of expanded state by task ID */
    expandedState: Record<string, boolean>;
  };
