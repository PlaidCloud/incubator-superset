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
import { ChartProps, getCategoricalSchemeRegistry } from '@superset-ui/core';
import type { EChartsOption } from 'echarts';
import type { CallbackDataParams } from 'echarts/types/src/util/types';
import { GanttTask, FlattenedGanttTask, PluginChartGanttProps } from '../types';

const HEIGHT_RATIO = 0.6;
const DIM_DISPLAY_INDEX = 0;
const DIM_TIME_START = 1;
const DIM_TIME_END = 2;
const DIM_TASK_NAME = 3;
const DIM_COLOR = 4;
const DIM_LEVEL = 5;
const DIM_IS_GROUP = 6;
const DIM_EXPANDED = 7;
const DIM_PROGRESS = 9;

/**
 * Flatten hierarchical tasks into a visible list based on expanded state
 */
function flattenTasks(
  tasks: GanttTask[],
  expandedState: Record<string, boolean>,
): FlattenedGanttTask[] {
  const taskMap = new Map<string, GanttTask>();
  tasks.forEach(task => taskMap.set(task.id, task));

  const result: FlattenedGanttTask[] = [];
  let displayIndex = 0;

  function isAncestorExpanded(task: GanttTask): boolean {
    if (!task.parentId) return true;
    const parent = taskMap.get(task.parentId);
    if (!parent) return true;
    const parentExpanded = expandedState[parent.id] ?? parent.expanded ?? true;
    if (!parentExpanded) return false;
    return isAncestorExpanded(parent);
  }

  // Get root tasks first, then process in order
  const rootTasks = tasks.filter(t => t.parentId === null);

  function processTask(task: GanttTask) {
    const visible = isAncestorExpanded(task);
    const expanded = expandedState[task.id] ?? task.expanded ?? true;

    result.push({
      ...task,
      visible,
      displayIndex: visible ? displayIndex++ : -1,
      expanded,
    });

    // Process children
    if (task.children) {
      task.children.forEach(childId => {
        const child = taskMap.get(childId);
        if (child) {
          processTask(child);
        }
      });
    }
  }

  rootTasks.forEach(task => processTask(task));
  return result;
}

function renderGanttItem(
  params: { coordSys: { x: number; y: number; width: number; height: number } },
  api: {
    value: (dim: number) => number | string;
    coord: (data: [number | string, number]) => [number, number];
    size: (data: [number, number]) => [number, number];
    style: (opts?: Record<string, unknown>) => Record<string, unknown>;
  },
) {
  const displayIndex = api.value(DIM_DISPLAY_INDEX) as number;
  const startTime = api.coord([api.value(DIM_TIME_START), displayIndex]);
  const endTime = api.coord([api.value(DIM_TIME_END), displayIndex]);
  const barLength = endTime[0] - startTime[0];
  const barHeight = api.size([0, 1])[1] * HEIGHT_RATIO;
  const x = startTime[0];
  const y = startTime[1] - barHeight / 2;

  const taskName = api.value(DIM_TASK_NAME) as string;
  const color = api.value(DIM_COLOR) as string;
  const level = api.value(DIM_LEVEL) as number;
  const isGroup = api.value(DIM_IS_GROUP) as number;
  const expanded = api.value(DIM_EXPANDED) as number;

  const rectShape = clipRectByRect(params, { x, y, width: barLength, height: barHeight });

  // Indent text based on level
  const indent = level * 15;

  // Create expand/collapse icon for groups
  const expandIcon = isGroup
    ? {
      type: 'text',
      style: {
        text: expanded ? '▼' : '▶',
        x: x + 5,
        y: y + barHeight / 2,
        textVerticalAlign: 'middle',
        textAlign: 'left',
        fill: '#fff',
        fontSize: 10,
      },
    }
    : null;

  return {
    type: 'group',
    children: [
      {
        type: 'rect',
        ignore: !rectShape,
        shape: rectShape,
        style: {
          fill: color,
          stroke: isGroup ? '#333' : '#fff',
          lineWidth: isGroup ? 2 : 1,
        },
      },
      expandIcon,
      {
        type: 'text',
        ignore: !rectShape || barLength < 30,
        style: {
          text: barLength > (isGroup ? 60 : 50) ? taskName : '',
          x: x + (isGroup ? 20 : 5) + indent,
          y: y + barHeight / 2,
          textVerticalAlign: 'middle',
          textAlign: 'left',
          fill: '#fff',
          fontSize: 11,
          fontWeight: isGroup ? 'bold' : 'normal',
        },
      },
    ].filter(Boolean),
  };
}

function clipRectByRect(
  params: { coordSys: { x: number; y: number; width: number; height: number } },
  rect: { x: number; y: number; width: number; height: number },
) {
  const { x: coordX, y: coordY, width: coordWidth, height: coordHeight } = params.coordSys;
  const x = Math.max(rect.x, coordX);
  const x2 = Math.min(rect.x + rect.width, coordX + coordWidth);
  const y = Math.max(rect.y, coordY);
  const y2 = Math.min(rect.y + rect.height, coordY + coordHeight);
  if (x2 > x && y2 > y) {
    return { x, y, width: x2 - x, height: y2 - y };
  }
  return null;
}

/**
 * Generate category labels with indentation for hierarchy
 */
function generateCategoryLabels(flattenedTasks: FlattenedGanttTask[]): string[] {
  return flattenedTasks
    .filter(t => t.visible)
    .map(task => {
      const indent = '  '.repeat(task.level);
      const prefix = task.isGroup ? (task.expanded ? '▼ ' : '▶ ') : '• ';
      return `${indent}${prefix}${task.taskName}`;
    });
}

function getTooltipValues(
  params: CallbackDataParams | CallbackDataParams[],
): (number | string)[] {
  const item = Array.isArray(params) ? params[0] : params;
  return Array.isArray(item?.value)
    ? (item.value as (number | string)[])
    : [];
}

export default function transformProps(chartProps: ChartProps): PluginChartGanttProps {
  const { width, height, formData, hooks, queriesData } = chartProps;
  const {
    title = 'Gantt Chart',
    barHeightRatio = 0.6,
    zoomable = true,
    defaultExpandLevel = 2,
    timeRangePreset = 'all',
    customStartDate = '',
    customEndDate = '',
    timeGranularity = 'day',
    taskFilter = '',
    showProgress = true,
    // Column mappings from control panel (Superset converts snake_case to camelCase)
    taskIdColumn,
    taskColumn,
    parentColumn,
    startTimeColumn,
    endTimeColumn,
    progressColumn,
  } = formData;

  // Get raw data from query - comes as array of row objects
  const rawData = (queriesData?.[0]?.data || []) as Record<string, unknown>[];

  // Get color scheme from formData
  const colorScheme = formData.colorScheme || formData.color_scheme || 'supersetColors';
  const schemeRegistry = getCategoricalSchemeRegistry();
  const colorSchemeObj = schemeRegistry.get(colorScheme);
  const colorPalette = colorSchemeObj?.colors || [
    '#5470c6', '#91cc75', '#fac858', '#ee6666', '#73c0de',
    '#3ba272', '#fc8452', '#9a60b4', '#ea7ccc', '#6e7079',
  ];

  // Transform raw query data into GanttTask[] format
  const tasks: GanttTask[] = [];
  const taskIdToTaskMap = new Map<string, GanttTask>(); // Map original task_id to task object
  const childrenMap = new Map<string, string[]>(); // Map internal task id to children ids

  // First pass: create all tasks (without colors - will be assigned after level computation)
  rawData.forEach((row, index) => {
    // Get the original task_id from data (e.g., 1, 2, 3...)
    const originalTaskId = taskIdColumn && row[taskIdColumn] !== undefined && row[taskIdColumn] !== null && row[taskIdColumn] !== ''
      ? String(row[taskIdColumn])
      : null;

    const taskName = taskColumn ? String(row[taskColumn] ?? `Task ${index + 1}`) : `Task ${index + 1}`;

    // Get parent_task_id - this references the original task_id of the parent
    const parentTaskId = parentColumn && row[parentColumn] !== undefined && row[parentColumn] !== null && row[parentColumn] !== ''
      ? String(row[parentColumn])
      : null;

    const startTime = startTimeColumn ? row[startTimeColumn] : null;
    const endTime = endTimeColumn ? row[endTimeColumn] : null;

    // Get progress value and handle possible formats (0-1 or 0-100)
    let progress = 0;
    if (progressColumn && row[progressColumn] !== undefined && row[progressColumn] !== null) {
      const val = Number(row[progressColumn]);
      if (!isNaN(val)) {
        progress = val;
      }
    }

    // Generate an internal unique ID for this task
    const internalId = `task-${index}`;

    const task: GanttTask = {
      id: internalId,
      parentId: parentTaskId, // Store original parent_task_id temporarily, will be resolved
      level: 0, // Will be computed later
      isGroup: false, // Will be updated based on children
      expanded: true,
      categoryIndex: index,
      taskName,
      startTime: startTime ? new Date(startTime as string | number | Date).getTime() : Date.now(),
      endTime: endTime ? new Date(endTime as string | number | Date).getTime() : Date.now() + 86400000,
      progress,
      color: '', // Will be assigned after level computation
      children: [],
    };

    tasks.push(task);

    // Map original task_id (from CSV) to the task object
    if (originalTaskId) {
      taskIdToTaskMap.set(originalTaskId, task);
    }
  });

  // Second pass: resolve parent references using original task_id values
  tasks.forEach(task => {
    const parentTaskId = task.parentId; // This is the original parent_task_id from CSV
    if (parentTaskId) {
      // Look up parent by original task_id
      const parent = taskIdToTaskMap.get(parentTaskId);
      if (parent) {
        // Update parentId to point to parent's internal ID
        task.parentId = parent.id;

        // Track children
        if (!childrenMap.has(parent.id)) {
          childrenMap.set(parent.id, []);
        }
        childrenMap.get(parent.id)!.push(task.id);
        parent.isGroup = true;
      } else {
        // Parent not found, make this a root task
        task.parentId = null;
      }
    }
  });

  // Create an internal ID map for level computation
  const internalIdToTaskMap = new Map<string, GanttTask>();
  tasks.forEach(task => internalIdToTaskMap.set(task.id, task));

  // Third pass: assign children arrays and compute levels
  function computeLevel(task: GanttTask, visited = new Set<string>()): number {
    if (visited.has(task.id)) return 0; // Prevent infinite loops
    visited.add(task.id);

    if (!task.parentId) return 0;
    const parent = internalIdToTaskMap.get(task.parentId);
    if (!parent) return 0;
    return computeLevel(parent, visited) + 1;
  }

  tasks.forEach(task => {
    task.children = childrenMap.get(task.id) || [];
    task.level = computeLevel(task);
  });

  // Fourth pass: assign colors based on level (tasks at same level get same color)
  tasks.forEach(task => {
    const colorIndex = task.level % colorPalette.length;
    task.color = colorPalette[colorIndex];
  });

  // Fifth pass: compute group progress if not specified (average of children)
  tasks.forEach(task => {
    if (task.isGroup && (task.progress === 0 || task.progress === undefined)) {
      if (task.children && task.children.length > 0) {
        const childProgress = task.children
          .map(childId => internalIdToTaskMap.get(childId)?.progress || 0)
          .filter(p => !isNaN(p));
        if (childProgress.length > 0) {
          task.progress = childProgress.reduce((a, b) => a + b, 0) / childProgress.length;
        }
      }
    }
  });

  // Get expanded state from hooks or initialize based on defaultExpandLevel
  const expandedState: Record<string, boolean> = (hooks?.setControlValue as unknown as Record<string, boolean>) || {};

  // Initialize expanded state based on defaultExpandLevel if not set
  const initialExpandedState: Record<string, boolean> = {};
  tasks.forEach(task => {
    if (task.isGroup) {
      if (expandedState[task.id] === undefined) {
        initialExpandedState[task.id] = task.level < (defaultExpandLevel as number);
      } else {
        initialExpandedState[task.id] = expandedState[task.id];
      }
    }
  });

  // Flatten tasks based on expanded state
  const flattenedTasks = flattenTasks(tasks, initialExpandedState);
  const visibleTasks = flattenedTasks.filter(t => t.visible);

  // Generate category labels
  const categories = generateCategoryLabels(flattenedTasks);

  // Transform visible tasks to ECharts data format
  const seriesData = visibleTasks.map(task => [
    task.displayIndex,
    new Date(task.startTime).getTime(),
    new Date(task.endTime).getTime(),
    task.taskName,
    task.color,
    task.level,
    task.isGroup ? 1 : 0,
    task.expanded ? 1 : 0,
    task.id,
    task.progress || 0,
  ]);

  const echartOptions: EChartsOption = {
    tooltip: {
      formatter: params => {
        const values = getTooltipValues(params);
        const name = values[DIM_TASK_NAME];
        const start = values[DIM_TIME_START];
        const end = values[DIM_TIME_END];
        const level = values[DIM_LEVEL];
        const isGroup = values[DIM_IS_GROUP];
        const progress = values[DIM_PROGRESS];

        const startDate = new Date(start as number).toLocaleDateString();
        const endDate = new Date(end as number).toLocaleDateString();
        const type = isGroup ? 'Group' : 'Task';
        const levelLabel = `Level ${level}`;
        const progressLabel = progress !== undefined ? `<br/>Progress: ${progress}%` : '';
        return `<strong>${name}</strong><br/>Type: ${type}<br/>Level: ${levelLabel}<br/>Start: ${startDate}<br/>End: ${endDate}${progressLabel}`;
      },
    },
    title: {
      text: title as string,
      left: 'center',
    },
    dataZoom: zoomable
      ? [
        {
          type: 'slider',
          xAxisIndex: 0,
          filterMode: 'weakFilter',
          height: 20,
          bottom: 0,
          start: 0,
          end: 100,
          handleSize: '80%',
          showDetail: false,
        },
        {
          type: 'inside',
          xAxisIndex: 0,
          filterMode: 'weakFilter',
          start: 0,
          end: 100,
          zoomOnMouseWheel: false,
          moveOnMouseMove: true,
        },
        {
          type: 'slider',
          yAxisIndex: 0,
          zoomLock: true,
          width: 10,
          right: 10,
          top: 70,
          bottom: 30,
          start: 0,
          end: 100,
          handleSize: 0,
          showDetail: false,
        },
        {
          type: 'inside',
          yAxisIndex: 0,
          start: 0,
          end: 100,
          zoomOnMouseWheel: false,
          moveOnMouseMove: true,
          moveOnMouseWheel: true,
        },
      ]
      : [],
    grid: {
      show: true,
      top: 70,
      bottom: zoomable ? 30 : 20,
      left: 180,
      right: zoomable ? 30 : 20,
      backgroundColor: '#fff',
      borderWidth: 0,
    },
    xAxis: {
      type: 'time',
      position: 'top',
      splitLine: {
        lineStyle: {
          color: ['#E9EDFF'],
        },
      },
      axisLine: {
        show: false,
      },
      axisTick: {
        lineStyle: {
          color: '#929ABA',
        },
      },
      axisLabel: {
        color: '#929ABA',
        inside: false,
        align: 'center',
      },
    },
    yAxis: {
      type: 'category',
      data: categories,
      axisTick: { show: false },
      splitLine: { show: false },
      axisLine: { show: false },
      axisLabel: {
        show: true,
        color: '#333',
        fontSize: 11,
        formatter: (value: string) => value,
      },
      inverse: true,
    },
    series: [
      {
        type: 'custom',
        renderItem: renderGanttItem as any,
        encode: {
          x: [DIM_TIME_START, DIM_TIME_END],
          y: DIM_DISPLAY_INDEX,
        },
        data: seriesData,
      },
    ],
  };

  return {
    width,
    height,
    echartOptions,
    tasks,
    flattenedTasks,
    categories,
    title: title as string,
    barHeightRatio: barHeightRatio as number,
    zoomable: zoomable as boolean,
    expandedState: initialExpandedState,
    showYAxisLabels: formData.showYAxisLabels,
    showBarLabels: formData.showBarLabels,
    timeRangePreset: timeRangePreset as PluginChartGanttProps['timeRangePreset'],
    customStartDate: customStartDate as string,
    customEndDate: customEndDate as string,
    timeGranularity: timeGranularity as PluginChartGanttProps['timeGranularity'],
    taskFilter: taskFilter as string,
    showProgress: showProgress as boolean,
    showTodayMarker: formData.showTodayMarker ?? true,
  };
}
