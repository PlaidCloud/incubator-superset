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
import { ChartProps } from '@superset-ui/core';
import { EChartsOption } from 'echarts';
import { GanttTask, FlattenedGanttTask, PluginChartGanttProps } from '../types';

// Mock data for demonstration with nested hierarchy
const MOCK_DATA: GanttTask[] = [
  // Project Alpha (root group)
  {
    id: 'alpha',
    parentId: null,
    level: 0,
    isGroup: true,
    expanded: true,
    categoryIndex: 0,
    taskName: 'Project Alpha',
    startTime: '2024-01-01',
    endTime: '2024-03-15',
    color: '#5470c6',
    children: ['alpha-planning', 'alpha-dev'],
  },
  {
    id: 'alpha-planning',
    parentId: 'alpha',
    level: 1,
    isGroup: true,
    expanded: true,
    categoryIndex: 0,
    taskName: 'Planning Phase',
    startTime: '2024-01-01',
    endTime: '2024-01-31',
    color: '#91cc75',
    children: ['alpha-planning-research', 'alpha-planning-design'],
  },
  {
    id: 'alpha-planning-research',
    parentId: 'alpha-planning',
    level: 2,
    isGroup: false,
    categoryIndex: 0,
    taskName: 'Research',
    startTime: '2024-01-01',
    endTime: '2024-01-15',
    color: '#fac858',
  },
  {
    id: 'alpha-planning-design',
    parentId: 'alpha-planning',
    level: 2,
    isGroup: false,
    categoryIndex: 0,
    taskName: 'Design',
    startTime: '2024-01-15',
    endTime: '2024-01-31',
    color: '#ee6666',
  },
  {
    id: 'alpha-dev',
    parentId: 'alpha',
    level: 1,
    isGroup: true,
    expanded: true,
    categoryIndex: 0,
    taskName: 'Development Phase',
    startTime: '2024-02-01',
    endTime: '2024-03-15',
    color: '#73c0de',
    children: ['alpha-dev-frontend', 'alpha-dev-backend', 'alpha-dev-testing'],
  },
  {
    id: 'alpha-dev-frontend',
    parentId: 'alpha-dev',
    level: 2,
    isGroup: false,
    categoryIndex: 0,
    taskName: 'Frontend',
    startTime: '2024-02-01',
    endTime: '2024-02-28',
    color: '#3ba272',
  },
  {
    id: 'alpha-dev-backend',
    parentId: 'alpha-dev',
    level: 2,
    isGroup: false,
    categoryIndex: 0,
    taskName: 'Backend',
    startTime: '2024-02-01',
    endTime: '2024-03-01',
    color: '#fc8452',
  },
  {
    id: 'alpha-dev-testing',
    parentId: 'alpha-dev',
    level: 2,
    isGroup: false,
    categoryIndex: 0,
    taskName: 'Testing',
    startTime: '2024-03-01',
    endTime: '2024-03-15',
    color: '#9a60b4',
  },
  // Project Beta (root group)
  {
    id: 'beta',
    parentId: null,
    level: 0,
    isGroup: true,
    expanded: true,
    categoryIndex: 0,
    taskName: 'Project Beta',
    startTime: '2024-01-10',
    endTime: '2024-03-20',
    color: '#ea7ccc',
    children: ['beta-sprint1', 'beta-sprint2', 'beta-sprint3'],
  },
  {
    id: 'beta-sprint1',
    parentId: 'beta',
    level: 1,
    isGroup: false,
    categoryIndex: 0,
    taskName: 'Sprint 1',
    startTime: '2024-01-10',
    endTime: '2024-02-01',
    color: '#5470c6',
  },
  {
    id: 'beta-sprint2',
    parentId: 'beta',
    level: 1,
    isGroup: false,
    categoryIndex: 0,
    taskName: 'Sprint 2',
    startTime: '2024-02-01',
    endTime: '2024-02-25',
    color: '#91cc75',
  },
  {
    id: 'beta-sprint3',
    parentId: 'beta',
    level: 1,
    isGroup: false,
    categoryIndex: 0,
    taskName: 'Sprint 3',
    startTime: '2024-02-25',
    endTime: '2024-03-20',
    color: '#fac858',
  },
  // Project Gamma (root group with deep nesting)
  {
    id: 'gamma',
    parentId: null,
    level: 0,
    isGroup: true,
    expanded: true,
    categoryIndex: 0,
    taskName: 'Project Gamma',
    startTime: '2024-01-15',
    endTime: '2024-03-30',
    color: '#ee6666',
    children: ['gamma-phase1'],
  },
  {
    id: 'gamma-phase1',
    parentId: 'gamma',
    level: 1,
    isGroup: true,
    expanded: true,
    categoryIndex: 0,
    taskName: 'Phase 1',
    startTime: '2024-01-15',
    endTime: '2024-02-28',
    color: '#73c0de',
    children: ['gamma-phase1-analysis'],
  },
  {
    id: 'gamma-phase1-analysis',
    parentId: 'gamma-phase1',
    level: 2,
    isGroup: true,
    expanded: true,
    categoryIndex: 0,
    taskName: 'Analysis',
    startTime: '2024-01-15',
    endTime: '2024-02-15',
    color: '#3ba272',
    children: ['gamma-phase1-analysis-data', 'gamma-phase1-analysis-report'],
  },
  {
    id: 'gamma-phase1-analysis-data',
    parentId: 'gamma-phase1-analysis',
    level: 3,
    isGroup: false,
    categoryIndex: 0,
    taskName: 'Data Collection',
    startTime: '2024-01-15',
    endTime: '2024-02-01',
    color: '#fc8452',
  },
  {
    id: 'gamma-phase1-analysis-report',
    parentId: 'gamma-phase1-analysis',
    level: 3,
    isGroup: false,
    categoryIndex: 0,
    taskName: 'Report Generation',
    startTime: '2024-02-01',
    endTime: '2024-02-15',
    color: '#9a60b4',
  },
];

const HEIGHT_RATIO = 0.6;
const DIM_DISPLAY_INDEX = 0;
const DIM_TIME_START = 1;
const DIM_TIME_END = 2;
const DIM_TASK_NAME = 3;
const DIM_COLOR = 4;
const DIM_LEVEL = 5;
const DIM_IS_GROUP = 6;
const DIM_EXPANDED = 7;
const DIM_TASK_ID = 8;

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

export default function transformProps(chartProps: ChartProps): PluginChartGanttProps {
  const { width, height, formData, hooks } = chartProps;
  const {
    title = 'Gantt Chart',
    barHeightRatio = 0.6,
    zoomable = true,
    defaultExpandLevel = 2,
  } = formData;

  // Get expanded state from hooks or initialize based on defaultExpandLevel
  const expandedState: Record<string, boolean> = (hooks?.setControlValue as Record<string, boolean>) || {};

  // Initialize expanded state based on defaultExpandLevel if not set
  const initialExpandedState: Record<string, boolean> = {};
  MOCK_DATA.forEach(task => {
    if (task.isGroup) {
      if (expandedState[task.id] === undefined) {
        initialExpandedState[task.id] = task.level < (defaultExpandLevel as number);
      } else {
        initialExpandedState[task.id] = expandedState[task.id];
      }
    }
  });

  // Flatten tasks based on expanded state
  const flattenedTasks = flattenTasks(MOCK_DATA, initialExpandedState);
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
  ]);

  const echartOptions: EChartsOption = {
    tooltip: {
      formatter: (params: { value: (number | string)[] }) => {
        const [, start, end, name, , level, isGroup] = params.value;
        const startDate = new Date(start as number).toLocaleDateString();
        const endDate = new Date(end as number).toLocaleDateString();
        const type = isGroup ? 'Group' : 'Task';
        const levelLabel = `Level ${level}`;
        return `<strong>${name}</strong><br/>Type: ${type}<br/>Level: ${levelLabel}<br/>Start: ${startDate}<br/>End: ${endDate}`;
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
        renderItem: renderGanttItem as unknown as (params: unknown, api: unknown) => unknown,
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
    tasks: MOCK_DATA,
    flattenedTasks,
    categories,
    title: title as string,
    barHeightRatio: barHeightRatio as number,
    zoomable: zoomable as boolean,
    expandedState: initialExpandedState,
    showYAxisLabels: formData.showYAxisLabels,
    showBarLabels: formData.showBarLabels,
  };
}
