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
import { useEffect, useRef, useState, useCallback } from 'react';
import { styled, useTheme } from '@superset-ui/core';
import { init, EChartsType, use } from 'echarts/core';
import { CustomChart } from 'echarts/charts';
import { CanvasRenderer } from 'echarts/renderers';
import {
  TooltipComponent,
  TitleComponent,
  GridComponent,
  DataZoomComponent,
} from 'echarts/components';
import type { EChartsOption } from 'echarts';
import { PluginChartGanttProps, GanttTask, FlattenedGanttTask } from './types';
import React from 'react';
// Register ECharts components
use([
  CanvasRenderer,
  CustomChart,
  TooltipComponent,
  TitleComponent,
  GridComponent,
  DataZoomComponent,
]);

const StyledContainer = styled.div<{ height: number; width: number }>`
  height: ${({ height }) => height}px;
  width: ${({ width }) => width}px;
  position: relative;
`;

const ExpandCollapseControls = styled.div`
  position: absolute;
  top: 10px;
  right: 50px;
  display: flex;
  gap: 8px;
  z-index: 10;
`;

const ControlButton = styled.button`
  padding: 4px 12px;
  font-size: 12px;
  border: 1px solid ${({ theme }) => theme.colorBorder};
  border-radius: 4px;
  background: ${({ theme }) => theme.colorBgContainer};
  cursor: pointer;
  transition: all 0.2s;

  &:hover {
    border-color: ${({ theme }) => theme.colorPrimary};
    color: ${({ theme }) => theme.colorPrimary};
  }
`;

const DIM_DISPLAY_INDEX = 0;
const DIM_TIME_START = 1;
const DIM_TIME_END = 2;
const DIM_TASK_NAME = 3;
const DIM_COLOR = 4;
const DIM_LEVEL = 5;
const DIM_IS_GROUP = 6;
const DIM_EXPANDED = 7;
const DIM_TASK_ID = 8;
const DIM_SHOW_BAR_LABELS = 9;
const DIM_BAR_HEIGHT_RATIO = 10;
const DIM_INDENT_SIZE = 11;

interface RectShape {
  x: number;
  y: number;
  width: number;
  height: number;
}

function clipRectByRect(
  params: { coordSys: { x: number; y: number; width: number; height: number } },
  rect: RectShape,
): RectShape | null {
  const {
    x: coordX,
    y: coordY,
    width: coordWidth,
    height: coordHeight,
  } = params.coordSys;
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
 * Flatten hierarchical tasks into a visible list based on expanded state
 */
function flattenTasks(
  tasks: GanttTask[],
  expandedState: Record<string, boolean>,
): FlattenedGanttTask[] {
  const taskMap = new Map<string, GanttTask>();
  tasks.forEach(task => taskMap.set(task.id, task));

  const result: FlattenedGanttTask[] = [];
  let displayIdx = 0;

  function isAncestorExpanded(task: GanttTask): boolean {
    if (!task.parentId) return true;
    const parent = taskMap.get(task.parentId);
    if (!parent) return true;
    const parentExpanded = expandedState[parent.id] ?? parent.expanded ?? true;
    if (!parentExpanded) return false;
    return isAncestorExpanded(parent);
  }

  const rootTasks = tasks.filter(t => t.parentId === null);

  function processTask(task: GanttTask) {
    const visible = isAncestorExpanded(task);
    const expanded = expandedState[task.id] ?? task.expanded ?? true;

    result.push({
      ...task,
      visible,
      displayIndex: visible ? displayIdx : -1,
      expanded,
    });
    if (visible) {
      displayIdx += 1;
    }

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

/**
 * Generate category labels with indentation for hierarchy
 */
function generateCategoryLabels(
  flattenedTasks: FlattenedGanttTask[],
): string[] {
  return flattenedTasks
    .filter(t => t.visible)
    .map(task => {
      const indent = '  '.repeat(task.level);
      return `${indent}${task.taskName}`;
    });
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
  const heightRatio = api.value(DIM_BAR_HEIGHT_RATIO) as number;
  const barHeight = api.size([0, 1])[1] * heightRatio;
  const x = startTime[0];
  const y = startTime[1] - barHeight / 2;

  const taskName = api.value(DIM_TASK_NAME) as string;
  const color = api.value(DIM_COLOR) as string;
  const level = api.value(DIM_LEVEL) as number;
  const isGroup = api.value(DIM_IS_GROUP) as number;
  const expanded = api.value(DIM_EXPANDED) as number;
  const showBarLabels = api.value(DIM_SHOW_BAR_LABELS) as number;
  const indentSize = api.value(DIM_INDENT_SIZE) as number;

  const rectShape = clipRectByRect(params, {
    x,
    y,
    width: barLength,
    height: barHeight,
  });
  const indent = level * indentSize;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const expandIcon: any = isGroup
    ? {
        type: 'text',
        style: {
          text: expanded ? '▼' : '▶',
          x: x + 5,
          y: y + barHeight / 2,
          textVerticalAlign: 'middle',
          textAlign: 'left',
          // eslint-disable-next-line theme-colors/no-literal-colors
          fill: 'rgba(255, 255, 255, 0.9)',
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
          stroke: isGroup ? 'rgba(0, 0, 0, 0.3)' : 'rgba(255, 255, 255, 0.5)',
          lineWidth: isGroup ? 2 : 1,
        },
      },
      expandIcon,
      {
        type: 'text',
        ignore: !rectShape || barLength < 30 || !showBarLabels,
        style: {
          text: barLength > (isGroup ? 60 : 50) ? taskName : '',
          x: x + (isGroup ? 20 : 5) + indent,
          y: y + barHeight / 2,
          textVerticalAlign: 'middle',
          textAlign: 'left',
          // eslint-disable-next-line theme-colors/no-literal-colors
          fill: 'rgba(255, 255, 255, 0.9)',
          fontSize: 11,
          fontWeight: isGroup ? 'bold' : 'normal',
        },
      },
    ].filter(Boolean),
  };
}

interface ThemeConfig {
  colorBgContainer: string;
  colorSplit: string;
  colorTextSecondary: string;
  colorText: string;
}

/**
 * Build ECharts options from current state
 */
function buildEchartsOptions(
  flattenedTasks: FlattenedGanttTask[],
  categories: string[],
  title: string,
  zoomable: boolean,
  themeConfig: ThemeConfig,
  showYAxisLabels: boolean,
  showBarLabels: boolean,
  barHeightRatio: number,
  showGroupSummary: boolean,
  indentSize: number,
): EChartsOption {
  const visibleTasks = flattenedTasks.filter(
    t => t.visible && (showGroupSummary || !t.isGroup),
  );

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
    showBarLabels ? 1 : 0,
    barHeightRatio,
    indentSize,
  ]);

  return {
    tooltip: {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      formatter: (params: any) => {
        const { value } = params;
        const [, start, end, name, , level, isGroup] = value;
        const startDate = new Date(start as number).toLocaleDateString();
        const endDate = new Date(end as number).toLocaleDateString();
        const type = isGroup ? 'Group' : 'Task';
        const levelLabel = `Level ${level}`;
        return `<strong>${name}</strong><br/>Type: ${type}<br/>Level: ${levelLabel}<br/>Start: ${startDate}<br/>End: ${endDate}`;
      },
    },
    title: {
      text: title,
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
      left: showYAxisLabels ? 180 : 30,
      right: zoomable ? 30 : 20,
      backgroundColor: themeConfig.colorBgContainer,
      borderWidth: 0,
    },
    xAxis: {
      type: 'time',
      position: 'top',
      splitLine: {
        lineStyle: {
          color: [themeConfig.colorSplit],
        },
      },
      axisLine: {
        show: false,
      },
      axisTick: {
        lineStyle: {
          color: themeConfig.colorTextSecondary,
        },
      },
      axisLabel: {
        color: themeConfig.colorTextSecondary,
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
        show: showYAxisLabels,
        color: themeConfig.colorText,
        fontSize: 11,
        formatter: (value: string) => value,
      },
      inverse: true,
    },
    series: [
      {
        type: 'custom',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        renderItem: renderGanttItem as any,
        encode: {
          x: [DIM_TIME_START, DIM_TIME_END],
          y: DIM_DISPLAY_INDEX,
        },
        data: seriesData,
      },
    ],
  };
}

export default function PluginChartGantt(props: PluginChartGanttProps) {
  const {
    height,
    width,
    tasks,
    expandedState: initialExpandedState,
    title = 'Gantt Chart',
    zoomable = true,
    showYAxisLabels = true,
    showBarLabels = true,
    barHeightRatio = 0.6,
    showGroupSummary = true,
    indentSize = 10,
  } = props;

  const theme = useTheme();
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<EChartsType | null>(null);
  const [expandedState, setExpandedState] =
    useState<Record<string, boolean>>(initialExpandedState);

  // Compute flattened tasks and categories based on current expanded state
  const flattenedTasks = flattenTasks(tasks, expandedState);
  const categories = generateCategoryLabels(flattenedTasks);

  const themeConfig: ThemeConfig = {
    colorBgContainer: theme.colorBgContainer,
    colorSplit: theme.colorSplit,
    colorTextSecondary: theme.colorTextSecondary,
    colorText: theme.colorText,
  };

  const echartOptions = buildEchartsOptions(
    flattenedTasks,
    categories,
    title,
    zoomable,
    themeConfig,
    showYAxisLabels,
    showBarLabels,
    barHeightRatio,
    showGroupSummary,
    indentSize,
  );

  // Toggle expand/collapse for a single task
  const handleToggleExpand = useCallback((taskId: string) => {
    setExpandedState(prev => ({
      ...prev,
      [taskId]: !prev[taskId],
    }));
  }, []);

  // Expand all groups
  const handleExpandAll = useCallback(() => {
    const newState: Record<string, boolean> = {};
    tasks.forEach(task => {
      if (task.isGroup) {
        newState[task.id] = true;
      }
    });
    setExpandedState(newState);
  }, [tasks]);

  // Collapse all groups
  const handleCollapseAll = useCallback(() => {
    const newState: Record<string, boolean> = {};
    tasks.forEach(task => {
      if (task.isGroup) {
        newState[task.id] = false;
      }
    });
    setExpandedState(newState);
  }, [tasks]);

  // Initialize chart
  useEffect(() => {
    if (chartRef.current && !chartInstance.current) {
      chartInstance.current = init(chartRef.current);

      // Handle click events for expand/collapse
      chartInstance.current?.on('click', params => {
        if (params.componentType === 'series' && params.value) {
          const value = params.value as (number | string)[];
          const isGroup = value[DIM_IS_GROUP];
          const taskId = value[DIM_TASK_ID] as string;
          if (isGroup) {
            handleToggleExpand(taskId);
          }
        }
      });
    }

    return () => {
      if (chartInstance.current) {
        chartInstance.current.dispose();
        chartInstance.current = null;
      }
    };
  }, [handleToggleExpand]);

  // Update chart options when they change
  useEffect(() => {
    if (chartInstance.current) {
      chartInstance.current.setOption(echartOptions, true);
    }
  }, [echartOptions]);

  // Handle resize
  useEffect(() => {
    if (chartInstance.current) {
      chartInstance.current.resize({ width, height });
    }
  }, [width, height]);

  return (
    <StyledContainer height={height} width={width}>
      <ExpandCollapseControls>
        <ControlButton onClick={handleExpandAll}>Expand All</ControlButton>
        <ControlButton onClick={handleCollapseAll}>Collapse All</ControlButton>
      </ExpandCollapseControls>
      <div ref={chartRef} style={{ width: '100%', height: '100%' }} />
    </StyledContainer>
  );
}
