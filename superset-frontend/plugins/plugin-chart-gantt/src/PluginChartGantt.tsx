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
import { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import { styled, useTheme } from '@apache-superset/core/theme';
import { init, EChartsType, use } from 'echarts/core';
import { CustomChart } from 'echarts/charts';
import { CanvasRenderer } from 'echarts/renderers';
import {
  TooltipComponent,
  TitleComponent,
  GridComponent,
  DataZoomComponent,
  MarkLineComponent,
} from 'echarts/components';
import type { EChartsOption } from 'echarts';
import {
  PluginChartGanttProps,
  GanttTask,
  FlattenedGanttTask,
  TimeRangePreset,
  TimeGranularity,
} from './types';

/**
 * Calculate time range bounds based on preset
 */
function getTimeRangeBounds(
  preset: TimeRangePreset,
  customStart?: string,
  customEnd?: string,
): { start: Date | null; end: Date | null } {
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());

  switch (preset) {
    case 'today':
      return {
        start: today,
        end: new Date(today.getTime() + 24 * 60 * 60 * 1000 - 1),
      };
    case 'this_week': {
      const dayOfWeek = today.getDay();
      const startOfWeek = new Date(today);
      startOfWeek.setDate(today.getDate() - dayOfWeek);
      const endOfWeek = new Date(startOfWeek);
      endOfWeek.setDate(startOfWeek.getDate() + 6);
      endOfWeek.setHours(23, 59, 59, 999);
      return { start: startOfWeek, end: endOfWeek };
    }
    case 'this_month': {
      const startOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
      const endOfMonth = new Date(
        today.getFullYear(),
        today.getMonth() + 1,
        0,
        23,
        59,
        59,
        999,
      );
      return { start: startOfMonth, end: endOfMonth };
    }
    case 'next_month': {
      const startOfNextMonth = new Date(
        today.getFullYear(),
        today.getMonth() + 1,
        1,
      );
      const endOfNextMonth = new Date(
        today.getFullYear(),
        today.getMonth() + 2,
        0,
        23,
        59,
        59,
        999,
      );
      return { start: startOfNextMonth, end: endOfNextMonth };
    }
    case 'this_year': {
      const startOfYear = new Date(today.getFullYear(), 0, 1);
      const endOfYear = new Date(today.getFullYear(), 11, 31, 23, 59, 59, 999);
      return { start: startOfYear, end: endOfYear };
    }
    case 'custom': {
      return {
        start: customStart ? new Date(customStart) : null,
        end: customEnd ? new Date(customEnd) : null,
      };
    }
    case 'all':
    default:
      return { start: null, end: null };
  }
}

/**
 * Check if a task overlaps with the given time range
 */
function taskOverlapsTimeRange(
  task: GanttTask,
  rangeStart: Date | null,
  rangeEnd: Date | null,
): boolean {
  if (!rangeStart && !rangeEnd) return true;

  const taskStart = new Date(task.startTime).getTime();
  const taskEnd = new Date(task.endTime).getTime();
  const rangeStartTime = rangeStart ? rangeStart.getTime() : -Infinity;
  const rangeEndTime = rangeEnd ? rangeEnd.getTime() : Infinity;

  // Task overlaps if it starts before range ends AND ends after range starts
  return taskStart <= rangeEndTime && taskEnd >= rangeStartTime;
}

/**
 * Filter tasks based on all filter criteria
 * Preserves hierarchy - if a child matches, parent is also included
 */
function filterTasks(
  tasks: GanttTask[],
  timeRangePreset: TimeRangePreset,
  customStartDate: string,
  customEndDate: string,
  taskFilter: string,
): GanttTask[] {
  const { start: rangeStart, end: rangeEnd } = getTimeRangeBounds(
    timeRangePreset,
    customStartDate,
    customEndDate,
  );

  const searchTerm = taskFilter.toLowerCase().trim();

  // Build a map of task IDs for quick lookup
  const taskMap = new Map<string, GanttTask>();
  tasks.forEach(task => taskMap.set(task.id, task));

  // First pass: find all tasks that directly match the filter criteria
  const matchingIds = new Set<string>();
  tasks.forEach(task => {
    // Time range filter
    if (!taskOverlapsTimeRange(task, rangeStart, rangeEnd)) {
      return;
    }

    // Task name filter - if no search term, include all
    if (!searchTerm || task.taskName.toLowerCase().includes(searchTerm)) {
      matchingIds.add(task.id);
    }
  });

  // Second pass: include all ancestors of matching tasks
  const includedIds = new Set<string>(matchingIds);
  const addAncestors = (task: GanttTask) => {
    if (task.parentId) {
      const parent = taskMap.get(task.parentId);
      if (parent && !includedIds.has(parent.id)) {
        includedIds.add(parent.id);
        addAncestors(parent);
      }
    }
  };

  matchingIds.forEach(id => {
    const task = taskMap.get(id);
    if (task) {
      addAncestors(task);
    }
  });

  // Return filtered tasks preserving original order
  return tasks.filter(task => includedIds.has(task.id));
}

/**
 * Get time axis formatting based on granularity
 */
function getTimeAxisConfig(granularity: TimeGranularity): {
  minInterval: number;
  axisLabelFormatter: string;
} {
  switch (granularity) {
    case 'week':
      return {
        minInterval: 7 * 24 * 60 * 60 * 1000, // 1 week in ms
        axisLabelFormatter: '{MMM} {dd}',
      };
    case 'month':
      return {
        minInterval: 30 * 24 * 60 * 60 * 1000, // ~1 month in ms
        axisLabelFormatter: '{MMM} {yyyy}',
      };
    case 'day':
    default:
      return {
        minInterval: 24 * 60 * 60 * 1000, // 1 day in ms
        axisLabelFormatter: '{MMM} {dd}',
      };
  }
}
// Register ECharts components
use([
  CanvasRenderer,
  CustomChart,
  TooltipComponent,
  TitleComponent,
  GridComponent,
  DataZoomComponent,
  MarkLineComponent,
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

const FilterBadge = styled.span`
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  margin-left: 8px;
  font-size: 11px;
  font-weight: 500;
  border-radius: 10px;
  background: ${({ theme }) => theme.colorInfoBg};
  color: ${({ theme }) => theme.colorInfo};
`;

const FilterToolbar = styled.div`
  position: absolute;
  top: 40px;
  left: 10px;
  right: 10px;
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  padding: 8px 12px;
  background: ${({ theme }) => theme.colorBgContainer};
  border: 1px solid ${({ theme }) => theme.colorBorder};
  border-radius: 6px;
  z-index: 10;
`;

const FilterGroup = styled.div`
  display: flex;
  align-items: center;
  gap: 6px;
`;

const FilterLabel = styled.label`
  font-size: 11px;
  font-weight: 500;
  color: ${({ theme }) => theme.colorTextSecondary};
  white-space: nowrap;
`;

const FilterInput = styled.input`
  padding: 4px 8px;
  font-size: 12px;
  border: 1px solid ${({ theme }) => theme.colorBorder};
  border-radius: 4px;
  background: ${({ theme }) => theme.colorBgContainer};
  color: ${({ theme }) => theme.colorText};
  width: 150px;

  &:focus {
    outline: none;
    border-color: ${({ theme }) => theme.colorPrimary};
  }

  &::placeholder {
    color: ${({ theme }) => theme.colorTextSecondary};
  }
`;

const FilterSelect = styled.select`
  padding: 4px 8px;
  font-size: 12px;
  border: 1px solid ${({ theme }) => theme.colorBorder};
  border-radius: 4px;
  background: ${({ theme }) => theme.colorBgContainer};
  color: ${({ theme }) => theme.colorText};
  cursor: pointer;

  &:focus {
    outline: none;
    border-color: ${({ theme }) => theme.colorPrimary};
  }
`;

const FilterSeparator = styled.div`
  width: 1px;
  height: 20px;
  background: ${({ theme }) => theme.colorBorder};
`;

const ClearFiltersButton = styled.button`
  padding: 4px 8px;
  font-size: 11px;
  border: none;
  border-radius: 4px;
  background: ${({ theme }) => theme.colorErrorBg};
  color: ${({ theme }) => theme.colorError};
  cursor: pointer;
  transition: all 0.2s;

  &:hover {
    background: ${({ theme }) => theme.colorError};
    color: ${({ theme }) => theme.colorBgContainer};
  }
`;

const TIME_RANGE_OPTIONS: { value: TimeRangePreset; label: string }[] = [
  { value: 'all', label: 'All Time' },
  { value: 'today', label: 'Today' },
  { value: 'this_week', label: 'This Week' },
  { value: 'this_month', label: 'This Month' },
  { value: 'next_month', label: 'Next Month' },
  { value: 'this_year', label: 'This Year' },
  { value: 'custom', label: 'Custom...' },
];

const GRANULARITY_OPTIONS: { value: TimeGranularity; label: string }[] = [
  { value: 'day', label: 'Day' },
  { value: 'week', label: 'Week' },
  { value: 'month', label: 'Month' },
];

// Data dimension indices for series data array
const DIM_DISPLAY_INDEX = 0;
const DIM_TIME_START = 1;
const DIM_TIME_END = 2;
const DIM_TASK_NAME = 3;
const DIM_COLOR = 4;
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const DIM_LEVEL = 5; // Used in tooltip via array destructuring
const DIM_IS_GROUP = 6;
const DIM_EXPANDED = 7;
const DIM_TASK_ID = 8;
const DIM_SHOW_BAR_LABELS = 9;
const DIM_BAR_HEIGHT_RATIO = 10;
const DIM_IS_HIGHLIGHTED = 11;
const DIM_PROGRESS = 12;
const DIM_SHOW_PROGRESS = 13;

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
  const isGroup = api.value(DIM_IS_GROUP) as number;
  const expanded = api.value(DIM_EXPANDED) as number;
  const showBarLabels = api.value(DIM_SHOW_BAR_LABELS) as number;
  const isHighlighted = api.value(DIM_IS_HIGHLIGHTED) as number;
  const showProgress = api.value(DIM_SHOW_PROGRESS) as number;

  const { coordSys } = params as any;
  const gridLeft = coordSys.x;
  const gridRight = gridLeft + coordSys.width;

  const rectShape = clipRectByRect(params, {
    x,
    y,
    width: barLength,
    height: barHeight,
  });

  // If the bar is not visible at all, don't render anything
  if (!rectShape) {
    return undefined;
  }

  // Calculate visible range of the bar to handle sticky labels
  const barVisibleX = Math.max(x, gridLeft);
  const barVisibleRight = Math.min(x + barLength, gridRight);
  const barVisibleWidth = barVisibleRight - barVisibleX;

  // Reposition elements for "sticky" effect when bar starts off-screen
  const isStartedOffScreen = x < gridLeft;
  const iconX = isStartedOffScreen ? gridLeft + 10 : x + 15;
  const textStartX = isStartedOffScreen ? gridLeft + 25 : x + 25;

  // Calculate percentage text - we'll reserve space for it if showProgress is on
  const progress = api.value(DIM_PROGRESS) as number;
  const progressPercentText = `${Math.round(progress)}%`;
  const progressTextWidth = showProgress ? 35 : 0; // Reserve ~35px for percentage text

  const textMaxWidth = barVisibleRight - textStartX - 5 - progressTextWidth;

  // Modern flat expand icon for groups
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const expandIcon: any = isGroup
    ? {
        type: 'text',
        style: {
          text: expanded ? '−' : '+',
          x: iconX,
          y: y + barHeight / 2,
          textVerticalAlign: 'middle',
          textAlign: 'center',
          // eslint-disable-next-line theme-colors/no-literal-colors
          fill: 'rgba(255, 255, 255, 0.85)',
          fontSize: 12,
          fontWeight: 'bold',
        },
        // Hide icon if bar segment is too small
        ignore: barVisibleWidth < 20,
      }
    : null;

  // Calculate contrasting text color based on bar color brightness
  const getTextColor = (bgColor: string): string => {
    // Simple brightness check - if color is light, use dark text
    const hex = bgColor.replace('#', '');
    const r = parseInt(hex.substring(0, 2), 16);
    const g = parseInt(hex.substring(2, 4), 16);
    const b = parseInt(hex.substring(4, 6), 16);
    const brightness = (r * 299 + g * 587 + b * 114) / 1000;
    // eslint-disable-next-line theme-colors/no-literal-colors
    return brightness > 150
      ? 'rgba(0, 0, 0, 0.85)'
      : 'rgba(255, 255, 255, 0.95)';
  };

  const textColor = getTextColor(color);

  return {
    type: 'group',
    children: [
      {
        type: 'rect',
        shape: {
          ...rectShape,
          r: 4, // Rounded corners for modern look
        },
        style: {
          fill: color,
          // Flat design - no stroke for regular bars, subtle highlight border only
          // eslint-disable-next-line theme-colors/no-literal-colors
          stroke: isHighlighted ? '#1890ff' : undefined,
          lineWidth: isHighlighted ? 2 : 0,
          shadowBlur: 0, // No shadows for flat design
        },
      },
      expandIcon,
      {
        type: 'text',
        ignore: textMaxWidth < 15 || !showBarLabels,
        style: {
          text: taskName,
          x: textStartX,
          y: y + barHeight / 2,
          textVerticalAlign: 'middle',
          textAlign: 'left',
          fill: textColor,
          fontSize: 12,
          fontWeight: isGroup ? '600' : '400',
          fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, sans-serif',
          width: Math.max(textMaxWidth, 0),
          overflow: 'truncate',
          ellipsis: '...',
        },
      },
      {
        type: 'text',
        // Only show percentage if bar is visible enough and enabled
        ignore: !showProgress || !showBarLabels || barVisibleWidth < 40,
        style: {
          text: progressPercentText,
          x: barVisibleRight - 5,
          y: y + barHeight / 2,
          textVerticalAlign: 'middle',
          textAlign: 'right',
          fill: textColor,
          fontSize: 10,
          fontWeight: '500',
          fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, sans-serif',
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
  timeGranularity: TimeGranularity,
  highlightedTaskIds: Set<string>,
  showTodayMarker: boolean,
  showProgress: boolean,
  containerHeight: number,
  totalSpanDays: number,
  zoomStart?: number,
  zoomEnd?: number,
): EChartsOption {
  // Fixed row height for consistent bar sizing
  const ROW_HEIGHT = 32;

  const visibleTasks = flattenedTasks.filter(
    t => t.visible && (showGroupSummary || !t.isGroup),
  );

  // Calculate the ideal grid height based on number of tasks
  const taskCount = visibleTasks.length;
  const idealGridHeight = taskCount * ROW_HEIGHT;
  const availableHeight = containerHeight - 140 - (zoomable ? 30 : 0); // Account for title, margins, and zoom controls

  // Use the smaller of ideal height or available height, with a minimum
  const gridHeight = Math.min(idealGridHeight, Math.max(availableHeight, 100));

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
    highlightedTaskIds.has(task.id) ? 1 : 0,
    task.progress || 0,
    showProgress ? 1 : 0,
  ]);

  const timeAxisConfig = getTimeAxisConfig(timeGranularity);

  return {
    tooltip: {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      formatter: (params: any) => {
        const { value } = params;
        const name = value[DIM_TASK_NAME];
        const start = value[DIM_TIME_START];
        const end = value[DIM_TIME_END];
        const level = value[DIM_LEVEL];
        const isGroup = value[DIM_IS_GROUP];
        const progress = value[DIM_PROGRESS];

        const startDate = new Date(start as number).toLocaleDateString();
        const endDate = new Date(end as number).toLocaleDateString();
        const type = isGroup ? 'Group' : 'Task';
        const levelLabel = `Level ${level}`;
        const progressLabel =
          progress !== undefined
            ? `<br/>Progress: ${Math.round(progress)}%`
            : '';
        return `<strong>${name}</strong><br/>Type: ${type}<br/>Level: ${levelLabel}<br/>Start: ${startDate}<br/>End: ${endDate}${progressLabel}`;
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
            start: zoomStart ?? 0,
            end:
              zoomEnd ??
              (totalSpanDays > 0
                ? timeGranularity === 'day'
                  ? Math.min((7 / totalSpanDays) * 100, 100)
                  : timeGranularity === 'week'
                    ? Math.min((35 / totalSpanDays) * 100, 100)
                    : 100
                : 10),
            handleSize: '80%',
            showDetail: false,
            // Allow zooming down to 1 unit of granularity
            minValueSpan: timeAxisConfig.minInterval,
          },
          {
            type: 'inside',
            xAxisIndex: 0,
            filterMode: 'weakFilter',
            start: zoomStart ?? 0,
            end:
              zoomEnd ??
              (totalSpanDays > 0
                ? timeGranularity === 'day'
                  ? Math.min((7 / totalSpanDays) * 100, 100)
                  : timeGranularity === 'week'
                    ? Math.min((35 / totalSpanDays) * 100, 100)
                    : 100
                : 10),
            zoomOnMouseWheel: true,
            moveOnMouseMove: true,
            moveOnMouseWheel: true,
            // Allow zooming down to 1 unit of granularity
            minValueSpan: timeAxisConfig.minInterval,
          },
          {
            type: 'slider',
            yAxisIndex: 0,
            zoomLock: true,
            width: 10,
            right: 10,
            top: 110,
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
      top: 110,
      height: gridHeight, // Use calculated height for consistent row sizing
      left: showYAxisLabels ? 180 : 30,
      right: zoomable ? 30 : 20,
      backgroundColor: themeConfig.colorBgContainer,
      borderWidth: 0,
    },
    xAxis: {
      type: 'time',
      position: 'top',
      minInterval: timeAxisConfig.minInterval,
      splitLine: {
        show: true,
        lineStyle: {
          color: themeConfig.colorSplit,
          width: 1,
          type: 'dashed',
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
        formatter: timeAxisConfig.axisLabelFormatter,
        hideOverlap: true,
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
        clip: true,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        renderItem: renderGanttItem as any,
        encode: {
          x: [DIM_TIME_START, DIM_TIME_END],
          y: DIM_DISPLAY_INDEX,
        },
        data: seriesData,
        markLine: showTodayMarker
          ? {
              silent: true,
              symbol: 'none',
              animation: false,
              lineStyle: {
                // eslint-disable-next-line theme-colors/no-literal-colors
                color: '#ff6b6b',
                width: 2,
                type: 'solid',
              },
              label: {
                show: true,
                position: 'end',
                formatter: 'Today',
                // eslint-disable-next-line theme-colors/no-literal-colors
                color: '#ff6b6b',
                fontWeight: 'bold',
                fontSize: 11,
                padding: [2, 6],
                // eslint-disable-next-line theme-colors/no-literal-colors
                backgroundColor: 'rgba(255, 107, 107, 0.1)',
                borderRadius: 3,
              },
              data: [
                {
                  xAxis: Date.now(),
                },
              ],
            }
          : undefined,
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
    timeRangePreset = 'all',
    customStartDate = '',
    customEndDate = '',
    timeGranularity = 'day',
    taskFilter = '',
    showTodayMarker = true,
    showProgress = true,
  } = props;

  // Removed from UI controls - always show group summaries
  const showGroupSummary = true;

  const theme = useTheme();
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<EChartsType | null>(null);
  const [expandedState, setExpandedState] =
    useState<Record<string, boolean>>(initialExpandedState);

  // Local filter state for in-chart controls
  const [localTimeRangePreset, setLocalTimeRangePreset] =
    useState<TimeRangePreset>(timeRangePreset);
  const [localTaskFilter, setLocalTaskFilter] = useState<string>(taskFilter);
  const [localCustomStartDate, setLocalCustomStartDate] =
    useState<string>(customStartDate);
  const [localCustomEndDate, setLocalCustomEndDate] =
    useState<string>(customEndDate);

  const [localTimeGranularity, setLocalTimeGranularity] =
    useState<TimeGranularity>(timeGranularity);

  // Ref to track last zoom levels to maintain perspective during granularity changes
  const lastZoomRef = useRef<{ start: number; end: number } | null>(null);
  // Flag to know if we should reset zoom to presets (manually changed via dropdown)
  // or keep current zoom (auto-changed via zoom interaction)
  const [shouldResetZoom, setShouldResetZoom] = useState(false);

  // Calculate total time span of data for zoom thresholds
  const totalSpanDays = useMemo(() => {
    if (tasks.length === 0) return 0;
    const times = tasks.flatMap(t => [
      new Date(t.startTime).getTime(),
      new Date(t.endTime).getTime(),
    ]);
    return (Math.max(...times) - Math.min(...times)) / (24 * 60 * 60 * 1000);
  }, [tasks]);

  // Handle zoom interaction to update the "View" option
  const handleDataZoom = useCallback(
    (params: any) => {
      const zoom = params.batch ? params.batch[0] : params;
      const { start, end } = zoom;

      // Update our ref so we can maintain this zoom if granularity changes
      lastZoomRef.current = { start, end };

      // Calculate visible duration to determine best-fit granularity
      const spanPercent = end - start;
      const visibleDays = totalSpanDays * (spanPercent / 100);

      let newGranularity: TimeGranularity = 'month';
      if (visibleDays < 15) newGranularity = 'day';
      else if (visibleDays < 60) newGranularity = 'week';

      if (newGranularity !== localTimeGranularity) {
        setShouldResetZoom(false); // It's an auto-change, don't reset to defaults
        setLocalTimeGranularity(newGranularity);
      }
    },
    [localTimeGranularity, totalSpanDays],
  );

  // Sync local state with props when they change
  useEffect(() => {
    setLocalTimeRangePreset(timeRangePreset);
  }, [timeRangePreset]);

  useEffect(() => {
    setLocalTaskFilter(taskFilter);
  }, [taskFilter]);

  useEffect(() => {
    setLocalCustomStartDate(customStartDate);
  }, [customStartDate]);

  useEffect(() => {
    setLocalCustomEndDate(customEndDate);
  }, [customEndDate]);

  useEffect(() => {
    setLocalTimeGranularity(timeGranularity);
  }, [timeGranularity]);

  // Apply filters to tasks
  const filteredTasks = filterTasks(
    tasks,
    localTimeRangePreset,
    localCustomStartDate,
    localCustomEndDate,
    localTaskFilter,
  );

  // Count active filters for badge
  const activeFilterCount = [
    localTimeRangePreset !== 'all',
    localTaskFilter.trim().length > 0,
  ].filter(Boolean).length;

  // Determine which tasks should be highlighted (when search filter is active)
  const highlightedTaskIds = new Set<string>();
  if (localTaskFilter.trim().length > 0) {
    const searchTerm = localTaskFilter.toLowerCase().trim();
    filteredTasks.forEach(task => {
      if (task.taskName.toLowerCase().includes(searchTerm)) {
        highlightedTaskIds.add(task.id);
      }
    });
  }

  // Clear all filters
  const handleClearFilters = useCallback(() => {
    setLocalTimeRangePreset('all');
    setLocalTaskFilter('');
    setLocalCustomStartDate('');
    setLocalCustomEndDate('');
  }, []);

  // Compute flattened tasks and categories based on current expanded state
  const flattenedTasks = flattenTasks(filteredTasks, expandedState);
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
    localTimeGranularity,
    highlightedTaskIds,
    showTodayMarker,
    showProgress,
    height,
    totalSpanDays,
    shouldResetZoom ? undefined : lastZoomRef.current?.start,
    shouldResetZoom ? undefined : lastZoomRef.current?.end,
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

  // Separate effect for datazoom listener to avoid full chart re-initialization
  useEffect(() => {
    if (chartInstance.current) {
      chartInstance.current.off('datazoom');
      chartInstance.current.on('datazoom', handleDataZoom);
    }
  }, [handleDataZoom]);

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
        {activeFilterCount > 0 && (
          <FilterBadge>
            {activeFilterCount} filter{activeFilterCount > 1 ? 's' : ''} active
          </FilterBadge>
        )}
      </ExpandCollapseControls>

      <FilterToolbar>
        <FilterGroup>
          <FilterLabel htmlFor="time-range">Time Range:</FilterLabel>
          <FilterSelect
            id="time-range"
            value={localTimeRangePreset}
            onChange={e =>
              setLocalTimeRangePreset(e.target.value as TimeRangePreset)
            }
          >
            {TIME_RANGE_OPTIONS.map(option => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </FilterSelect>
        </FilterGroup>

        {localTimeRangePreset === 'custom' && (
          <>
            <FilterGroup>
              <FilterLabel htmlFor="custom-start">From:</FilterLabel>
              <FilterInput
                id="custom-start"
                type="date"
                value={localCustomStartDate}
                onChange={e => setLocalCustomStartDate(e.target.value)}
              />
            </FilterGroup>
            <FilterGroup>
              <FilterLabel htmlFor="custom-end">To:</FilterLabel>
              <FilterInput
                id="custom-end"
                type="date"
                value={localCustomEndDate}
                onChange={e => setLocalCustomEndDate(e.target.value)}
              />
            </FilterGroup>
          </>
        )}

        <FilterSeparator />

        <FilterGroup>
          <FilterLabel htmlFor="task-filter">Search:</FilterLabel>
          <FilterInput
            id="task-filter"
            type="text"
            placeholder="Filter tasks..."
            value={localTaskFilter}
            onChange={e => setLocalTaskFilter(e.target.value)}
          />
        </FilterGroup>

        <FilterSeparator />

        <FilterGroup>
          <FilterLabel htmlFor="granularity">View:</FilterLabel>
          <FilterSelect
            id="granularity"
            value={localTimeGranularity}
            onChange={e => {
              setShouldResetZoom(true);
              setLocalTimeGranularity(e.target.value as TimeGranularity);
            }}
          >
            {GRANULARITY_OPTIONS.map(option => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </FilterSelect>
        </FilterGroup>

        {activeFilterCount > 0 && (
          <>
            <FilterSeparator />
            <ClearFiltersButton onClick={handleClearFilters}>
              Clear Filters
            </ClearFiltersButton>
          </>
        )}
      </FilterToolbar>

      <div ref={chartRef} style={{ width: '100%', height: '100%' }} />
    </StyledContainer>
  );
}
