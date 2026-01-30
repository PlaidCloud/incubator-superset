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
import { GanttTask, PluginChartGanttProps } from '../types';

// Mock data for demonstration
const MOCK_CATEGORIES = [
  'Project Alpha',
  'Project Beta',
  'Project Gamma',
  'Project Delta',
  'Project Epsilon',
];

const MOCK_DATA: GanttTask[] = [
  { categoryIndex: 0, taskName: 'Planning', startTime: '2024-01-01', endTime: '2024-01-15', color: '#5470c6' },
  { categoryIndex: 0, taskName: 'Design', startTime: '2024-01-15', endTime: '2024-02-01', color: '#91cc75' },
  { categoryIndex: 0, taskName: 'Development', startTime: '2024-02-01', endTime: '2024-03-15', color: '#fac858' },
  { categoryIndex: 1, taskName: 'Research', startTime: '2024-01-10', endTime: '2024-02-05', color: '#ee6666' },
  { categoryIndex: 1, taskName: 'Implementation', startTime: '2024-02-05', endTime: '2024-03-20', color: '#73c0de' },
  { categoryIndex: 2, taskName: 'Analysis', startTime: '2024-01-20', endTime: '2024-02-10', color: '#3ba272' },
  { categoryIndex: 2, taskName: 'Testing', startTime: '2024-02-10', endTime: '2024-03-01', color: '#fc8452' },
  { categoryIndex: 2, taskName: 'Deployment', startTime: '2024-03-01', endTime: '2024-03-10', color: '#9a60b4' },
  { categoryIndex: 3, taskName: 'Sprint 1', startTime: '2024-01-05', endTime: '2024-01-25', color: '#ea7ccc' },
  { categoryIndex: 3, taskName: 'Sprint 2', startTime: '2024-01-25', endTime: '2024-02-15', color: '#5470c6' },
  { categoryIndex: 3, taskName: 'Sprint 3', startTime: '2024-02-15', endTime: '2024-03-05', color: '#91cc75' },
  { categoryIndex: 4, taskName: 'Phase 1', startTime: '2024-01-01', endTime: '2024-02-01', color: '#fac858' },
  { categoryIndex: 4, taskName: 'Phase 2', startTime: '2024-02-01', endTime: '2024-03-01', color: '#ee6666' },
  { categoryIndex: 4, taskName: 'Phase 3', startTime: '2024-03-01', endTime: '2024-03-25', color: '#73c0de' },
];

const HEIGHT_RATIO = 0.6;
const DIM_CATEGORY_INDEX = 0;
const DIM_TIME_START = 1;
const DIM_TIME_END = 2;
const DIM_TASK_NAME = 3;
const DIM_COLOR = 4;

function renderGanttItem(
  params: { coordSys: { x: number; y: number; width: number; height: number } },
  api: {
    value: (dim: number) => number | string;
    coord: (data: [number | string, number]) => [number, number];
    size: (data: [number, number]) => [number, number];
    style: (opts?: { fill?: string; stroke?: string; text?: string; textFill?: string }) => Record<string, unknown>;
  },
) {
  const categoryIndex = api.value(DIM_CATEGORY_INDEX) as number;
  const startTime = api.coord([api.value(DIM_TIME_START), categoryIndex]);
  const endTime = api.coord([api.value(DIM_TIME_END), categoryIndex]);
  const barLength = endTime[0] - startTime[0];
  const barHeight = api.size([0, 1])[1] * HEIGHT_RATIO;
  const x = startTime[0];
  const y = startTime[1] - barHeight / 2;

  const taskName = api.value(DIM_TASK_NAME) as string;
  const color = api.value(DIM_COLOR) as string;

  const rectShape = clipRectByRect(params, { x, y, width: barLength, height: barHeight });

  return {
    type: 'group',
    children: [
      {
        type: 'rect',
        ignore: !rectShape,
        shape: rectShape,
        style: {
          fill: color,
          stroke: '#fff',
          lineWidth: 1,
        },
      },
      {
        type: 'rect',
        ignore: !rectShape || barLength < 50,
        shape: rectShape,
        style: {
          fill: 'transparent',
          text: barLength > 80 ? taskName : '',
          textFill: '#fff',
          fontSize: 11,
        },
      },
    ],
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

export default function transformProps(chartProps: ChartProps): PluginChartGanttProps {
  const { width, height, formData } = chartProps;
  const {
    title = 'Gantt Chart',
    barHeightRatio = 0.6,
    zoomable = true,
  } = formData;

  // Use mock data for now
  const categories = MOCK_CATEGORIES;
  const tasks = MOCK_DATA;

  // Transform tasks to ECharts data format: [categoryIndex, startTime, endTime, taskName, color]
  const seriesData = tasks.map(task => [
    task.categoryIndex,
    new Date(task.startTime).getTime(),
    new Date(task.endTime).getTime(),
    task.taskName,
    task.color,
  ]);

  const echartOptions: EChartsOption = {
    tooltip: {
      formatter: (params: { value: [number, number, number, string, string] }) => {
        const [, start, end, name] = params.value;
        const startDate = new Date(start).toLocaleDateString();
        const endDate = new Date(end).toLocaleDateString();
        return `<strong>${name}</strong><br/>Start: ${startDate}<br/>End: ${endDate}`;
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
      left: 120,
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
        fontSize: 12,
      },
    },
    series: [
      {
        type: 'custom',
        renderItem: renderGanttItem as unknown as (params: unknown, api: unknown) => unknown,
        encode: {
          x: [DIM_TIME_START, DIM_TIME_END],
          y: DIM_CATEGORY_INDEX,
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
    categories,
    title: title as string,
    barHeightRatio: barHeightRatio as number,
    zoomable: zoomable as boolean,
  };
}
