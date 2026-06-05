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
import { useMemo, useState } from 'react';
import { Select } from 'antd';
import ReactECharts from 'echarts-for-react';
import { getNumberFormatter } from '@superset-ui/core';
import {
  BenchmarkRangeDatum,
  BenchmarkRangeRecord,
  BenchmarkRangeSortBy,
  BenchmarkRangeSortOrder,
  BenchmarkRangeTransformedProps,
  PercentValueMode,
} from './types';

const IQR_COLOR = '#f7c9a9';
const IQR_BORDER_COLOR = '#f2a877';
const IQR_LINE_COLOR = '#a8a8a8';
const MEDIAN_COLOR = '#f47f5f';
const TARGET_COLOR = '#ff5a42';
const ACTUAL_COLOR = '#5f6368';
const ALL_VALUE = '__all__';
const CHART_ROW_HEIGHT = 26;
const CHART_VERTICAL_PADDING = 96;
const FILTER_BAR_HEIGHT = 112;

type BenchmarkMetric = 'actual' | 'median' | 'q1' | 'q3' | 'target';

function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getDisplayFactor(mode: PercentValueMode, data: BenchmarkRangeDatum[]) {
  if (mode === PercentValueMode.Fraction) {
    return 100;
  }
  if (mode === PercentValueMode.Percent) {
    return 1;
  }
  const values = data.flatMap(row => [
    Math.abs(row.q1),
    Math.abs(row.q3),
    Math.abs(row.median),
    Math.abs(row.target),
    Math.abs(row.actual),
  ]);
  const max = Math.max(...values, 0);
  return max <= 1 ? 100 : 1;
}

function getAxisExtent(data: BenchmarkRangeDatum[], factor: number) {
  const values = data.flatMap(row => [
    row.q1 * factor,
    row.q3 * factor,
    row.median * factor,
    row.target * factor,
    row.actual * factor,
    0,
  ]);
  const min = Math.min(...values, 0);
  const max = Math.max(...values, 0);
  const range = max - min || 10;
  const padding = range * 0.08;
  return {
    max: Math.ceil((max + padding) / 5) * 5,
    min: Math.floor((min - padding) / 5) * 5,
  };
}

function getTooltip(datum: BenchmarkRangeDatum, formatPercent: (value: number) => string) {
  const category = escapeHtml(datum.category);
  const gapLine = datum.formatted?.gap
    ? [
        `Gap: <span style="color: ${datum.formatted.gapColor || 'inherit'}">`,
        `${escapeHtml(datum.formatted.gap)}`,
        '</span>',
      ].join('')
    : '';
  return [
    `<strong>${category}</strong>`,
    `IQR: ${datum.formatted?.low || formatPercent(datum.q1)} - ${
      datum.formatted?.high || formatPercent(datum.q3)
    }`,
    `Median: ${datum.formatted?.median || formatPercent(datum.median)}`,
    `Target: ${datum.formatted?.target || formatPercent(datum.target)}`,
    `Actual: ${datum.formatted?.actual || formatPercent(datum.actual)}`,
    gapLine,
  ]
    .filter(Boolean)
    .join('<br />');
}

function percentile(values: number[], position: number) {
  if (!values.length) {
    return undefined;
  }
  const sorted = [...values].sort((a, b) => a - b);
  const index = (sorted.length - 1) * position;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) {
    return sorted[lower];
  }
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (index - lower);
}

function average(values: number[]) {
  return values.length
    ? values.reduce((sum, value) => sum + value, 0) / values.length
    : undefined;
}

function compareValues(
  a: BenchmarkRangeDatum,
  b: BenchmarkRangeDatum,
  sortBy: BenchmarkRangeSortBy,
  sortOrder: BenchmarkRangeSortOrder,
) {
  const direction = sortOrder === BenchmarkRangeSortOrder.Desc ? -1 : 1;
  if (sortBy === BenchmarkRangeSortBy.Category) {
    return a.category.localeCompare(b.category) * direction;
  }
  return ((a[sortBy] as number) - (b[sortBy] as number)) * direction;
}

function aggregateRecords(
  records: BenchmarkRangeRecord[],
  selectedValues: string[],
  sortBy: BenchmarkRangeSortBy,
  sortOrder: BenchmarkRangeSortOrder,
): BenchmarkRangeDatum[] {
  const hasSelection = selectedValues.length > 0;
  const groupedRecords = records.reduce<Record<string, BenchmarkRangeRecord[]>>(
    (accumulator, record) => ({
      ...accumulator,
      [record.category]: [...(accumulator[record.category] || []), record],
    }),
    {},
  );

  return Object.entries(groupedRecords)
    .map(([category, rows]) => {
      const actualValues = rows
        .map(row => row.actual)
        .filter((value): value is number => value !== undefined);
      const q1Values = rows
        .map(row => row.q1)
        .filter((value): value is number => value !== undefined);
      const q3Values = rows
        .map(row => row.q3)
        .filter((value): value is number => value !== undefined);
      const medianValues = rows
        .map(row => row.median)
        .filter((value): value is number => value !== undefined);
      const targetValues = rows
        .map(row => row.target)
        .filter((value): value is number => value !== undefined);
      const q1 = average(q1Values) ?? percentile(actualValues, 0.25) ?? 0;
      const q3 = average(q3Values) ?? percentile(actualValues, 0.75) ?? q1;
      const lower = Math.min(q1, q3);
      const upper = Math.max(q1, q3);
      const actual =
        actualValues.length > 1
          ? average(actualValues) ?? 0
          : actualValues[0] ?? average(medianValues) ?? 0;
      const midpoint =
        q1Values.length || q3Values.length ? (lower + upper) / 2 : undefined;
      const median =
        average(medianValues) ??
        midpoint ??
        percentile(actualValues, 0.5) ??
        actual;
      const target = average(targetValues) ?? median;
      const { filters: _filters, ...baseRow } = rows[0];
      const formattedSource = rows.find(row => row.formatted)?.formatted;
      const formatted = formattedSource
        ? {
            ...formattedSource,
            gapColor:
              formattedSource.gapColor ||
              (actual - target >= 0 ? '#0F6E56' : '#A32D2D'),
          }
        : undefined;

      return {
        ...baseRow,
        actual,
        category,
        formatted,
        isFiltered: hasSelection && !selectedValues.includes(category),
        median,
        q1: lower,
        q3: upper,
        range: upper - lower,
        target,
      };
    })
    .sort((a, b) => compareValues(a, b, sortBy, sortOrder));
}

export default function PluginChartBenchmarkRange(
  props: BenchmarkRangeTransformedProps,
) {
  const {
    filterColumns,
    filterState,
    groupby,
    height,
    percentValueMode,
    records,
    sortBy,
    sortOrder,
    setDataMask,
    showFilterControls,
    showLegend,
    width,
    xAxisLabel,
  } = props;
  const [dropdownFilters, setDropdownFilters] = useState<Record<string, string>>(
    {},
  );
  const filterOptions = useMemo(
    () =>
      filterColumns.reduce<Record<string, string[]>>((accumulator, column) => {
        const values = Array.from(
          new Set(
            records
              .map(record => record.filters[column.key])
              .filter(Boolean),
          ),
        ).sort((a, b) => a.localeCompare(b));
        return {
          ...accumulator,
          [column.key]: values,
        };
      }, {}),
    [filterColumns, records],
  );
  const filteredRecords = useMemo(
    () =>
      records.filter(record =>
        filterColumns.every(column => {
          const selectedValue = dropdownFilters[column.key];
          return !selectedValue || record.filters[column.key] === selectedValue;
        }),
      ),
    [dropdownFilters, filterColumns, records],
  );
  const selectedValues = useMemo(
    () =>
      Array.isArray(filterState?.selectedValues)
        ? (filterState?.selectedValues as string[])
        : [],
    [filterState],
  );
  const data = useMemo(
    () =>
      aggregateRecords(filteredRecords, selectedValues, sortBy, sortOrder),
    [filteredRecords, selectedValues, sortBy, sortOrder],
  );
  const formatter = getNumberFormatter('SMART_NUMBER');
  const factor = getDisplayFactor(percentValueMode, data);
  const formatPercent = (value: number) => `${formatter(value * factor)}%`;
  const containerHeight = Math.max(0, height - 2);
  const containerWidth = Math.max(0, width - 2);
  const hasFilterControls = showFilterControls && filterColumns.length > 0;
  const filterBarHeight = hasFilterControls ? FILTER_BAR_HEIGHT : 0;
  const chartHeight = Math.max(0, containerHeight - filterBarHeight);
  const renderedChartHeight = Math.max(
    chartHeight,
    data.length * CHART_ROW_HEIGHT + CHART_VERTICAL_PADDING,
  );

  const option = useMemo<any>(() => {
    const categories = data.map(row => row.category);
    const maxLabelLength = Math.max(
      ...categories.map(category => category.length),
      12,
    );
    const left = Math.min(260, Math.max(120, maxLabelLength * 7 + 28));
    const yAxisNameGap = Math.max(88, left - 12);
    const extent = getAxisExtent(data, factor);
    const scaled = (value: number) => value * factor;
    const markerData = (metric: BenchmarkMetric, color: string) =>
      data.map(row => ({
        benchmark: row,
        itemStyle: {
          color,
          opacity: row.isFiltered ? 0.25 : 1,
        },
        value: [scaled(row[metric] as number), row.category],
      }));

    return {
      animationDuration: 250,
      animationDurationUpdate: 250,
      grid: {
        bottom: 44,
        containLabel: false,
        left,
        right: 28,
        top: showLegend ? 44 : 18,
      },
      legend: {
        data: [
          {
            icon: 'circle',
            itemStyle: {
              color: IQR_COLOR,
            },
            name: 'IQR',
          },
          {
            icon: 'circle',
            itemStyle: {
              color: MEDIAN_COLOR,
            },
            name: 'Median',
          },
          {
            icon: 'circle',
            itemStyle: {
              color: TARGET_COLOR,
            },
            name: 'Target',
          },
          {
            icon: 'circle',
            itemStyle: {
              color: ACTUAL_COLOR,
            },
            name: 'Actual',
          },
        ],
        show: showLegend,
        top: 4,
        type: 'plain',
      },
      series: [
        {
          data: data.map(row => ({
            benchmark: row,
            value: [scaled(row.q1), scaled(row.q3), row.category],
          })),
          emphasis: {
            focus: 'self',
          },
          encode: {
            x: [0, 1],
            y: 2,
          },
          itemStyle: {
            color: IQR_COLOR,
          },
          name: 'IQR',
          progressive: 1000,
          renderItem: (params: any, api: any) => {
            const q1 = api.value(0);
            const q3 = api.value(1);
            const category = api.value(2);
            const start = api.coord([q1, category]);
            const end = api.coord([q3, category]);
            const bandSize = api.size([0, 1]);
            const bandHeight = Math.min(16, Math.max(8, bandSize[1] * 0.55));
            const capHeight = Math.max(22, bandHeight + 8);
            const centerY = start[1];
            const row = data[params.dataIndex] as BenchmarkRangeDatum | undefined;

            if (!Number.isFinite(start[0]) || !Number.isFinite(end[0])) {
              return null;
            }

            return {
              children: [
                {
                  shape: {
                    height: bandHeight,
                    width: Math.abs(end[0] - start[0]),
                    x: Math.min(start[0], end[0]),
                    y: centerY - bandHeight / 2,
                  },
                  style: {
                    fill: IQR_COLOR,
                    opacity: row?.isFiltered ? 0.25 : 0.9,
                    stroke: IQR_BORDER_COLOR,
                  },
                  type: 'rect',
                },
                {
                  shape: {
                    x1: start[0],
                    x2: end[0],
                    y1: centerY,
                    y2: centerY,
                  },
                  style: {
                    stroke: IQR_LINE_COLOR,
                    lineWidth: 1.5,
                    opacity: row?.isFiltered ? 0.35 : 1,
                  },
                  type: 'line',
                },
                {
                  shape: {
                    x1: start[0],
                    x2: start[0],
                    y1: centerY - capHeight / 2,
                    y2: centerY + capHeight / 2,
                  },
                  style: {
                    stroke: IQR_LINE_COLOR,
                    lineWidth: 1.5,
                    opacity: row?.isFiltered ? 0.35 : 1,
                  },
                  type: 'line',
                },
                {
                  shape: {
                    x1: end[0],
                    x2: end[0],
                    y1: centerY - capHeight / 2,
                    y2: centerY + capHeight / 2,
                  },
                  style: {
                    stroke: IQR_LINE_COLOR,
                    lineWidth: 1.5,
                    opacity: row?.isFiltered ? 0.35 : 1,
                  },
                  type: 'line',
                },
              ],
              type: 'group',
            };
          },
          type: 'custom',
        },
        {
          data: markerData('median', MEDIAN_COLOR),
          itemStyle: {
            color: MEDIAN_COLOR,
          },
          name: 'Median',
          symbol: 'circle',
          symbolSize: 8,
          type: 'scatter',
        },
        {
          data: markerData('target', TARGET_COLOR),
          itemStyle: {
            color: TARGET_COLOR,
          },
          name: 'Target',
          symbol: 'circle',
          symbolSize: 8,
          type: 'scatter',
        },
        {
          data: markerData('actual', ACTUAL_COLOR),
          itemStyle: {
            color: ACTUAL_COLOR,
          },
          name: 'Actual',
          symbol: 'circle',
          symbolSize: 8,
          type: 'scatter',
        },
      ],
      tooltip: {
        axisPointer: {
          type: 'shadow',
        },
        confine: true,
        formatter: (params: any) => {
          const items = Array.isArray(params) ? params : [params];
          const datum = items.find(item => item?.data?.benchmark)?.data
            ?.benchmark as BenchmarkRangeDatum | undefined;
          return datum ? getTooltip(datum, formatPercent) : '';
        },
        trigger: 'axis',
      },
      xAxis: {
        axisLabel: {
          formatter: (value: number) => `${formatter(value)}%`,
        },
        max: extent.max,
        min: extent.min,
        name: xAxisLabel,
        nameGap: 28,
        nameLocation: 'middle',
        splitLine: {
          lineStyle: {
            opacity: 0.45,
          },
        },
        type: 'value',
      },
      yAxis: {
        axisLabel: {
          hideOverlap: false,
        },
        axisTick: {
          show: false,
        },
        data: categories,
        inverse: true,
        name: 'Profit Center',
        nameGap: yAxisNameGap,
        nameLocation: 'middle',
        triggerEvent: true,
        type: 'category',
      },
    };
  }, [
    data,
    factor,
    formatter,
    formatPercent,
    chartHeight,
    showLegend,
    xAxisLabel,
  ]);

  const onEvents = useMemo(
    () => ({
      click: (params: any) => {
        const datum = params?.data?.benchmark as BenchmarkRangeDatum | undefined;
        const selectedName = datum?.category;
        if (!selectedName || !groupby.length) {
          return;
        }
        const currentValues = filterState?.selectedValues || [];
        const isSelected = currentValues.includes(selectedName);
        const nextValues =
          currentValues.length === 1 && isSelected ? [] : [selectedName];

        setDataMask({
          extraFormData: {
            filters: [
              {
                col: groupby[0],
                op: nextValues.length ? 'IN' : 'IS NOT NULL',
                val: nextValues.length ? nextValues : null,
              } as any,
            ],
          },
          filterState: {
            selectedValues: nextValues.length ? nextValues : null,
            value: nextValues.length ? nextValues : null,
          },
        });
      },
    }),
    [filterState, groupby, setDataMask],
  );

  return (
    <div
      style={{
        boxSizing: 'border-box',
        height: containerHeight,
        overflow: 'hidden',
        width: containerWidth,
      }}
    >
      <style>
        {`
          .benchmark-range-filter-dropdown .ant-select-item {
            height: auto;
            min-height: 32px;
          }
          .benchmark-range-filter-dropdown .ant-select-item-option-content {
            overflow: visible;
            text-overflow: clip;
            white-space: normal;
            word-break: normal;
          }
        `}
      </style>
      {hasFilterControls && (
        <div
          style={{
            boxSizing: 'border-box',
            height: FILTER_BAR_HEIGHT,
            overflow: 'hidden',
            padding: '4px 0 12px',
            width: '100%',
          }}
        >
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: 12,
              justifyContent: 'center',
              overflow: 'hidden',
            }}
          >
            {filterColumns.map(column => (
              <div key={column.key} style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 12, marginBottom: 4 }}>
                  {column.label}
                </div>
                <Select
                  dropdownClassName="benchmark-range-filter-dropdown"
                  dropdownMatchSelectWidth={false}
                  dropdownStyle={{
                    maxWidth: 520,
                    minWidth: 220,
                  }}
                  value={dropdownFilters[column.key] || ALL_VALUE}
                  onChange={(value: string) =>
                    setDropdownFilters(currentFilters => {
                      const nextFilters = { ...currentFilters };
                      if (value === ALL_VALUE) {
                        delete nextFilters[column.key];
                      } else {
                        nextFilters[column.key] = value;
                      }
                      return nextFilters;
                    })
                  }
                  style={{ minWidth: 120 }}
                >
                  <Select.Option value={ALL_VALUE}>All</Select.Option>
                  {(filterOptions[column.key] || []).map(value => (
                    <Select.Option key={value} title={value} value={value}>
                      {value}
                    </Select.Option>
                  ))}
                </Select>
              </div>
            ))}
          </div>
        </div>
      )}
      <div
        style={{
          height: chartHeight,
          overflowX: 'hidden',
          overflowY: renderedChartHeight > chartHeight ? 'auto' : 'hidden',
          width: containerWidth,
        }}
      >
        <ReactECharts
          lazyUpdate
          notMerge
          onEvents={onEvents}
          option={option}
          opts={{ renderer: 'canvas' }}
          style={{ height: renderedChartHeight, width: containerWidth }}
        />
      </div>
    </div>
  );
}
