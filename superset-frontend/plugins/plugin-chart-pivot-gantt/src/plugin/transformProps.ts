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
import {
  CategoricalColorNamespace,
  ChartProps,
  DataRecord,
  ensureIsArray,
  getColumnLabel,
  getMetricLabel,
  getNumberFormatter,
  getTimeFormatter,
  QueryFormColumn,
  QueryFormMetric,
} from '@superset-ui/core';
import {
  Granularity,
  GRANULARITY_ORDER,
  HAlign,
  PivotGanttProps,
  RgbaColor,
} from '../types';

const toCss = (c: RgbaColor | string | undefined, fallback: string): string => {
  if (!c) return fallback;
  if (typeof c === 'string') return c;
  return `rgba(${c.r}, ${c.g}, ${c.b}, ${c.a ?? 1})`;
};

const positive = (v: unknown, def: number): number => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : def;
};

const firstLabel = (c: unknown): string | undefined => {
  const arr = (ensureIsArray(c) as unknown[]).flat().filter(Boolean);
  return arr.length ? getColumnLabel(arr[0] as QueryFormColumn) : undefined;
};

const align = (v: unknown, def: HAlign): HAlign =>
  v === 'left' || v === 'center' || v === 'right' ? v : def;

export default function transformProps(chartProps: ChartProps): PivotGanttProps {
  const {
    width,
    height,
    queriesData = [],
    formData,
    rawFormData,
    hooks,
    datasource,
    emitCrossFilters = false,
    filterState = {},
  } = chartProps;
  const fd = formData as Record<string, any>;
  const raw = (rawFormData ?? {}) as Record<string, any>;
  const { setDataMask = () => {}, setControlValue } = hooks;

  const data = (queriesData[0]?.data ?? []) as DataRecord[];
  const grandTotals = (queriesData[1]?.data?.[0] ?? {}) as DataRecord;
  const totals = queriesData.slice(2).map(q => (q.data ?? []) as DataRecord[]);

  const rows = ensureIsArray(fd.groupbyRows).map(c =>
    getColumnLabel(c as QueryFormColumn),
  );
  const metricNames = ensureIsArray(fd.metrics).map(m =>
    getMetricLabel(m as QueryFormMetric),
  );

  const metricsConfig = (raw.metrics_config ?? {}) as Record<
    string,
    { d3NumberFormat?: string }
  >;
  const columnFormats = ((datasource as any)?.columnFormats ?? {}) as Record<
    string,
    string
  >;
  const valueFormat = fd.valueFormat || 'SMART_NUMBER';
  const metricFormatters = Object.fromEntries(
    metricNames.map(m => [
      m,
      getNumberFormatter(
        metricsConfig[m]?.d3NumberFormat || columnFormats[m] || valueFormat,
      ),
    ]),
  );

  const dateFormat: string = fd.dateFormat || '%d.%m.%Y';
  const dateFormatter = getTimeFormatter(dateFormat);

  const sliceId = fd.sliceId as number | undefined;
  const scale = CategoricalColorNamespace.getScale(fd.colorScheme);
  const firstCol = rows[0];
  const markersColors = firstCol
    ? Array.from(new Set(data.map(r => String(r[firstCol])))).map(value => ({
        value,
        color: scale(value, sliceId),
      }))
    : [];

  let granularity = ensureIsArray(fd.timelineFormat).filter(g =>
    GRANULARITY_ORDER.includes(g as Granularity),
  ) as Granularity[];
  if (!granularity.length) granularity = ['P1Y'];

  const sliderValues = (fd.sliderValues ?? {}) as {
    start?: number;
    end?: number;
  };
  const progress = fd.markerProgressCol as string | undefined;

  return {
    width,
    height,
    data,
    rows,
    metricNames,
    totals,
    grandTotals,
    dateStartCol: firstLabel(fd.dateStartCol),
    dateEndCol: firstLabel(fd.dateEndCol),
    progressMetric: progress && metricNames.includes(progress) ? progress : undefined,
    labelCols: {
      left: firstLabel(fd.markerLabelLeftCol),
      right: firstLabel(fd.markerLabelRightCol),
      top: firstLabel(fd.markerLabelTopCol),
      bottom: firstLabel(fd.markerLabelBottomCol),
      description: ensureIsArray(fd.markerDescriptionCols).map(c =>
        getColumnLabel(c as QueryFormColumn),
      ),
    },
    metricFormatters,
    dateFormatter,
    markersColors,
    markerOptions: {
      height: positive(fd.markerHeight, 24),
      fontSize: positive(fd.markerFontSize, 12),
      fontColor: toCss(fd.markerFontColor, '#fff'),
      labelAlign: align(fd.markerLabelAlign, 'center'),
      showLabel: fd.showMarkerLabel ?? true,
    },
    descriptionStyle: {
      fontSize: positive(fd.markerDescriptionFontSize, 12),
      color: toCss(fd.markerDescriptionFontColor, '#fff'),
      align: align(fd.markerDescriptionLabelAlign, 'center'),
    },
    detailsStyle: {
      fontSize: positive(fd.markerDetailFontSize, 12),
      color: toCss(fd.markerDetailFontColor, '#000'),
    },
    hintOptions: {
      show: fd.showHint ?? true,
      fontSize: Math.min(16, Math.max(9, positive(fd.hintFontSize, 12))),
      trigger: fd.hintTrigger === 'click' ? 'click' : 'hover',
      wrap: fd.hintWrapText ?? true,
    },
    timelineOptions: {
      granularity,
      fontSize: positive(fd.timelineFontSize, 10),
    },
    legendOptions: {
      show: fd.showLegend ?? true,
      name: fd.legendName ?? '',
      fontSize: positive(fd.legendFontSize, 12),
    },
    showDayLine: fd.showDayLine ?? true,
    showGrandTotal: fd.showGrandTotal ?? true,
    hideExpandedRows: fd.hideExpandedRows ?? false,
    defaultCollapsedLevel: Number(fd.defaultCollapsedLevel) || 0,
    headerFontSize: positive(fd.headerFontSize, 12),
    valueFontSize: positive(fd.valueFontSize, 12),
    labelAlign: align(fd.labelAlign, 'left'),
    orderByCol: ensureIsArray(fd.orderByCol)[0] as string | undefined,
    orderDesc: fd.orderDesc ?? true,
    sliderStart: Number.isFinite(Number(sliderValues.start))
      ? Number(sliderValues.start)
      : undefined,
    sliderEnd: Number.isFinite(Number(sliderValues.end))
      ? Number(sliderValues.end)
      : undefined,
    emitCrossFilters,
    emitFullHierarchy: fd.emitFullHierarchy ?? true,
    selectedFilters: filterState.selectedFilters ?? null,
    setDataMask,
    setControlValue: setControlValue as
      | ((name: string, value: unknown) => void)
      | undefined,
    sliceId,
  };
}
