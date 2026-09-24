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
import { MouseEvent, useCallback, useMemo, useState } from 'react';
import { styled, useTheme } from '@apache-superset/core/theme';
import { t } from '@apache-superset/core/translation';
import { Slider } from '@superset-ui/core/components';
import type { DataRecord, NumberFormatter } from '@superset-ui/core';
import {
  DAY_MS,
  Granularity,
  GRANULARITY_ORDER,
  PivotGanttProps,
} from './types';

const KEY_SEP = '\u0000';
const ROW_PAD = 4;
const SUMMARY_H = 12;
const MIN_ROW_H = 26;
const MARGIN = 8;
const HIER_COL_W = 150;
const METRIC_COL_W = 100;
const UNIT_MIN_PX = 25;
const UNIT_DAYS: Record<Granularity, number> = {
  P1D: 1,
  P1W: 7,
  P1M: 30,
  P3M: 120,
  P1Y: 365,
};

interface Marker {
  start: number;
  end: number;
  label: string;
  color: string;
  progress: number;
  left: string[];
  right: string[];
  top: string[];
  bottom: string[];
  description: string[];
}

interface Node {
  key: string;
  path: string[];
  depth: number;
  isLeaf: boolean;
  children: Node[];
  metrics: DataRecord;
  marker?: Marker;
}

interface CalendarCell {
  key: string;
  label: string;
  width: number;
}

interface Hint {
  x: number;
  y: number;
  node: Node;
}

const keyOf = (path: string[]) => path.join(KEY_SEP);

const toTime = (v: unknown): number | null => {
  if (v === null || v === undefined || v === '') return null;
  const d = typeof v === 'number' ? new Date(v) : new Date(String(v));
  const ms = d.getTime();
  return Number.isNaN(ms) ? null : ms;
};

const startOfDay = (ms: number) => {
  const d = new Date(ms);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
};

const dayDiff = (a: number, b: number) =>
  Math.round((startOfDay(b) - startOfDay(a)) / DAY_MS);

const withAlpha = (color: string, alpha: number): string => {
  const hex = color.match(/^#([0-9a-f]{6})$/i);
  if (hex) {
    const n = parseInt(hex[1], 16);
    return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${alpha})`;
  }
  const rgb = color.match(/^rgba?\(([^)]+)\)$/i);
  if (rgb) {
    const [r, g, b] = rgb[1].split(',').map(s => s.trim());
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }
  return color;
};

const lang = () =>
  typeof document !== 'undefined' && document.documentElement.lang
    ? document.documentElement.lang.replace('_', '-')
    : 'en';

const isoWeek = (d: Date) => {
  const tmp = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const day = tmp.getUTCDay() || 7;
  tmp.setUTCDate(tmp.getUTCDate() + 4 - day);
  const yearStart = Date.UTC(tmp.getUTCFullYear(), 0, 1);
  return Math.ceil(((tmp.getTime() - yearStart) / DAY_MS + 1) / 7);
};

const unitStart = (ms: number, g: Granularity): number => {
  const d = new Date(ms);
  d.setHours(0, 0, 0, 0);
  if (g === 'P1Y') d.setMonth(0, 1);
  else if (g === 'P3M') d.setMonth(Math.floor(d.getMonth() / 3) * 3, 1);
  else if (g === 'P1M') d.setDate(1);
  else if (g === 'P1W') d.setDate(d.getDate() - ((d.getDay() + 6) % 7));
  return d.getTime();
};

const unitNext = (ms: number, g: Granularity): number => {
  const d = new Date(ms);
  if (g === 'P1Y') d.setFullYear(d.getFullYear() + 1);
  else if (g === 'P3M') d.setMonth(d.getMonth() + 3);
  else if (g === 'P1M') d.setMonth(d.getMonth() + 1);
  else if (g === 'P1W') d.setDate(d.getDate() + 7);
  else d.setDate(d.getDate() + 1);
  return d.getTime();
};

const unitLabel = (ms: number, g: Granularity): string => {
  const d = new Date(ms);
  if (g === 'P1Y') return String(d.getFullYear());
  if (g === 'P3M') return `${t('Quarter')} ${Math.floor(d.getMonth() / 3) + 1}`;
  if (g === 'P1M') return d.toLocaleString(lang(), { month: 'long' });
  if (g === 'P1W') return t('Week %s', isoWeek(d));
  return d.toLocaleDateString(lang(), { day: 'numeric', month: 'short' });
};

function buildCells(
  g: Granularity,
  rangeStart: number,
  rangeEnd: number,
  dayWidth: number,
): CalendarCell[] {
  const cells: CalendarCell[] = [];
  let cur = unitStart(rangeStart, g);
  let guard = 0;
  while (cur <= rangeEnd && guard < 5000) {
    const next = unitNext(cur, g);
    const cs = Math.max(cur, rangeStart);
    const ce = Math.min(next - DAY_MS, rangeEnd);
    const days = dayDiff(cs, ce) + 1;
    if (days > 0) {
      cells.push({
        key: `${g}-${cur}`,
        label: unitLabel(cur, g),
        width: days * dayWidth,
      });
    }
    cur = next;
    guard += 1;
  }
  return cells;
}

const asText = (v: unknown): string | null =>
  v === null || v === undefined || v === '' ? null : String(v);

interface Model {
  roots: Node[];
  errors: string[];
  dataMin?: number;
  dataMax?: number;
}

function buildModel(
  props: Pick<
    PivotGanttProps,
    | 'data'
    | 'rows'
    | 'totals'
    | 'dateStartCol'
    | 'dateEndCol'
    | 'labelCols'
    | 'progressMetric'
    | 'markersColors'
    | 'orderByCol'
    | 'orderDesc'
    | 'dateFormatter'
  >,
): Model {
  const {
    data,
    rows,
    totals,
    dateStartCol,
    dateEndCol,
    labelCols,
    progressMetric,
    markersColors,
    orderByCol,
    orderDesc,
    dateFormatter,
  } = props;
  const totalsByKey: Record<string, DataRecord> = {};
  totals.forEach((levelRows, i) => {
    const cols = rows.slice(0, i + 1);
    levelRows.forEach(r => {
      totalsByKey[keyOf(cols.map(c => String(r[c])))] = r;
    });
  });
  const colorOf = (v: string) =>
    markersColors.find(c => c.value === v)?.color ?? '#999';
  const progressOf = (metrics: DataRecord) => {
    if (!progressMetric) return 100;
    const n = Number(metrics[progressMetric]);
    if (!Number.isFinite(n)) return 100;
    return Math.max(0, Math.min(100, n * 100));
  };
  const sideLabel = (rec: DataRecord, col?: string): string | null => {
    if (!col) return null;
    const v = rec[col];
    const ms = col === dateStartCol || col === dateEndCol ? toTime(v) : null;
    return ms !== null ? dateFormatter(new Date(ms)) : asText(v);
  };

  const byKey = new Map<string, Node>();
  const roots: Node[] = [];
  const errors = new Set<string>();
  let dataMin: number | undefined;
  let dataMax: number | undefined;

  data.forEach(rec => {
    const values = rows.map(c => asText(rec[c]) ?? 'null');
    const color = colorOf(values[0]);
    const start = dateStartCol ? toTime(rec[dateStartCol]) : null;
    const end = dateEndCol ? toTime(rec[dateEndCol]) : null;
    if (start === null) {
      errors.add(
        t(
          'Invalid values in the "Start Date" field. Please make sure all values in the selected column are valid dates.',
        ),
      );
    }
    if (end === null) {
      errors.add(
        t(
          'Invalid values in the "End Date" field. Please make sure all values in the selected column are valid dates.',
        ),
      );
    }
    if (start !== null && end !== null && end < start) {
      errors.add(
        t(
          '"Start Date" is later than "End Date". Please ensure that the start date is earlier than or equal to the end date.',
        ),
      );
    }
    const description = labelCols.description
      .map(c => asText(rec[c]))
      .filter((s): s is string => s !== null);
    const left = sideLabel(rec, labelCols.left);
    const right = sideLabel(rec, labelCols.right);
    const top = sideLabel(rec, labelCols.top);
    const bottom = sideLabel(rec, labelCols.bottom);

    let parent: Node | undefined;
    for (let level = 1; level <= rows.length; level += 1) {
      const path = values.slice(0, level);
      const key = keyOf(path);
      let node = byKey.get(key);
      if (!node) {
        node = {
          key,
          path,
          depth: level - 1,
          isLeaf: level === rows.length,
          children: [],
          metrics: totalsByKey[key] ?? {},
        };
        byKey.set(key, node);
        (parent ? parent.children : roots).push(node);
      }
      if (start !== null && end !== null && end >= start) {
        dataMin = dataMin === undefined ? start : Math.min(dataMin, start);
        dataMax = dataMax === undefined ? end : Math.max(dataMax, end);
        const add = (arr: string[], v: string | null) =>
          v !== null && !arr.includes(v) ? [...arr, v] : arr;
        if (node.marker) {
          node.marker.start = Math.min(node.marker.start, start);
          node.marker.end = Math.max(node.marker.end, end);
          node.marker.left = add(node.marker.left, left);
          node.marker.right = add(node.marker.right, right);
          node.marker.top = add(node.marker.top, top);
          node.marker.bottom = add(node.marker.bottom, bottom);
          description.forEach(d => {
            node!.marker!.description = add(node!.marker!.description, d);
          });
        } else {
          node.marker = {
            start,
            end,
            label: path[level - 1],
            color,
            progress: progressOf(node.metrics),
            left: add([], left),
            right: add([], right),
            top: add([], top),
            bottom: add([], bottom),
            description: Array.from(new Set(description)),
          };
        }
      }
      parent = node;
    }
  });

  if (orderByCol) {
    const isMetric = !rows.includes(orderByCol);
    const cmp = (a: Node, b: Node) => {
      const va = isMetric ? a.metrics[orderByCol] : a.path[a.depth];
      const vb = isMetric ? b.metrics[orderByCol] : b.path[b.depth];
      const na = Number(va);
      const nb = Number(vb);
      const r =
        Number.isFinite(na) && Number.isFinite(nb)
          ? na - nb
          : String(va ?? '').localeCompare(String(vb ?? ''));
      return orderDesc ? -r : r;
    };
    const sortTree = (nodes: Node[]) => {
      nodes.sort(cmp);
      nodes.forEach(n => sortTree(n.children));
    };
    sortTree(roots);
  }

  return { roots, errors: Array.from(errors), dataMin, dataMax };
}

const Styles = styled.div<{ height: number; width: number }>`
  ${({ theme, height, width }) => `
    height: ${height}px;
    width: ${width}px;
    display: flex;
    flex-direction: column;
    font-family: ${theme.fontFamily};
    color: ${theme.colorText};
    position: relative;
    overflow: hidden;

    .pgError {
      margin: ${theme.sizeUnit}px ${MARGIN}px;
      padding: ${theme.sizeUnit * 2}px;
      border: 1px solid ${theme.colorWarning};
      background: ${theme.colorWarningBg};
      color: ${theme.colorWarningText};
      border-radius: ${theme.borderRadius}px;
      font-size: ${theme.fontSizeSM}px;
    }
    .pgSlider {
      padding: ${theme.sizeUnit}px ${MARGIN * 3}px 0;
      flex: 0 0 auto;
    }
    .pgScroll {
      flex: 1 1 auto;
      min-height: 0;
      margin: 0 ${MARGIN}px;
      overflow: auto;
      display: flex;
      align-items: flex-start;
      border: 1px solid ${theme.colorBorderSecondary};
      border-radius: ${theme.borderRadius}px;
      background: ${theme.colorBgContainer};
    }
    table.pgTable {
      flex: 0 0 auto;
      table-layout: fixed;
      border-collapse: separate;
      border-spacing: 0;
      font-feature-settings: 'tnum' 1;
    }
    table.pgTable th,
    table.pgTable td {
      padding: 0 ${theme.sizeUnit}px;
      border-bottom: 1px solid ${theme.colorBorderSecondary};
      border-right: 1px solid ${theme.colorBorderSecondary};
      background: ${theme.colorBgContainer};
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      vertical-align: middle;
    }
    table.pgTable thead th {
      position: sticky;
      top: 0;
      z-index: 5;
      font-weight: ${theme.fontWeightNormal};
      box-sizing: border-box;
    }
    table.pgTable td.pgVal {
      text-align: right;
    }
    table.pgTable tr.pgSubtotal td {
      font-weight: ${theme.fontWeightStrong};
    }
    table.pgTable tr.pgSelected td {
      background: ${theme.colorPrimaryBg};
    }
    table.pgTable tfoot td {
      position: sticky;
      bottom: 0;
      z-index: 5;
      font-weight: ${theme.fontWeightStrong};
      border-top: 1px solid ${theme.colorBorderSecondary};
    }
    .pgRowLabel {
      cursor: pointer;
    }
    .pgRowLabel:hover {
      text-decoration: underline;
    }
    .pgToggle {
      display: inline-block;
      width: 14px;
      height: 14px;
      line-height: 12px;
      text-align: center;
      font-size: 11px;
      border: 1px solid ${theme.colorBorderSecondary};
      border-radius: 2px;
      margin-right: ${theme.sizeUnit}px;
      cursor: pointer;
      user-select: none;
      background: ${theme.colorFillSecondary};
    }
    .pgCalendar {
      flex: 0 0 auto;
      position: relative;
    }
    .pgCalHeader {
      position: sticky;
      top: 0;
      z-index: 5;
      background: ${theme.colorBgContainer};
      box-sizing: border-box;
    }
    .pgCalHeaderRow {
      display: flex;
      border-bottom: 1px solid ${theme.colorBorderSecondary};
      box-sizing: border-box;
    }
    .pgCalCell {
      flex: 0 0 auto;
      box-sizing: border-box;
      border-right: 1px solid ${theme.colorBorderSecondary};
      text-align: center;
      overflow: hidden;
      white-space: nowrap;
      text-overflow: ellipsis;
      text-transform: capitalize;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .pgCalBody {
      position: relative;
    }
    .pgCalRow {
      position: relative;
      border-bottom: 1px solid ${theme.colorBorderSecondary};
      box-sizing: border-box;
      cursor: pointer;
    }
    .pgCalRow.pgSelected {
      background: ${theme.colorPrimaryBg};
    }
    .pgMarker {
      position: absolute;
      border-radius: ${theme.borderRadius}px;
      box-sizing: border-box;
      z-index: 2;
    }
    .pgMarker:hover {
      overflow: visible;
      z-index: 3;
    }
    .pgLabels {
      position: absolute;
      inset: 0;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      justify-content: center;
    }
    .pgMarker:hover .pgLabels {
      overflow: visible;
    }
    .pgLabel,
    .pgDesc {
      padding: 0 ${theme.sizeUnit}px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      line-height: 1.3;
    }
    .pgSide {
      position: absolute;
      white-space: nowrap;
      line-height: 1.2;
    }
    .pgSideLeft {
      right: 100%;
      top: 50%;
      transform: translateY(-50%);
      padding-right: 3px;
    }
    .pgSideRight {
      left: 100%;
      top: 50%;
      transform: translateY(-50%);
      padding-left: 3px;
    }
    .pgSideTop {
      bottom: 100%;
      left: 50%;
      transform: translateX(-50%);
    }
    .pgSideBottom {
      top: 100%;
      left: 50%;
      transform: translateX(-50%);
    }
    .pgSummary {
      position: absolute;
      border-radius: ${theme.borderRadius}px;
      z-index: 2;
    }
    .pgDayLine {
      position: absolute;
      top: 0;
      bottom: 0;
      width: 2px;
      background: ${theme.colorTextBase};
      z-index: 4;
      pointer-events: none;
    }
    .pgDayPill {
      position: absolute;
      top: 2px;
      transform: translateX(-50%);
      background: ${theme.colorTextBase};
      color: ${theme.colorBgContainer};
      border-radius: ${theme.borderRadius * 2}px;
      padding: 1px 6px;
      font-size: ${theme.fontSizeXS}px;
      z-index: 4;
      pointer-events: none;
      white-space: nowrap;
    }
    .pgLegend {
      flex: 0 0 auto;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: ${theme.sizeUnit * 3}px;
      padding: ${theme.sizeUnit}px ${MARGIN}px;
    }
    .pgLegendItem {
      display: inline-flex;
      align-items: center;
      gap: ${theme.sizeUnit}px;
    }
    .pgLegendItem i {
      display: inline-block;
      width: 30px;
      height: 12px;
    }
    .pgHint {
      position: fixed;
      z-index: 1000;
      background: ${theme.colorBgElevated};
      color: ${theme.colorText};
      border: 1px solid ${theme.colorBorderSecondary};
      border-radius: ${theme.borderRadius}px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
      padding: ${theme.sizeUnit * 2}px;
      max-width: 420px;
      max-height: 320px;
      overflow: auto;
      pointer-events: auto;
    }
    .pgHint table {
      border-collapse: collapse;
    }
    .pgHint td {
      padding: 2px ${theme.sizeUnit}px;
      vertical-align: top;
    }
    .pgHint td:first-child {
      color: ${theme.colorTextSecondary};
      text-align: right;
    }
    .pgHint td:last-child {
      font-weight: ${theme.fontWeightStrong};
    }
    .pgHint tr:nth-child(odd) td {
      background: ${theme.colorFillSecondary};
    }
    .pgHintClose {
      float: right;
      cursor: pointer;
      margin-left: ${theme.sizeUnit}px;
    }
  `}
`;

export default function PivotGantt(props: PivotGanttProps) {
  const {
    width,
    height,
    data,
    rows,
    metricNames,
    totals,
    grandTotals,
    dateStartCol,
    dateEndCol,
    progressMetric,
    labelCols,
    metricFormatters,
    dateFormatter,
    markersColors,
    markerOptions,
    descriptionStyle,
    detailsStyle,
    hintOptions,
    timelineOptions,
    legendOptions,
    showDayLine,
    showGrandTotal,
    hideExpandedRows,
    defaultCollapsedLevel,
    headerFontSize,
    valueFontSize,
    labelAlign,
    orderByCol,
    orderDesc,
    sliderStart,
    sliderEnd,
    emitCrossFilters,
    emitFullHierarchy,
    selectedFilters,
    setDataMask,
    setControlValue,
  } = props;
  const theme = useTheme();

  const model = useMemo(
    () =>
      buildModel({
        data,
        rows,
        totals,
        dateStartCol,
        dateEndCol,
        labelCols,
        progressMetric,
        markersColors,
        orderByCol,
        orderDesc,
        dateFormatter,
      }),
    [
      data,
      rows,
      totals,
      dateStartCol,
      dateEndCol,
      labelCols,
      progressMetric,
      markersColors,
      orderByCol,
      orderDesc,
      dateFormatter,
    ],
  );

  // ---- collapse state -----------------------------------------------------
  const [collapsedOverride, setCollapsedOverride] = useState<Record<
    string,
    boolean
  > | null>(null);
  const collapsed = useMemo(() => {
    if (collapsedOverride) return collapsedOverride;
    const out: Record<string, boolean> = {};
    const visit = (n: Node) => {
      if (!n.isLeaf) {
        out[n.key] =
          defaultCollapsedLevel > 0 &&
          rows.length - n.depth - 1 <= defaultCollapsedLevel;
        n.children.forEach(visit);
      }
    };
    model.roots.forEach(visit);
    return out;
  }, [collapsedOverride, model.roots, rows.length, defaultCollapsedLevel]);
  const toggle = useCallback(
    (key: string) =>
      setCollapsedOverride({ ...collapsed, [key]: !collapsed[key] }),
    [collapsed],
  );
  const visible = useMemo(() => {
    const out: Node[] = [];
    const visit = (n: Node) => {
      out.push(n);
      if (!n.isLeaf && !collapsed[n.key]) n.children.forEach(visit);
    };
    model.roots.forEach(visit);
    return out;
  }, [model.roots, collapsed]);

  // ---- time range (slider) ------------------------------------------------
  const [range, setRange] = useState<[number, number] | null>(null);
  const today = startOfDay(Date.now());
  const persisted = [sliderStart, sliderEnd].filter(
    (v): v is number => v !== undefined && Number.isFinite(v),
  );
  const boundsMin = startOfDay(
    Math.min(model.dataMin ?? today - 30 * DAY_MS, ...persisted),
  );
  const boundsMaxRaw = startOfDay(
    Math.max(model.dataMax ?? today + 30 * DAY_MS, ...persisted),
  );
  const boundsMax = boundsMaxRaw > boundsMin ? boundsMaxRaw : boundsMin + DAY_MS;
  const clamp = (v: number | undefined, def: number) =>
    v === undefined || !Number.isFinite(v)
      ? def
      : Math.min(boundsMax, Math.max(boundsMin, startOfDay(v)));
  const effective: [number, number] = range ?? [
    clamp(sliderStart, boundsMin),
    clamp(sliderEnd, boundsMax),
  ];
  const rangeStart = Math.min(effective[0], effective[1]);
  const rangeEnd = Math.max(effective[0], effective[1], rangeStart + DAY_MS);
  const totalDays = dayDiff(rangeStart, rangeEnd) + 1;

  // ---- geometry -----------------------------------------------------------
  const tableW = rows.length * HIER_COL_W + metricNames.length * METRIC_COL_W;
  const calendarW = Math.max(120, width - 2 * MARGIN - tableW - 4);
  const dayWidth = calendarW / totalDays;
  const x = (ms: number) => dayDiff(rangeStart, ms) * dayWidth;

  const granularities = useMemo(() => {
    const sorted = [...timelineOptions.granularity].sort(
      (a, b) => GRANULARITY_ORDER.indexOf(a) - GRANULARITY_ORDER.indexOf(b),
    );
    const fit = sorted.filter(g => UNIT_DAYS[g] * dayWidth > UNIT_MIN_PX);
    return fit.length ? fit : (['P1Y'] as Granularity[]);
  }, [timelineOptions.granularity, dayWidth]);
  const headerRows = useMemo(
    () =>
      granularities.map(g => ({
        g,
        cells: buildCells(g, rangeStart, rangeEnd, dayWidth),
      })),
    [granularities, rangeStart, rangeEnd, dayWidth],
  );
  const headerRowH = timelineOptions.fontSize + 14;
  const headerH = headerRows.length * headerRowH;

  const rowHeightOf = (node: Node) => {
    if (!node.isLeaf && !collapsed[node.key]) {
      return Math.max(MIN_ROW_H, SUMMARY_H + 2 * ROW_PAD);
    }
    let h = markerOptions.height + 2 * ROW_PAD;
    if (node.isLeaf && node.marker) {
      const f = detailsStyle.fontSize + 2;
      if (node.marker.top.length) h += f;
      if (node.marker.bottom.length) h += f;
    }
    return Math.max(MIN_ROW_H, h);
  };
  const totalRowH = MIN_ROW_H;

  // ---- formatting ---------------------------------------------------------
  const fmt = (metric: string, v: unknown) => {
    if (v === null || v === undefined || v === '') return '';
    const f = metricFormatters[metric] as NumberFormatter | undefined;
    const n = Number(v);
    return f && Number.isFinite(n) ? f(n) : String(v);
  };

  // ---- cross filters ------------------------------------------------------
  const isSelected = useCallback(
    (node: Node) => {
      if (!selectedFilters) return false;
      const levels = emitFullHierarchy
        ? rows.slice(0, node.depth + 1)
        : [rows[node.depth]];
      return levels.every((col, i) => {
        const idx = emitFullHierarchy ? i : node.depth;
        return selectedFilters[col]?.includes(node.path[idx]);
      });
    },
    [selectedFilters, rows, emitFullHierarchy],
  );
  const select = useCallback(
    (node: Node) => {
      if (!emitCrossFilters) return;
      const levels = emitFullHierarchy
        ? rows.map((_, i) => i).slice(0, node.depth + 1)
        : [node.depth];
      const clear = isSelected(node);
      const sel: Record<string, string[]> = {};
      levels.forEach(i => {
        sel[rows[i]] = [node.path[i]];
      });
      setDataMask({
        extraFormData: {
          filters: clear
            ? []
            : levels.map(i => ({
                col: rows[i],
                op: 'IN' as const,
                val: [node.path[i]],
              })),
        },
        filterState: {
          value: clear ? null : levels.map(i => node.path[i]),
          selectedFilters: clear ? null : sel,
        },
      });
    },
    [emitCrossFilters, emitFullHierarchy, rows, isSelected, setDataMask],
  );

  // ---- hint ---------------------------------------------------------------
  const [hint, setHint] = useState<Hint | null>(null);
  const hover = (e: MouseEvent, node: Node) => {
    if (hintOptions.show && hintOptions.trigger === 'hover') {
      setHint({ x: e.clientX, y: e.clientY, node });
    }
  };
  const leave = () => {
    if (hintOptions.trigger === 'hover') setHint(null);
  };
  const click = (e: MouseEvent, node: Node) => {
    e.stopPropagation();
    if (hintOptions.show && hintOptions.trigger === 'click') {
      setHint(hint?.node === node ? null : { x: e.clientX, y: e.clientY, node });
    }
    select(node);
  };

  // ---- renderers ----------------------------------------------------------
  const renderMarker = (node: Node) => {
    const m = node.marker;
    if (!m) return null;
    const left = x(m.start);
    const w = Math.max(2, (dayDiff(m.start, m.end) + 1) * dayWidth);
    const gradient = (alpha: number) =>
      `linear-gradient(90deg, ${m.color} ${m.progress}%, ${withAlpha(
        m.color,
        alpha,
      )} ${m.progress}%)`;
    if (!node.isLeaf && !collapsed[node.key]) {
      return (
        <div
          className="pgSummary"
          style={{
            left,
            width: w,
            top: '50%',
            height: SUMMARY_H,
            marginTop: -SUMMARY_H / 2,
            background: gradient(0.3),
          }}
          onMouseEnter={e => hover(e, node)}
          onMouseLeave={leave}
          onClick={e => click(e, node)}
          role="presentation"
        />
      );
    }
    const showSides = node.isLeaf;
    const top =
      ROW_PAD + (showSides && m.top.length ? detailsStyle.fontSize + 2 : 0);
    const desc = m.description.join(' | ');
    return (
      <div
        className="pgMarker"
        style={{
          left,
          width: w,
          top,
          height: markerOptions.height,
          background: gradient(0.5),
          color: markerOptions.fontColor,
          fontSize: markerOptions.fontSize,
        }}
        onMouseEnter={e => hover(e, node)}
        onMouseLeave={leave}
        onClick={e => click(e, node)}
        role="presentation"
      >
        {showSides && m.left.length > 0 && (
          <span
            className="pgSide pgSideLeft"
            style={{ fontSize: detailsStyle.fontSize, color: detailsStyle.color }}
          >
            {m.left.join(' | ')}
          </span>
        )}
        {showSides && m.right.length > 0 && (
          <span
            className="pgSide pgSideRight"
            style={{ fontSize: detailsStyle.fontSize, color: detailsStyle.color }}
          >
            {m.right.join(' | ')}
          </span>
        )}
        {showSides && m.top.length > 0 && (
          <span
            className="pgSide pgSideTop"
            style={{ fontSize: detailsStyle.fontSize, color: detailsStyle.color }}
          >
            {m.top.join(' | ')}
          </span>
        )}
        {showSides && m.bottom.length > 0 && (
          <span
            className="pgSide pgSideBottom"
            style={{ fontSize: detailsStyle.fontSize, color: detailsStyle.color }}
          >
            {m.bottom.join(' | ')}
          </span>
        )}
        <div className="pgLabels">
          {markerOptions.showLabel && (
            <div
              className="pgLabel"
              style={{ textAlign: markerOptions.labelAlign }}
              title={m.label}
            >
              {m.label}
            </div>
          )}
          {desc && (
            <div
              className="pgDesc"
              style={{
                textAlign: descriptionStyle.align,
                fontSize: descriptionStyle.fontSize,
                color: descriptionStyle.color,
              }}
              title={desc}
            >
              {desc}
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderHint = () => {
    if (!hint || !hintOptions.show) return null;
    const { node } = hint;
    const m = node.marker;
    return (
      <div
        className="pgHint"
        style={{
          left: hint.x + 12,
          top: hint.y + 12,
          fontSize: hintOptions.fontSize,
          whiteSpace: hintOptions.wrap ? 'normal' : 'nowrap',
        }}
      >
        {hintOptions.trigger === 'click' && (
          <span
            className="pgHintClose"
            onClick={() => setHint(null)}
            role="presentation"
          >
            ×
          </span>
        )}
        <table>
          <tbody>
            {rows.slice(0, node.depth + 1).map((r, i) => (
              <tr key={r}>
                <td>{r}</td>
                <td>{node.path[i]}</td>
              </tr>
            ))}
            {m && dateStartCol && (
              <tr>
                <td>{dateStartCol}</td>
                <td>{dateFormatter(new Date(m.start))}</td>
              </tr>
            )}
            {m && dateEndCol && (
              <tr>
                <td>{dateEndCol}</td>
                <td>{dateFormatter(new Date(m.end))}</td>
              </tr>
            )}
            {metricNames.map(mn => (
              <tr key={mn}>
                <td>{mn}</td>
                <td>{fmt(mn, node.metrics[mn])}</td>
              </tr>
            ))}
            {m && m.description.length > 0 && (
              <tr>
                <td>{labelCols.description.join(', ')}</td>
                <td>{m.description.join(' | ')}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    );
  };

  const showTotals = showGrandTotal && metricNames.length > 0;
  const todayVisible = showDayLine && today >= rangeStart && today <= rangeEnd;
  const sliderProps = {
    range: true,
    min: boundsMin,
    max: boundsMax,
    step: DAY_MS,
    value: [rangeStart, rangeEnd],
    tooltip: {
      formatter: (v?: number) =>
        v === undefined ? '' : dateFormatter(new Date(v)),
    },
    onChange: (v: number[]) => setRange([v[0], v[1]]),
    onChangeComplete: (v: number[]) =>
      setControlValue?.('slider_values', { start: v[0], end: v[1] }),
  };

  return (
    <Styles height={height} width={width}>
      {model.errors.map(err => (
        <p className="pgError" key={err}>
          <b>{t('Error')}: </b>
          {err}
        </p>
      ))}
      <div className="pgSlider">
        <Slider {...(sliderProps as any)} />
      </div>
      <div
        className="pgScroll"
        onClick={() => {
          if (hintOptions.trigger === 'click') setHint(null);
        }}
        role="presentation"
      >
        <table
          className="pgTable"
          style={{ width: tableW, fontSize: valueFontSize }}
        >
          <colgroup>
            {rows.map(r => (
              <col key={r} style={{ width: HIER_COL_W }} />
            ))}
            {metricNames.map(m => (
              <col key={m} style={{ width: METRIC_COL_W }} />
            ))}
          </colgroup>
          <thead>
            <tr>
              {rows.map(r => (
                <th
                  key={r}
                  style={{
                    height: headerH,
                    fontSize: headerFontSize,
                    textAlign: labelAlign,
                  }}
                  title={r}
                >
                  {r}
                </th>
              ))}
              {metricNames.map(m => (
                <th
                  key={m}
                  style={{
                    height: headerH,
                    fontSize: headerFontSize,
                    textAlign: labelAlign,
                  }}
                  title={m}
                >
                  {m}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map(node => {
              const h = rowHeightOf(node);
              const isCol = collapsed[node.key];
              const hideVals = hideExpandedRows && !node.isLeaf && !isCol;
              const cls = [
                node.isLeaf ? '' : 'pgSubtotal',
                isSelected(node) ? 'pgSelected' : '',
              ]
                .filter(Boolean)
                .join(' ');
              return (
                <tr key={node.key} style={{ height: h }} className={cls}>
                  {rows.map((r, i) => {
                    let content: React.ReactNode = '';
                    if (i === node.depth) {
                      content = (
                        <>
                          {!node.isLeaf && (
                            <span
                              className="pgToggle"
                              onClick={e => {
                                e.stopPropagation();
                                toggle(node.key);
                              }}
                              role="presentation"
                            >
                              {isCol ? '+' : '−'}
                            </span>
                          )}
                          <span
                            className="pgRowLabel"
                            onClick={e => click(e, node)}
                            onMouseEnter={e => hover(e, node)}
                            onMouseLeave={leave}
                            role="presentation"
                            title={node.path[i]}
                          >
                            {node.path[i]}
                          </span>
                        </>
                      );
                    } else if (i === node.depth + 1 && !node.isLeaf) {
                      content = t('Total');
                    }
                    return (
                      <td key={r} style={{ textAlign: labelAlign }}>
                        {content}
                      </td>
                    );
                  })}
                  {metricNames.map(m => (
                    <td key={m} className="pgVal">
                      {hideVals ? '' : fmt(m, node.metrics[m])}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
          {showTotals && (
            <tfoot>
              <tr style={{ height: totalRowH }}>
                <td colSpan={rows.length} style={{ textAlign: 'right' }}>
                  {t('Total')}
                </td>
                {metricNames.map(m => (
                  <td key={m} className="pgVal">
                    {fmt(m, grandTotals[m])}
                  </td>
                ))}
              </tr>
            </tfoot>
          )}
        </table>
        <div className="pgCalendar" style={{ width: calendarW }}>
          <div className="pgCalHeader" style={{ height: headerH }}>
            {headerRows.map(hr => (
              <div
                className="pgCalHeaderRow"
                key={hr.g}
                style={{ height: headerRowH, fontSize: timelineOptions.fontSize }}
              >
                {hr.cells.map(c => (
                  <div
                    className="pgCalCell"
                    key={c.key}
                    style={{ width: c.width }}
                    title={c.label}
                  >
                    <span>{c.label}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
          <div className="pgCalBody">
            {visible.map(node => (
              <div
                className={`pgCalRow ${isSelected(node) ? 'pgSelected' : ''}`}
                key={node.key}
                style={{ height: rowHeightOf(node) }}
                onClick={e => click(e, node)}
                role="presentation"
              >
                {renderMarker(node)}
              </div>
            ))}
            {showTotals && (
              <div className="pgCalRow" style={{ height: totalRowH }} />
            )}
            {todayVisible && (
              <>
                <div
                  className="pgDayLine"
                  style={{ left: x(today) + dayWidth / 2 - 1 }}
                />
                <div
                  className="pgDayPill"
                  style={{ left: x(today) + dayWidth / 2 }}
                >
                  {dateFormatter(new Date(today))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>
      {legendOptions.show && markersColors.length > 0 && (
        <div
          className="pgLegend"
          style={{ fontSize: legendOptions.fontSize, minHeight: theme.sizeUnit * 6 }}
        >
          {legendOptions.name && <span>{legendOptions.name}:</span>}
          {markersColors.map(c => (
            <span className="pgLegendItem" key={c.value}>
              <i style={{ background: c.color }} />
              {c.value}
            </span>
          ))}
        </div>
      )}
      {renderHint()}
    </Styles>
  );
}
