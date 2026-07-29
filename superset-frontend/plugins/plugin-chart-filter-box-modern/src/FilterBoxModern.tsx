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
import { useCallback, useMemo, useState } from 'react';
import { useSelector } from 'react-redux';
import { t } from '@apache-superset/core/translation';
import {
  SupersetClient,
  ensureIsArray,
  DataMaskStateWithId,
  QueryObjectFilterClause,
} from '@superset-ui/core';
import { AsyncSelect, Button, SelectValue } from '@superset-ui/core/components';
import { FilterBoxModernTransformedProps, FilterValue } from './types';

// AsyncSelect (labelInValue) keeps values as {label, value, key}; the state
// holds those labeled values (so the `value` prop stays consistent), and we
// unwrap to raw values only when emitting the cross-filter.
type Selection = Record<string, unknown[]>;

function toRawValues(vals: unknown): FilterValue[] {
  return ensureIsArray(vals).map(v =>
    v && typeof v === 'object' && 'value' in (v as object)
      ? (v as { value: FilterValue }).value
      : (v as FilterValue),
  );
}

/**
 * Server-side, paginated value fetcher for one column. Searches with
 * LOWER(col) LIKE LOWER('%term%') so it works on Databend (no ILIKE) and is
 * case-insensitive. Lets the user reach ALL values, not just the first 1000.
 *
 * `dashboardFilters` are the dashboard's native filters scoped to this chart;
 * applying them here limits the option list to the current selections
 * (e.g. picking a Plant Key in the sidebar narrows every dropdown's values).
 */
function makeFetcher(
  datasource: string,
  col: string,
  dashboardFilters: QueryObjectFilterClause[],
) {
  const [idStr, type] = (datasource || '__table').split('__');
  const id = Number(idStr);
  return async (search: string, page: number, pageSize: number) => {
    const safe = (search || '').replace(/'/g, "''");
    const where = search
      ? `LOWER("${col}") LIKE LOWER('%${safe}%')`
      : undefined;
    const { json } = await SupersetClient.post({
      endpoint: '/api/v1/chart/data',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        datasource: { id, type },
        queries: [
          {
            columns: [col],
            metrics: [],
            orderby: [],
            ...(dashboardFilters.length
              ? { filters: dashboardFilters }
              : {}),
            row_limit: pageSize,
            row_offset: page * pageSize,
            ...(where ? { extras: { where } } : {}),
          },
        ],
        result_format: 'json',
        result_type: 'full',
      }),
    });
    const rows = (json?.result?.[0]?.data ?? []) as Record<
      string,
      FilterValue
    >[];
    const data = rows
      .map(r => r[col])
      .filter(v => v !== null && v !== undefined)
      .map(v => ({ label: String(v), value: v as string | number }));
    const totalCount =
      page * pageSize + data.length + (data.length === pageSize ? pageSize : 0);
    return { data, totalCount };
  };
}

export default function FilterBoxModern(
  props: FilterBoxModernTransformedProps,
) {
  const {
    width,
    height,
    filterColumns,
    datasource,
    rowLimit,
    instantFiltering,
    setDataMask,
    dashboardFilters,
  } = props;
  const [selected, setSelected] = useState<Selection>({});

  // Native (sidebar) filters live in the dashboard's `dataMask`, not in this
  // chart's formData. Read them from the store and keep only the dashboard
  // native filters (keys prefixed `NATIVE_FILTER-`); chart cross-filters use
  // numeric keys (including this box itself) and are skipped so the box does
  // not limit its own options. Combined with `dashboardFilters` (the chart's
  // own "Limit selector values"), these scope every option query.
  const dataMask = useSelector(
    (state: { dataMask?: DataMaskStateWithId }) => state.dataMask,
  );
  const activeFilters = useMemo(() => {
    const fromSidebar = Object.entries(dataMask ?? {})
      .filter(([id]) => id.startsWith('NATIVE_FILTER-'))
      .flatMap(([, mask]) => ensureIsArray(mask?.extraFormData?.filters));
    return [...dashboardFilters, ...fromSidebar];
  }, [dataMask, dashboardFilters]);

  const fetchers = useMemo(
    () =>
      Object.fromEntries(
        filterColumns.map(col => [
          col,
          makeFetcher(datasource, col, activeFilters),
        ]),
      ),
    [datasource, filterColumns, activeFilters],
  );

  const emit = useCallback(
    (sel: Selection) => {
      const filters = Object.entries(sel)
        .filter(([, vals]) => vals && vals.length > 0)
        .map(([col, vals]) => ({ col, op: 'IN' as const, val: toRawValues(vals) }));
      setDataMask({
        extraFormData: { filters },
        filterState: { value: filters.length ? filters : null },
      });
    },
    [setDataMask],
  );

  const onColumnChange = useCallback(
    (col: string, vals: unknown[]) => {
      setSelected(prev => {
        const next = { ...prev, [col]: vals };
        if (instantFiltering) {
          emit(next);
        }
        return next;
      });
    },
    [emit, instantFiltering],
  );

  return (
    <div style={{ width, height, overflow: 'auto', padding: 8 }}>
      {filterColumns.map(col => (
        <div key={col} style={{ marginBottom: 12 }}>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>{col}</div>
          <AsyncSelect
            mode="multiple"
            allowClear
            ariaLabel={col}
            placeholder={t('Type to search %s', col)}
            value={(selected[col] ?? []) as SelectValue}
            options={fetchers[col]}
            pageSize={rowLimit}
            onChange={(vals: unknown) => onColumnChange(col, ensureIsArray(vals))}
            css={{ width: '100%' }}
          />
        </div>
      ))}
      {!instantFiltering && (
        <Button
          buttonStyle="primary"
          buttonSize="small"
          onClick={() => emit(selected)}
        >
          {t('Apply')}
        </Button>
      )}
    </div>
  );
}
