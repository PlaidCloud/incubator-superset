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
  useRef,
  ReactNode,
  ReactElement,
  HTMLProps,
  MutableRefObject,
  CSSProperties,
  DragEvent,
  useState,
  cloneElement,
  isValidElement,
} from 'react';

import {
  useReactTable,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getExpandedRowModel,
  ColumnFiltersState,
  SortingState,
  ExpandedState,
  ColumnDef,
  flexRender,
  getGroupedRowModel,
} from '@tanstack/react-table';
import { css } from '@apache-superset/core/theme';
import { typedMemo } from '@superset-ui/core';

import GlobalFilter, { GlobalFilterProps } from './components/GlobalFilter';
import SelectPageSize, {
  SelectPageSizeProps,
  SizeOption,
} from './components/SelectPageSize';
import SimplePagination from './components/Pagination';
import { PAGE_SIZE_OPTIONS } from '../consts';

/**
 * Grouped rows are indented by depth. The indent cannot be passed to the cell
 * itself: `flexRender` builds an element for the column's renderer component,
 * so a `style` handed to it never reaches the `td` in the DOM. Carrying the
 * depth on the row and letting CSS reach the first cell keeps the indent
 * without reintroducing a wrapper `td`.
 */
const rowIndent = css`
  tbody tr[data-depth] > *:first-of-type {
    padding-left: var(--dt-row-indent, 0);
  }
`;

export interface DataTableProps<D extends object> {
  columns: (ColumnDef<D> & { name: string })[];
  data: D[];
  tableClassName?: string;
  searchInput?: boolean | GlobalFilterProps<D>['searchInput'];
  selectPageSize?: boolean | SelectPageSizeProps['selectRenderer'];
  pageSizeOptions?: SizeOption[]; // available page size options
  maxPageItemCount?: number;
  width?: string | number;
  height?: string | number;
  serverPagination?: boolean;
  onServerPaginationChange: (pageNumber: number, pageSize: number) => void;
  serverPaginationData: { pageSize?: number; currentPage?: number };
  pageSize?: number;
  noResults?: string | ((filterString: string) => ReactNode);
  sticky?: boolean;
  rowCount: number;
  wrapperRef?: MutableRefObject<HTMLDivElement>;
  onColumnOrderChange: () => void;
  renderGroupingHeaders?: () => JSX.Element;
  renderTimeComparisonDropdown?: () => JSX.Element;
  expandedGroups?: Record<string, boolean>;
  onExpandedGroupsChange?: (expanded: Record<string, boolean>) => void;
  rowGrouping?: string[];
}

export interface RenderHTMLCellProps extends HTMLProps<HTMLTableCellElement> {
  cellContent: ReactNode;
}

// Be sure to pass our updateMyData and the skipReset option
export default typedMemo(function DataTable<D extends object>({
  tableClassName,
  columns,
  data,
  serverPaginationData,
  width: initialWidth = '100%',
  height: initialHeight = 300,
  pageSize: initialPageSize = 0,
  pageSizeOptions = PAGE_SIZE_OPTIONS,
  maxPageItemCount = 9,
  searchInput = true,
  onServerPaginationChange,
  rowCount,
  selectPageSize,
  noResults: noResultsText = 'No data found',
  serverPagination,
  wrapperRef: userWrapperRef,
  onColumnOrderChange,
  renderGroupingHeaders,
  renderTimeComparisonDropdown,
  expandedGroups = {},
  onExpandedGroupsChange,
  rowGrouping,
}: DataTableProps<D>): JSX.Element {
  const resultsSize = serverPagination ? rowCount : data.length;
  const pageSizeRef = useRef([initialPageSize, resultsSize]);
  const hasPagination = initialPageSize > 0 && resultsSize > 0; // pageSize == 0 means no pagination
  const hasGlobalControl =
    hasPagination || !!searchInput || renderTimeComparisonDropdown;

  const defaultWrapperRef = useRef<HTMLDivElement>(null);
  const globalControlRef = useRef<HTMLDivElement>(null);
  const paginationRef = useRef<HTMLDivElement>(null);
  const wrapperRef = userWrapperRef || defaultWrapperRef;

  const [globalFilter, setGlobalFilter] = useState('');
  const [columnOrder, setColumnOrder] = useState(columns.map((_, i) => `${i}`));
  const [pagination, setPagination] = useState({
    pageIndex: 0,
    pageSize: initialPageSize > 0 ? initialPageSize : resultsSize || 10,
  });
  const [expanded, setExpanded] = useState<ExpandedState>(expandedGroups);
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);

  const [grouping, setGrouping] = useState<string[]>(
    rowGrouping && rowGrouping.length > 0
      ? rowGrouping.map(
          name => columns.find(col => col.name === name)?.id || '',
        )
      : [],
  );

  const updatedColumns = columns.map(col => ({
    ...col,
    enableGrouping: true,
  }));

  const table = useReactTable<D>({
    columns: updatedColumns,
    data,
    state: {
      sorting,
      grouping,
      columnFilters,
      globalFilter,
      columnOrder,
      pagination,
      expanded,
    },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onGlobalFilterChange: setGlobalFilter,
    onGroupingChange: setGrouping,
    onColumnOrderChange: setColumnOrder,
    onPaginationChange: setPagination,
    onExpandedChange: expandedState => {
      const newExpanded =
        typeof expandedState === 'function'
          ? expandedState(expanded)
          : expandedState;
      setExpanded(newExpanded);
      onExpandedGroupsChange?.(newExpanded as Record<string, boolean>);
    },
    globalFilterFn: 'auto',
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getExpandedRowModel: getExpandedRowModel(),
    getGroupedRowModel: getGroupedRowModel(),
  });

  const { rows } = table.getRowModel();
  const pageCount = table.getPageCount();
  const { pageIndex } = table.getState().pagination;
  const { pageSize } = table.getState().pagination;

  const noResults =
    typeof noResultsText === 'function'
      ? noResultsText(globalFilter as string)
      : noResultsText;

  const getNoResults = () => <div className="dt-no-results">{noResults}</div>;

  if (!columns || columns.length === 0) {
    return getNoResults() as JSX.Element;
  }

  const shouldRenderFooter = columns.some(x => !!x.footer);

  let columnBeingDragged = -1;

  const onDragStart = (e: DragEvent) => {
    const el = e.target as HTMLTableCellElement;
    const allColumns = table.getAllLeafColumns();
    columnBeingDragged = allColumns.findIndex(
      col => col.id === el.dataset.columnName,
    );
    e.dataTransfer.effectAllowed = 'move';
  };

  const onDrop = (e: DragEvent) => {
    const el = e.target as HTMLTableCellElement;
    const allColumns = table.getAllLeafColumns();
    const newPosition = allColumns.findIndex(
      col => col.id === el.dataset.columnName,
    );

    if (newPosition !== -1) {
      const currentCols = table.getState().columnOrder;
      const colToBeMoved = currentCols.splice(columnBeingDragged, 1);
      currentCols.splice(newPosition, 0, colToBeMoved[0]);
      table.setColumnOrder(currentCols);
      // toggle value in TableChart to trigger column width recalc
      onColumnOrderChange();
    }
    e.preventDefault();
  };

  const renderTable = () => (
    <table className={tableClassName} css={rowIndent}>
      <thead>
        {renderGroupingHeaders ? renderGroupingHeaders() : null}
        {table.getHeaderGroups().map(headerGroup => (
          <tr key={headerGroup.id}>
            {headerGroup.headers.map(header => (
              <th
                key={header.id}
                colSpan={header.colSpan}
                onDragStart={onDragStart}
                onDrop={onDrop}
                onDragOver={e => e.preventDefault()}
                onDragEnter={e => e.preventDefault()}
              >
                {header.isPlaceholder
                  ? null
                  : flexRender(header.column.columnDef.header, {
                      column: header.column,
                      header,
                      table,
                    })}
              </th>
            ))}
          </tr>
        ))}
      </thead>
      <tbody>
        {rows && rows.length > 0 ? (
          rows.map(row => (
            <tr
              role="row"
              key={row.id}
              // The indent rides on the row and is applied by `rowIndent`;
              // see the note there for why it cannot ride on the cell.
              data-depth={row.depth || undefined}
              style={
                row.depth
                  ? ({
                      '--dt-row-indent': `${row.depth * 20}px`,
                    } as CSSProperties)
                  : undefined
              }
            >
              {row.getVisibleCells().map(cell => {
                // group row, group column: renders a div, so it needs a td
                if (cell.getIsGrouped()) {
                  return (
                    <td key={cell.id}>
                      <div style={{ display: 'flex' }}>
                        <div
                          onClick={row.getToggleExpandedHandler()}
                          style={{ cursor: 'pointer', marginRight: '8px' }}
                        >
                          {row.getIsExpanded() ? '▼' : '▶'}
                        </div>
                        {cell.getValue()}
                      </div>
                    </td>
                  );
                }

                // non-group column on a group row → show nothing, but keep the
                // cell so the row still lines up with its header
                if (cell.getIsPlaceholder()) {
                  return <td key={cell.id} />;
                }

                // aggregated child values → aggregated output; normal leaf cell
                // otherwise. Both go through the column's own renderer, which
                // is already a `styled.td`, so returning it as-is is what keeps
                // one td per cell instead of two.
                const rendered = cell.getIsAggregated()
                  ? flexRender(
                      cell.column.columnDef.aggregatedCell ??
                        cell.column.columnDef.cell,
                      {
                        getValue: cell.getValue,
                        row,
                        column: cell.column,
                        table,
                      },
                    )
                  : flexRender(cell.column.columnDef.cell, {
                      getValue: cell.getValue,
                      row,
                      column: cell.column,
                      table,
                    });

                if (!isValidElement(rendered)) {
                  // A renderer that returns a bare value still needs a cell.
                  return <td key={cell.id}>{rendered}</td>;
                }

                return cloneElement(rendered as ReactElement, { key: cell.id });
              })}
            </tr>
          ))
        ) : (
          <tr>
            <td className="dt-no-results" colSpan={columns.length}>
              {noResults}
            </td>
          </tr>
        )}
      </tbody>

      {shouldRenderFooter && (
        <tfoot>
          {table.getFooterGroups().map(footerGroup => (
            <tr key={footerGroup.id} role="row">
              {footerGroup.headers.map(header => (
                <td key={header.id}>
                  {header.isPlaceholder
                    ? null
                    : flexRender(header.column.columnDef.footer, {
                        column: header.column,
                        header,
                        table,
                      })}
                </td>
              ))}
            </tr>
          ))}
        </tfoot>
      )}
    </table>
  );

  const setPageSize = (size: number) => {
    if (serverPagination) {
      onServerPaginationChange(0, size);
    }
    // keep the original size if data is empty
    if (size || resultsSize !== 0) {
      table.setPageSize(size === 0 ? resultsSize : size);
    }
  };

  // force update the pageSize when it's been update from the initial state
  if (
    pageSizeRef.current[0] !== initialPageSize ||
    // when initialPageSize stays as zero, but total number of records changed,
    // we'd also need to update page size
    (initialPageSize === 0 && pageSizeRef.current[1] !== resultsSize)
  ) {
    pageSizeRef.current = [initialPageSize, resultsSize];
    setPageSize(initialPageSize);
  }

  const paginationStyle: CSSProperties = {};

  let resultPageCount = pageCount;
  let resultCurrentPageSize = pageSize;
  let resultCurrentPage = pageIndex;
  let resultOnPageChange: (page: number) => void = (pageNumber: number) => {
    table.setPageIndex(pageNumber);
  };

  if (serverPagination) {
    const serverPageSize = serverPaginationData?.pageSize ?? initialPageSize;
    resultPageCount = Math.ceil(rowCount / serverPageSize);
    if (!Number.isFinite(resultPageCount)) {
      resultPageCount = 0;
    }
    resultCurrentPageSize = serverPageSize;
    const foundPageSizeIndex = pageSizeOptions.findIndex(
      ([option]) => option >= resultCurrentPageSize,
    );
    if (foundPageSizeIndex === -1) {
      resultCurrentPageSize = 0;
    }
    resultCurrentPage = serverPaginationData?.currentPage ?? 0;
    resultOnPageChange = (pageNumber: number) =>
      onServerPaginationChange(pageNumber, serverPageSize);
  }

  return (
    <div
      ref={wrapperRef}
      style={{ width: initialWidth, height: initialHeight }}
    >
      {hasGlobalControl ? (
        <div ref={globalControlRef} className="form-inline dt-controls">
          <div className="row">
            <div
              className={renderTimeComparisonDropdown ? 'col-sm-5' : 'col-sm-6'}
            >
              {hasPagination ? (
                <SelectPageSize
                  total={resultsSize}
                  current={resultCurrentPageSize}
                  options={pageSizeOptions}
                  selectRenderer={
                    typeof selectPageSize === 'boolean'
                      ? undefined
                      : selectPageSize
                  }
                  onChange={setPageSize}
                />
              ) : null}
            </div>
            {searchInput ? (
              <div className="col-sm-6">
                <GlobalFilter<D>
                  searchInput={
                    typeof searchInput === 'boolean' ? undefined : searchInput
                  }
                  preGlobalFilteredRows={data}
                  setGlobalFilter={setGlobalFilter}
                  filterValue={globalFilter}
                />
              </div>
            ) : null}
            {renderTimeComparisonDropdown ? (
              <div
                className="col-sm-1"
                style={{ float: 'right', marginTop: '6px' }}
              >
                {renderTimeComparisonDropdown()}
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
      {renderTable()}
      {hasPagination && resultPageCount > 1 ? (
        <SimplePagination
          ref={paginationRef}
          style={paginationStyle}
          maxPageItemCount={maxPageItemCount}
          pageCount={resultPageCount}
          currentPage={resultCurrentPage}
          onPageChange={resultOnPageChange}
        />
      ) : null}
    </div>
  );
});
