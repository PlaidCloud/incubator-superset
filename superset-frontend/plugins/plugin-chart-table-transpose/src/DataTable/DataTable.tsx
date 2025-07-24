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
  useCallback,
  useRef,
  ReactNode,
  HTMLProps,
  MutableRefObject,
  CSSProperties,
  DragEvent,
  useEffect,
  useMemo,
  useState,
} from 'react';

import {
  useTable,
  usePagination,
  useSortBy,
  useGlobalFilter,
  useColumnOrder,
  PluginHook,
  TableOptions,
  FilterType,
  IdType,
  Row,
  Column,
} from 'react-table';
import { matchSorter, rankings } from 'match-sorter';
import { typedMemo, usePrevious } from '@superset-ui/core';
import { isEqual } from 'lodash';
import GlobalFilter, { GlobalFilterProps } from './components/GlobalFilter';
import SelectPageSize, {
  SelectPageSizeProps,
  SizeOption,
} from './components/SelectPageSize';
import SimplePagination from './components/Pagination';
import useSticky from './hooks/useSticky';
import { PAGE_SIZE_OPTIONS } from '../consts';
import { sortAlphanumericCaseInsensitive } from './utils/sortAlphanumericCaseInsensitive';

export interface DataTableProps<D extends object> extends TableOptions<D> {
  tableClassName?: string;
  searchInput?: boolean | GlobalFilterProps<D>['searchInput'];
  selectPageSize?: boolean | SelectPageSizeProps['selectRenderer'];
  pageSizeOptions?: SizeOption[]; // available page size options
  maxPageItemCount?: number;
  hooks?: PluginHook<D>[]; // any additional hooks
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
  custom_css?: string; // custom CSS class to apply to the table
}

export interface RenderHTMLCellProps extends HTMLProps<HTMLTableCellElement> {
  cellContent: ReactNode;
}

const sortTypes = {
  alphanumeric: sortAlphanumericCaseInsensitive,
};

// Be sure to pass our updateMyData and the skipReset option
export default typedMemo(function DataTable<D extends object>({
  tableClassName,
  columns,
  data,
  serverPaginationData,
  width: initialWidth = '100%',
  height: initialHeight = 300,
  pageSize: initialPageSize = 0,
  initialState: initialState_ = {},
  pageSizeOptions = PAGE_SIZE_OPTIONS,
  maxPageItemCount = 9,
  sticky: doSticky,
  searchInput = true,
  onServerPaginationChange,
  rowCount,
  selectPageSize,
  noResults: noResultsText = 'No data found',
  hooks,
  serverPagination,
  wrapperRef: userWrapperRef,
  onColumnOrderChange,
  renderGroupingHeaders,
  renderTimeComparisonDropdown,
  custom_css,
  ...moreUseTableOptions
}: DataTableProps<D>): JSX.Element {
  const tableHooks: PluginHook<D>[] = [
    useGlobalFilter,
    useSortBy,
    usePagination,
    useColumnOrder,
    doSticky ? useSticky : [],
    hooks || [],
  ].flat();
  const columnNames = Object.keys(data?.[0] || {});
  const previousColumnNames = usePrevious(columnNames);
  const resultsSize = serverPagination ? rowCount : data.length;
  const sortByRef = useRef([]); // cache initial `sortby` so sorting doesn't trigger page reset
  const pageSizeRef = useRef([initialPageSize, resultsSize]);
  const hasPagination = initialPageSize > 0 && resultsSize > 0; // pageSize == 0 means no pagination
  const hasGlobalControl =
    hasPagination || !!searchInput || renderTimeComparisonDropdown;
  const initialState = {
    ...initialState_,
    // zero length means all pages, the `usePagination` plugin does not
    // understand pageSize = 0
    sortBy: sortByRef.current,
    pageSize: initialPageSize > 0 ? initialPageSize : resultsSize || 10,
  };
  const defaultWrapperRef = useRef<HTMLDivElement>(null);
  const globalControlRef = useRef<HTMLDivElement>(null);
  const paginationRef = useRef<HTMLDivElement>(null);
  const wrapperRef = userWrapperRef || defaultWrapperRef;
  const paginationData = JSON.stringify(serverPaginationData);

  const [currentSortBy, setCurrentSortBy] = useState<Array<{ id: string, desc: boolean }>>([]);

  const defaultGetTableSize = useCallback(() => {
    if (wrapperRef.current) {
      // `initialWidth` and `initialHeight` could be also parameters like `100%`
      // `Number` returns `NaN` on them, then we fallback to computed size
      const width = Number(initialWidth) || wrapperRef.current.clientWidth;
      const height =
        (Number(initialHeight) || wrapperRef.current.clientHeight) -
        (globalControlRef.current?.clientHeight || 0) -
        (paginationRef.current?.clientHeight || 0);
      return { width, height };
    }
    return undefined;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    initialHeight,
    initialWidth,
    wrapperRef,
    hasPagination,
    hasGlobalControl,
    paginationRef,
    resultsSize,
    paginationData,
  ]);

  const defaultGlobalFilter: FilterType<D> = useCallback(
    (rows: Row<D>[], columnIds: IdType<D>[], filterValue: string) => {
      // allow searching by "col1_value col2_value"
      const joinedString = (row: Row<D>) =>
        columnIds.map(x => row.values[x]).join(' ');
      return matchSorter(rows, filterValue, {
        keys: [...columnIds, joinedString],
        threshold: rankings.ACRONYM,
      }) as typeof rows;
    },
    [],
  );

  // Now create processedData using the sortBy state
  const processedData = useMemo(() => {
    // Check if we have transposed data (contains __isHeading or __is_summary__)
    const hasTransposedData = data.some(row =>
      ('__isHeading' in row && row.__isHeading) ||
      ('__is_summary__' in row && row.__is_summary__)
    );

    // If not transposed data, return original data for normal React Table sorting
    if (!hasTransposedData) {
      return data;
    }

    // Only apply custom sorting logic for transposed data
    const frozenRows: { row: D; index: number }[] = [];
    const sortableRows: { row: D; index: number }[] = [];

    data.forEach((row, index) => {
      if (
        ('__isHeading' in row && row.__isHeading) ||
        ('__is_summary__' in row && row.__is_summary__)
      ) {
        frozenRows.push({ row, index });
      } else {
        sortableRows.push({ row, index });
      }
    });

    // Apply sorting manually to sortableRows
    let sortedRows = [...sortableRows];

    if (currentSortBy && currentSortBy.length > 0) {
      sortedRows.sort((a, b) => {
        // Process multiple sort columns
        for (const sortColumn of currentSortBy) {
          const { id, desc } = sortColumn;

          // Find the column definition to get its sortType
          const column = columns.find(
            col => col.id === id || col.accessor === id,
          ) as Column<D> & { label: string };
          const sortType = column?.sortType;
          const columnLabel = column.label === "All Segments" ? "rowTotal" : column.label;

          const aVal = a.row[columnLabel as keyof D];
          const bVal = b.row[columnLabel as keyof D];

          // Handle null/undefined values
          if (aVal == null && bVal == null) continue; // Equal, check next sort column
          if (aVal == null) return desc ? -1 : 1;
          if (bVal == null) return desc ? 1 : -1;

          let compareResult = 0;

          // Apply sort based on sortType
          if (sortType === 'datetime') {
            const aTime = new Date(aVal as any).getTime();
            const bTime = new Date(bVal as any).getTime();
            compareResult = aTime - bTime;
          } else if (
            sortType === 'number' ||
            (typeof aVal === 'number' && typeof bVal === 'number')
          ) {
            compareResult = (aVal as number) - (bVal as number);
          } else {
            // Default string comparison
            compareResult = String(aVal).localeCompare(String(bVal));
          }

          // Apply desc order if needed
          if (compareResult !== 0) {
            return desc ? -compareResult : compareResult;
          }
          // If equal, continue to next sort column
        }
        return 0;
      });
    }

    // Reconstruct the data maintaining frozen row positions
    const result: D[] = [];
    let sortableIndex = 0;

    data.forEach(originalRow => {
      if (
        ('__isHeading' in originalRow && originalRow.__isHeading) ||
        ('__is_summary__' in originalRow && originalRow.__is_summary__)
      ) {
        // Keep frozen rows at their original positions
        result.push(originalRow);
      } else {
        // Use sorted sortable rows
        if (sortableIndex < sortedRows.length) {
          result.push(sortedRows[sortableIndex].row);
          sortableIndex++;
        }
      }
    });

    return result;
  }, [data, currentSortBy, columns]); // Include sortBy and columns in dependencies

  const {
    getTableProps,
    getTableBodyProps,
    prepareRow,
    headerGroups,
    footerGroups,
    page,
    pageCount,
    gotoPage,
    preGlobalFilteredRows,
    setGlobalFilter,
    setPageSize: setPageSize_,
    wrapStickyTable,
    setColumnOrder,
    allColumns,
    state: { pageIndex, pageSize, globalFilter: filterValue, sticky = {}, sortBy },
  } = useTable<D>(
    {
      columns,
      data: processedData,
      initialState,
      getTableSize: defaultGetTableSize,
      globalFilter: defaultGlobalFilter,
      sortTypes,
      autoResetSortBy: !isEqual(columnNames, previousColumnNames),
      // Only use manual sorting for transposed data
      manualSortBy: data.some(row =>
        ('__isHeading' in row && row.__isHeading) ||
        ('__is_summary__' in row && row.__is_summary__)
      ),
      ...moreUseTableOptions,
    },
    ...tableHooks,
  );

  // Only update currentSortBy for transposed data
  useEffect(() => {
    const hasTransposedData = data.some(row =>
      ('__isHeading' in row && row.__isHeading) ||
      ('__is_summary__' in row && row.__is_summary__)
    );

    if (hasTransposedData && sortBy && !isEqual(sortBy, currentSortBy)) {
      setCurrentSortBy(sortBy.map(({ id, desc }) => ({ id, desc: desc ?? false })));
    }
  }, [sortBy, currentSortBy, data]);

  useEffect(() => {
    if (custom_css) {
      const styleId = 'table-transpose-custom-css';
      let styleElement = document.getElementById(styleId) as HTMLStyleElement;

      if (!styleElement) {
        styleElement = document.createElement('style');
        styleElement.id = styleId;
        document.head.appendChild(styleElement);
      }

      styleElement.textContent = custom_css;

      return () => {
        // Clean up the style element when component unmounts or CSS changes
        if (styleElement && styleElement.parentNode) {
          styleElement.parentNode.removeChild(styleElement);
        }
      };
    }
    return undefined;
  }, [custom_css]);

  // make setPageSize accept 0
  const setPageSize = (size: number) => {
    if (serverPagination) {
      onServerPaginationChange(0, size);
    }
    // keep the original size if data is empty
    if (size || resultsSize !== 0) {
      setPageSize_(size === 0 ? resultsSize : size);
    }
  };

  const noResults =
    typeof noResultsText === 'function'
      ? noResultsText(filterValue as string)
      : noResultsText;

  const getNoResults = () => <div className="dt-no-results">{noResults}</div>;

  if (!columns || columns.length === 0) {
    return (
      wrapStickyTable ? wrapStickyTable(getNoResults) : getNoResults()
    ) as JSX.Element;
  }

  const shouldRenderFooter = columns.some(x => !!x.Footer);

  let columnBeingDragged = -1;

  const onDragStart = (e: DragEvent) => {
    const el = e.target as HTMLTableCellElement;
    columnBeingDragged = allColumns.findIndex(
      col => col.id === el.dataset.columnName,
    );
    e.dataTransfer.setData('text/plain', `${columnBeingDragged}`);
  };

  const onDrop = (e: DragEvent) => {
    const el = e.target as HTMLTableCellElement;
    const newPosition = allColumns.findIndex(
      col => col.id === el.dataset.columnName,
    );

    if (newPosition !== -1) {
      const currentCols = allColumns.map(c => c.id);
      const colToBeMoved = currentCols.splice(columnBeingDragged, 1);
      currentCols.splice(newPosition, 0, colToBeMoved[0]);
      setColumnOrder(currentCols);
      // toggle value in TableChart to trigger column width recalc
      onColumnOrderChange();
    }
    e.preventDefault();
  };

  const renderTable = () => (
    <table {...getTableProps({ className: tableClassName })}>
      <thead>
        {renderGroupingHeaders ? renderGroupingHeaders() : null}
        {headerGroups.map(headerGroup => {
          const { key: headerGroupKey, ...headerGroupProps } =
            headerGroup.getHeaderGroupProps();
          return (
            <tr key={headerGroupKey || headerGroup.id} {...headerGroupProps}>
              {headerGroup.headers.map(column =>
                column.render('Header', {
                  key: column.id,
                  ...column.getSortByToggleProps(),
                  onDragStart,
                  onDrop,
                }),
              )}
            </tr>
          );
        })}
      </thead>
      <tbody {...getTableBodyProps()}>
        {page && page.length > 0 ? (
          page.map((row, rowIndex) => {
            prepareRow(row);
            const { key: rowKey, ...rowProps } = row.getRowProps();
            return (
              <tr key={rowKey || `row-${rowIndex}`} {...rowProps} role="row">
                {row.cells.map((cell, cellIndex) =>
                  cell.render('Cell', { key: cell.column.id || `cell-${cellIndex}` }),
                )}
              </tr>
            );
          })
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
          {footerGroups.map(footerGroup => {
            const { key: footerGroupKey, ...footerGroupProps } =
              footerGroup.getHeaderGroupProps();
            return (
              <tr
                key={footerGroupKey || footerGroup.id}
                {...footerGroupProps}
                role="row"
              >
                {footerGroup.headers.map(column =>
                  column.render('Footer', { key: column.id }),
                )}
              </tr>
            );
          })}
        </tfoot>
      )}
    </table>
  );

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

  const paginationStyle: CSSProperties = sticky.height
    ? {}
    : { visibility: 'hidden' };

  let resultPageCount = pageCount;
  let resultCurrentPageSize = pageSize;
  let resultCurrentPage = pageIndex;
  let resultOnPageChange: (page: number) => void = gotoPage;
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
                  preGlobalFilteredRows={preGlobalFilteredRows}
                  setGlobalFilter={setGlobalFilter}
                  filterValue={filterValue}
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
      {wrapStickyTable ? wrapStickyTable(renderTable) : renderTable()}
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
