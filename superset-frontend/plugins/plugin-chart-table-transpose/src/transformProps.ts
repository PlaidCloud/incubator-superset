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
import memoizeOne from 'memoize-one';
import {
  ComparisonType,
  CurrencyFormatter,
  Currency,
  DataRecord,
  ensureIsArray,
  extractTimegrain,
  GenericDataType,
  getMetricLabel,
  getNumberFormatter,
  getTimeFormatter,
  getTimeFormatterForGranularity,
  NumberFormats,
  QueryMode,
  t,
  SMART_DATE_ID,
  TimeFormats,
  TimeFormatter,
  createSmartNumberFormatter,
} from '@superset-ui/core';
import {
  ColorFormatters,
  ConditionalFormattingConfig,
  getColorFormatters,
} from '@superset-ui/chart-controls';

import { isEmpty } from 'lodash';
import DateWithFormatter from './utils/DateWithFormatter';
import {
  BasicColorFormatterType,
  ColorSchemeEnum,
  DataColumnMeta,
  TableChartProps,
  TableChartTransformedProps,
  TableColumnConfig,
} from './types';

const { PERCENT_3_POINT } = NumberFormats;
const { DATABASE_DATETIME } = TimeFormats;

function isNumeric(key: string, data: DataRecord[] = []) {
  return data.every(
    x => x[key] === null || x[key] === undefined || typeof x[key] === 'number',
  );
}

const processDataRecords = memoizeOne(function processDataRecords(
  data: DataRecord[] | undefined,
  columns: DataColumnMeta[],
) {
  if (!data?.[0]) {
    return data || [];
  }
  const timeColumns = columns.filter(
    column => column.dataType === GenericDataType.Temporal,
  );

  if (timeColumns.length > 0) {
    return data.map(x => {
      const datum = { ...x };
      timeColumns.forEach(({ key, formatter }) => {
        // Convert datetime with a custom date class so we can use `String(...)`
        // formatted value for global search, and `date.getTime()` for sorting.
        datum[key] = new DateWithFormatter(x[key], {
          formatter: formatter as TimeFormatter,
        });
      });
      return datum;
    });
  }
  return data;
});

const calculateDifferences = (
  originalValue: number,
  comparisonValue: number,
) => {
  const valueDifference = originalValue - comparisonValue;
  let percentDifferenceNum;
  if (!originalValue && !comparisonValue) {
    percentDifferenceNum = 0;
  } else if (!originalValue || !comparisonValue) {
    percentDifferenceNum = originalValue ? 1 : -1;
  } else {
    percentDifferenceNum =
      (originalValue - comparisonValue) / Math.abs(comparisonValue);
  }
  return { valueDifference, percentDifferenceNum };
};

const processComparisonTotals = (
  comparisonSuffix: string,
  totals?: DataRecord[],
): DataRecord | undefined => {
  if (!totals) {
    return totals;
  }
  const transformedTotals: DataRecord = {};
  totals.map((totalRecord: DataRecord) =>
    Object.keys(totalRecord).forEach(key => {
      if (totalRecord[key] !== undefined && !key.includes(comparisonSuffix)) {
        transformedTotals[`Main ${key}`] =
          parseInt(transformedTotals[`Main ${key}`]?.toString() || '0', 10) +
          parseInt(totalRecord[key]?.toString() || '0', 10);
        transformedTotals[`# ${key}`] =
          parseInt(transformedTotals[`# ${key}`]?.toString() || '0', 10) +
          parseInt(
            totalRecord[`${key}__${comparisonSuffix}`]?.toString() || '0',
            10,
          );
        const { valueDifference, percentDifferenceNum } = calculateDifferences(
          transformedTotals[`Main ${key}`] as number,
          transformedTotals[`# ${key}`] as number,
        );
        transformedTotals[`△ ${key}`] = valueDifference;
        transformedTotals[`% ${key}`] = percentDifferenceNum;
      }
    }),
  );

  return transformedTotals;
};

const processComparisonDataRecords = memoizeOne(
  function processComparisonDataRecords(
    originalData: DataRecord[] | undefined,
    originalColumns: DataColumnMeta[],
    comparisonSuffix: string,
  ) {
    // Transform data
    return originalData?.map(originalItem => {
      const transformedItem: DataRecord = {};
      originalColumns.forEach(origCol => {
        if (
          (origCol.isMetric || origCol.isPercentMetric) &&
          !origCol.key.includes(comparisonSuffix) &&
          origCol.isNumeric
        ) {
          const originalValue = originalItem[origCol.key] || 0;
          const comparisonValue = origCol.isMetric
            ? originalItem?.[`${origCol.key}__${comparisonSuffix}`] || 0
            : originalItem[`%${origCol.key.slice(1)}__${comparisonSuffix}`] ||
            0;
          const { valueDifference, percentDifferenceNum } =
            calculateDifferences(
              originalValue as number,
              comparisonValue as number,
            );

          transformedItem[`Main ${origCol.key}`] = originalValue;
          transformedItem[`# ${origCol.key}`] = comparisonValue;
          transformedItem[`△ ${origCol.key}`] = valueDifference;
          transformedItem[`% ${origCol.key}`] = percentDifferenceNum;
        }
      });

      Object.keys(originalItem).forEach(key => {
        const isMetricOrPercentMetric = originalColumns.some(
          col => col.key === key && (col.isMetric || col.isPercentMetric),
        );
        if (!isMetricOrPercentMetric) {
          transformedItem[key] = originalItem[key];
        }
      });

      return transformedItem;
    });
  },
);

function processColumns(props: TableChartProps): [
  string[],
  string[],
  DataColumnMeta[],
] {
  const {
    datasource: { columnFormats, currencyFormats, verboseMap },
    rawFormData: formData,
    queriesData,
  } = props;
  const {
    table_timestamp_format: tableTimestampFormat,
    metrics: formDataMetrics = [],
    percent_metrics: formDataPercentMetrics,
    column_config: columnConfig = {},
  } = formData;

  // Filter out headings from metrics when processing columns
  const metricsWithoutHeadings = formDataMetrics.filter(
    (metric: any) => !(typeof metric === 'object' && 'heading' in metric)
  );

  const granularity = extractTimegrain(formData);
  const { data: records, colnames, coltypes } = queriesData[0] || {};

  // convert `metrics` and `percentMetrics` to the key names in `data.records`
  const metrics = (metricsWithoutHeadings ?? []).map(getMetricLabel);
  const rawPercentMetrics = (formDataPercentMetrics ?? []).map(getMetricLabel);
  // column names for percent metrics always starts with a '%' sign.
  const percentMetrics = rawPercentMetrics.map((x: string) => `%${x}`);
  const metricsSet = new Set(metrics);
  const percentMetricsSet = new Set(percentMetrics);
  const rawPercentMetricsSet = new Set(rawPercentMetrics);

  const columns: DataColumnMeta[] = (colnames || [])
    .filter(
      key =>
        // if a metric was only added to percent_metrics, they should not show up in the table.
        !(rawPercentMetricsSet.has(key) && !metricsSet.has(key)),
    )
    .map((key: string, i) => {
      const dataType = coltypes[i];
      const config = columnConfig[key] || {};
      // for the purpose of presentation, only numeric values are treated as metrics
      // because users can also add things like `MAX(str_col)` as a metric.
      const isMetric = metricsSet.has(key) && isNumeric(key, records);
      const isPercentMetric = percentMetricsSet.has(key);
      const label =
        isPercentMetric && verboseMap?.hasOwnProperty(key.replace('%', ''))
          ? `%${verboseMap[key.replace('%', '')]}`
          : verboseMap?.[key] || key;
      const isTime = dataType === GenericDataType.Temporal;
      const isNumber = dataType === GenericDataType.Numeric;
      const savedFormat = columnFormats?.[key];
      const savedCurrency = currencyFormats?.[key];
      const numberFormat = config.d3NumberFormat || savedFormat;
      const currency = config.currencyFormat?.symbol
        ? config.currencyFormat
        : savedCurrency;

      let formatter;

      if (isTime || config.d3TimeFormat) {
        // string types may also apply d3-time format
        // pick adhoc format first, fallback to column level formats defined in
        // datasource
        const customFormat = config.d3TimeFormat || savedFormat;
        const timeFormat = customFormat || tableTimestampFormat;
        // When format is "Adaptive Formatting" (smart_date)
        if (timeFormat === SMART_DATE_ID) {
          if (granularity) {
            // time column use formats based on granularity
            formatter = getTimeFormatterForGranularity(granularity);
          } else if (customFormat) {
            // other columns respect the column-specific format
            formatter = getTimeFormatter(customFormat);
          } else if (isNumeric(key, records)) {
            // if column is numeric values, it is considered a timestamp64
            formatter = getTimeFormatter(DATABASE_DATETIME);
          } else {
            // if no column-specific format, print cell as is
            formatter = String;
          }
        } else if (timeFormat) {
          formatter = getTimeFormatter(timeFormat);
        }
      } else if (isPercentMetric) {
        // percent metrics have a default format
        formatter = getNumberFormatter(numberFormat || PERCENT_3_POINT);
      } else if (isMetric || (isNumber && (numberFormat || currency))) {
        formatter = currency
          ? new CurrencyFormatter({
            d3Format: numberFormat,
            currency,
          })
          : getNumberFormatter(numberFormat);
      }
      return {
        key,
        label,
        dataType,
        isNumeric: dataType === GenericDataType.Numeric,
        isMetric,
        isPercentMetric,
        formatter,
        config,
      };
    });
  return [metrics, percentMetrics, columns];
};

const getComparisonColConfig = (
  label: string,
  parentColKey: string,
  columnConfig: Record<string, TableColumnConfig>,
) => {
  const comparisonKey = `${label} ${parentColKey}`;
  const comparisonColConfig = columnConfig[comparisonKey] || {};
  return comparisonColConfig;
};

const getComparisonColFormatter = (
  label: string,
  parentCol: DataColumnMeta,
  columnConfig: Record<string, TableColumnConfig>,
  savedFormat: string | undefined,
  savedCurrency: Currency | undefined,
) => {
  const currentColConfig = getComparisonColConfig(
    label,
    parentCol.key,
    columnConfig,
  );
  const hasCurrency = currentColConfig.currencyFormat?.symbol;
  const currentColNumberFormat =
    // fallback to parent's number format if not set
    currentColConfig.d3NumberFormat || parentCol.config?.d3NumberFormat;
  let { formatter } = parentCol;
  if (label === '%') {
    formatter = getNumberFormatter(currentColNumberFormat || PERCENT_3_POINT);
  } else if (currentColNumberFormat || hasCurrency) {
    const currency = currentColConfig.currencyFormat || savedCurrency;
    const numberFormat = currentColNumberFormat || savedFormat;
    formatter = currency
      ? new CurrencyFormatter({
        d3Format: numberFormat,
        currency,
      })
      : getNumberFormatter(numberFormat);
  }
  return formatter;
};

const processComparisonColumns = (
  columns: DataColumnMeta[],
  props: TableChartProps,
  comparisonSuffix: string,
) =>
  columns
    .map(col => {
      const {
        datasource: { columnFormats, currencyFormats },
        rawFormData: { column_config: columnConfig = {} },
      } = props;
      const savedFormat = columnFormats?.[col.key];
      const savedCurrency = currencyFormats?.[col.key];
      if (
        (col.isMetric || col.isPercentMetric) &&
        !col.key.includes(comparisonSuffix) &&
        col.isNumeric
      ) {
        return [
          {
            ...col,
            label: t('Main'),
            key: `${t('Main')} ${col.key}`,
            config: getComparisonColConfig(t('Main'), col.key, columnConfig),
            formatter: getComparisonColFormatter(
              t('Main'),
              col,
              columnConfig,
              savedFormat,
              savedCurrency,
            ),
          },
          {
            ...col,
            label: `#`,
            key: `# ${col.key}`,
            config: getComparisonColConfig(`#`, col.key, columnConfig),
            formatter: getComparisonColFormatter(
              `#`,
              col,
              columnConfig,
              savedFormat,
              savedCurrency,
            ),
          },
          {
            ...col,
            label: `△`,
            key: `△ ${col.key}`,
            config: getComparisonColConfig(`△`, col.key, columnConfig),
            formatter: getComparisonColFormatter(
              `△`,
              col,
              columnConfig,
              savedFormat,
              savedCurrency,
            ),
          },
          {
            ...col,
            label: `%`,
            key: `% ${col.key}`,
            config: getComparisonColConfig(`%`, col.key, columnConfig),
            formatter: getComparisonColFormatter(
              `%`,
              col,
              columnConfig,
              savedFormat,
              savedCurrency,
            ),
          },
        ];
      }
      if (
        !col.isMetric &&
        !col.isPercentMetric &&
        !col.key.includes(comparisonSuffix)
      ) {
        return [col];
      }
      return [];
    })
    .flat();

/**
 * Automatically set page size based on number of cells.
 */
const getPageSize = (
  pageSize: number | string | null | undefined,
  numRecords: number,
  numColumns: number,
) => {
  if (typeof pageSize === 'number') {
    // NaN is also has typeof === 'number'
    return pageSize || 0;
  }
  if (typeof pageSize === 'string') {
    return Number(pageSize) || 0;
  }
  // when pageSize not set, automatically add pagination if too many records
  return numRecords * numColumns > 5000 ? 200 : 0;
};

const defaultServerPaginationData = {};
const defaultColorFormatters = [] as ColorFormatters;

function createFormatter(config: {
  numberFormat?: string;
  smallNumberFormat?: string;
  currencyFormat?: { symbol?: string; symbolPosition?: string };
}) {
  if (config.currencyFormat && config.currencyFormat.symbol) {
    return new CurrencyFormatter({
      d3Format: config.numberFormat,
      currency: config.currencyFormat as Currency,
    });
  }


  if (config.smallNumberFormat && config.numberFormat) {
    return createSmartNumberFormatter({
      id: config.numberFormat,
      description: config.smallNumberFormat,
    });
  }

  if (config.numberFormat) {
    return getNumberFormatter(config.numberFormat);
  }

  return undefined;
}

function transposeData(
  data: DataRecord[], // Original data rows from the query
  originalDataColumns: DataColumnMeta[], // Metadata for original data columns
  formDataMetricsInOrder: any[], // formData.metrics, defining the order of rows
  showTotals?: boolean, // Add showTotals parameter
  rowConfig?: Record<string, any>, // Add rowConfig parameter
  showAllSegments: boolean = true,
  allSegmentsPosition: 'start' | 'end' = 'start',
  column_sort_order: 'none' | 'asc' | 'desc' = 'none',
): {
  transposedData: DataRecord[];
  transposedColumns: DataColumnMeta[];
} {
  // If there's no data to transpose or no metrics/headings defined for rows, return empty
  if ((!data.length || !originalDataColumns.length) && !formDataMetricsInOrder.length) {
    return { transposedData: [], transposedColumns: [] };
  }

  // 1. Determine transposed table headers (transposedColumns)
  // The first column header is fixed (e.g., 'Metric').
  // Subsequent column headers are derived from the values of the first non-metric/non-percent dimension
  // in the original data.
  const firstDimensionCol = originalDataColumns.find(
    col => !col.isMetric && !col.isPercentMetric,
  );
  // Use the key of the first dimension column to get header values from original data rows.
  const headerKeyForOriginalData = firstDimensionCol?.key;

  // Create a map to store formatters for each metric
  const metricFormatters = new Map<string, any>();
  originalDataColumns.forEach(col => {
    if (col.isMetric || col.isPercentMetric) {
      metricFormatters.set(col.key, col.formatter);
    }
  });

  const filteredDataForDynamicColumnHeaders = data.length > 0 ? data.filter(
    originalDataRow =>
      headerKeyForOriginalData &&
      originalDataRow[headerKeyForOriginalData] !== undefined) : [];

  let dynamicColumnHeaders = filteredDataForDynamicColumnHeaders.length > 0 ?
    filteredDataForDynamicColumnHeaders.map((originalDataRow) => {
      const label = headerKeyForOriginalData
        ? String(originalDataRow[headerKeyForOriginalData])
        : '';
      return {
        key: label,  // Use label as key instead of `col_${index}`
        label: label,
        dataType: GenericDataType.Numeric, // Changed to Numeric since these will contain metric values
        isMetric: false,
        isPercentMetric: false,
        isNumeric: true, // Changed to true since these columns will contain numeric values
        // We'll assign formatters dynamically per cell based on the metric
      };
    }) : []; // Filter out undefined values

  let dynamicColumnHeadersSortOrder: number[] = dynamicColumnHeaders.map((header, index) => index);
  if (column_sort_order !== 'none') {
    const indexedHeaders = dynamicColumnHeaders.map((header, index) => ({
      header,
      originalIndex: index,
    }));

    // Sort the indexed headers
    const sortedIndexedHeaders = indexedHeaders.sort((a, b) => {
      if (column_sort_order === 'asc') {
        return a.header.label.localeCompare(b.header.label);
      } else if (column_sort_order === 'desc') {
        return b.header.label.localeCompare(a.header.label);
      }
      return 0;
    });

    dynamicColumnHeaders = sortedIndexedHeaders.map(item => item.header);
    dynamicColumnHeadersSortOrder = sortedIndexedHeaders.map(item => item.originalIndex);
  }

  const transposedColumnHeaders: DataColumnMeta[] = [
    {
      key: 'metric',
      label: t('Metric'),
      dataType: GenericDataType.String,
      isMetric: false,
      isPercentMetric: false,
      isNumeric: false,
      config: {
        disableSortBy: true,
      }
    },
    // Always add the "Total" column header for row totals
    ...(showAllSegments && allSegmentsPosition === 'start' ? [
      {
        key: 'rowTotal',
        label: t('All Segments'),
        dataType: GenericDataType.Numeric,
        isMetric: false,
        isPercentMetric: false,
        isNumeric: true,
      },
    ] : []),
    ...dynamicColumnHeaders,
    ...(showAllSegments && allSegmentsPosition === 'end' ? [
      {
        key: 'rowTotal',
        label: t('All Segments'),
        dataType: GenericDataType.Numeric,
        isMetric: false,
        isPercentMetric: false,
        isNumeric: true,
      },
    ] : []),
  ];

  if (dynamicColumnHeaders.length === 0) {
    // simple transpose if no dynamic headers
    const originalRows = data.map(row => {
      const newRow: DataRecord = {};
      originalDataColumns.forEach(col => {
        newRow[col.key] = row[col.key];
        // Assign formatter if available
        if (metricFormatters.has(col.key)) {
          (newRow as any).__formatter__ = metricFormatters.get(col.key);
        }
      });
      return newRow;
    })

    const newRows = formDataMetricsInOrder.map(metricOrHeadingItem => {
      const newRow: DataRecord = {};
      if (
        typeof metricOrHeadingItem === 'object' &&
        metricOrHeadingItem.emptyRowHeading === true
      ) {
        newRow.__isHeading = true;
        // Set the heading text in the 'metric' column
        newRow.metric = metricOrHeadingItem.emptyRowHeadingText || '';
        // Blank out all other columns for this heading row
        transposedColumnHeaders.forEach(headerCol => {
          if (headerCol.key !== 'metric') { // Skip the 'metric' column as it has the heading
            newRow[headerCol.key] = '';
          }
        });
      } else {
        const itemIdentifier = getMetricLabel(metricOrHeadingItem);
        newRow.metric = itemIdentifier;
        newRow.__isHeading = false;
        originalRows.forEach(originalRow => {
          newRow.rowTotal = originalRow[itemIdentifier];
          // Assign formatter if available
          if (metricFormatters.has(itemIdentifier)) {
            (newRow as any).__formatter__ = metricFormatters.get(itemIdentifier);
          }
        });
      }
      return newRow;
    });

    return {
      transposedData: newRows,
      transposedColumns: transposedColumnHeaders,
    };

  }

  const transposedDataRows: DataRecord[] = [];
  // Object to store column sums if we need to show totals
  const columnSums: Record<string, number> = {};

  formDataMetricsInOrder.forEach(metricOrHeadingItem => {
    const newRow: DataRecord = {};
    let currentRowSum = 0;
    let currentRowHasNumeric = false;

    if (metricOrHeadingItem.isEmpty) {
      newRow.metric = '\u200B',
        newRow.isEmpty = true;
      const emptyRowConfig = rowConfig?.[''] || rowConfig?.['empty'];
      if (emptyRowConfig?.rowColor) {
        newRow.__rowColor__ = emptyRowConfig.rowColor;
      }
      transposedDataRows.push(newRow);
      return;
    }

    if (
      typeof metricOrHeadingItem === 'object' &&
      metricOrHeadingItem.emptyRowHeading === true
    ) {
      newRow.__isHeading = true;
      // Set the heading text in the 'metric' column
      newRow.metric = metricOrHeadingItem.emptyRowHeadingText || '';

      const headingRowConfig = rowConfig?.[metricOrHeadingItem.emptyRowHeadingText || ''];
      if (headingRowConfig?.rowColor) {
        newRow.__rowColor__ = headingRowConfig.rowColor;
      }

      // Blank out all other columns for this heading row
      transposedColumnHeaders.forEach(headerCol => {
        if (headerCol.key !== 'metric') { // Skip the 'metric' column as it has the heading
          newRow[headerCol.key] = '';
        }
      });
    } else {
      const itemIdentifier = getMetricLabel(metricOrHeadingItem);
      let displayLabel = itemIdentifier;
      const correspondingOriginalColumn = originalDataColumns.find(
        col => col.key === itemIdentifier,
      );

      // Store the formatter for this metric row
      if (correspondingOriginalColumn?.formatter) {
        (newRow as any).__formatter__ = correspondingOriginalColumn.formatter;
      }

      if (correspondingOriginalColumn) {
        displayLabel = correspondingOriginalColumn.label || itemIdentifier;
        const originalDataKey = correspondingOriginalColumn.key;

        // Get row configuration for this metric
        const rowConfigForMetric = rowConfig?.[displayLabel];

        // Add row color if configured
        if (rowConfigForMetric?.rowColor) {
          newRow.__rowColor__ = rowConfigForMetric.rowColor;
        }

        // Create a custom formatter if row config has number formatting
        if (rowConfigForMetric && (rowConfigForMetric.d3NumberFormat || rowConfigForMetric.d3SmallNumberFormat || rowConfigForMetric.currencyFormat)) {
          const formatter = createFormatter({
            numberFormat: rowConfigForMetric.d3NumberFormat,
            smallNumberFormat: rowConfigForMetric.d3SmallNumberFormat,
            currencyFormat: rowConfigForMetric.currencyFormat,
          });
          if (formatter) {
            (newRow as any).__formatter__ = formatter;
          }
        } else if (correspondingOriginalColumn.formatter) {
          (newRow as any).__formatter__ = correspondingOriginalColumn.formatter;
        }

        dynamicColumnHeaders.forEach((headerCol, sortedIndex) => {
          const originalDataIndex = dynamicColumnHeadersSortOrder[sortedIndex]; // Map to original data index
          const originalDataRow = data[originalDataIndex];
          let cellValue = null;
          if (originalDataRow) {
            cellValue = originalDataRow[originalDataKey];
          }
          newRow[headerCol.key] = cellValue;
          // Always sum for rowTotal if the cell value is numeric
          if (typeof cellValue === 'number' && !Number.isNaN(cellValue)) {
            currentRowSum += cellValue;
            currentRowHasNumeric = true;
            // Also sum for column totals
            if (showTotals) {
              columnSums[headerCol.key] = (columnSums[headerCol.key] || 0) + cellValue;
            }
          }
        });
      } else {
        const metricLabelFallback = typeof metricOrHeadingItem === 'string' ? metricOrHeadingItem : metricOrHeadingItem?.label;
        const fallbackColumn = originalDataColumns.find(col => col.label === metricLabelFallback || col.key === metricLabelFallback);
        if (fallbackColumn) {
          displayLabel = fallbackColumn.label || metricLabelFallback;
          const originalDataKey = fallbackColumn.key;
          // Store the formatter for this metric row
          if (fallbackColumn.formatter) {
            (newRow as any).__formatter__ = fallbackColumn.formatter;
          }
          dynamicColumnHeaders.forEach((headerCol, dynamicColIndex) => {
            const originalDataRow = data[dynamicColIndex];
            let cellValue = null;
            if (originalDataRow) {
              cellValue = originalDataRow[originalDataKey];
            }
            newRow[headerCol.key] = cellValue;
            if (typeof cellValue === 'number' && !Number.isNaN(cellValue)) {
              currentRowSum += cellValue;
              currentRowHasNumeric = true;
              // Also sum for column totals
              if (showTotals) {
                columnSums[headerCol.key] = (columnSums[headerCol.key] || 0) + cellValue;
              }
            }
          });
        } else {
          // If still not found, render as an empty row with the identifier.
          console.warn(
            `Metric or item "${itemIdentifier}" (label: "${metricLabelFallback}") not found in data columns. Rendering as mostly empty row.`,
          );
          newRow.metric = displayLabel; // Show the identifier in the metric column
          dynamicColumnHeaders.forEach(headerCol => {
            newRow[headerCol.key] = ''; // Placeholder for missing data
          });
          // Also blank out the total for this "missing" metric row
          newRow.rowTotal = null;
        }
      }
      // This part is for non-heading rows or successfully found fallback metrics
      if (!newRow.metric) { // Ensure metric label is set if not already by fallback
        newRow.metric = displayLabel;
      }
      newRow.__isHeading = false;
      // Always set rowTotal for non-heading rows
      if (dynamicColumnHeaders.length > 0) {
        newRow.rowTotal = currentRowHasNumeric ? currentRowSum : null;
      }
      // Sum for the rowTotal column
      if (showTotals && currentRowHasNumeric) {
        columnSums.rowTotal = (columnSums.rowTotal || 0) + currentRowSum;
      }
    }
    transposedDataRows.push(newRow);
  });

  // Add totals row if showTotals is true
  if (showTotals && Object.keys(columnSums).length > 0) {
    const totalsRow: DataRecord = {
      metric: t('Summary'),
      __is_summary__: true, // Mark this as a totals row
    };
    // Find the last non-heading row to get formatters
    let lastNonHeadingRow: DataRecord | null = null;
    for (let i = transposedDataRows.length - 1; i >= 0; i--) {
      if (!transposedDataRows[i].__isHeading) {
        lastNonHeadingRow = transposedDataRows[i];
        break;
      }
    }
    // If we found a non-heading row, copy its formatter
    if (lastNonHeadingRow && lastNonHeadingRow.__formatter__) {
      totalsRow.__formatter__ = lastNonHeadingRow.__formatter__;
    }
    // Add the sum for each column
    transposedColumnHeaders.forEach(col => {
      if (col.key !== 'metric') {
        totalsRow[col.key] = columnSums[col.key] || null;
      }
    });
    transposedDataRows.push(totalsRow);
  }

  return {
    transposedData: transposedDataRows,
    transposedColumns: transposedColumnHeaders,
  };
}

const transformProps = (
  chartProps: TableChartProps,
): TableChartTransformedProps => {
  const {
    height,
    width,
    rawFormData: formData,
    queriesData = [],
    filterState,
    ownState: serverPaginationData,
    hooks: {
      onAddFilter: onChangeFilter,
      setDataMask = () => { },
      onContextMenu,
    },
    emitCrossFilters,
  } = chartProps;

  const {
    align_pn: alignPositiveNegative = true,
    color_pn: colorPositiveNegative = true,
    show_cell_bars: showCellBars = true,
    include_search: includeSearch = false,
    page_length: pageLength,
    server_pagination: serverPagination = false,
    server_page_length: serverPageLength = 10,
    order_sort: sortOrder = false,
    query_mode: queryMode,
    show_totals: showTotals,
    conditional_formatting: conditionalFormatting,
    allow_rearrange_columns: allowRearrangeColumns,
    allow_render_html: allowRenderHtml,
    time_compare,
    comparison_color_enabled: comparisonColorEnabled = false,
    comparison_color_scheme: comparisonColorScheme = ColorSchemeEnum.Green,
    comparison_type,
    metrics: formDataMetrics = [],
    enable_pivot,
    custom_css,
    timeseries_limit_metric,
    summary_position = 'bottom',
    show_all_segments = true,
    all_segments_position = 'start',
    column_sort_order = 'none',
  } = formData;
  const isUsingTimeComparison =
    !isEmpty(time_compare) &&
    queryMode === QueryMode.Aggregate &&
    comparison_type === ComparisonType.Values;

  const calculateBasicStyle = (
    percentDifferenceNum: number,
    colorOption: ColorSchemeEnum,
  ) => {
    if (percentDifferenceNum === 0) {
      return {
        arrow: '',
        arrowColor: '',
        // eslint-disable-next-line theme-colors/no-literal-colors
        backgroundColor: 'rgba(0,0,0,0.2)',
      };
    }
    const isPositive = percentDifferenceNum > 0;
    const arrow = isPositive ? '↑' : '↓';
    const arrowColor =
      colorOption === ColorSchemeEnum.Green
        ? isPositive
          ? ColorSchemeEnum.Green
          : ColorSchemeEnum.Red
        : isPositive
          ? ColorSchemeEnum.Red
          : ColorSchemeEnum.Green;
    const backgroundColor =
      colorOption === ColorSchemeEnum.Green
        ? `rgba(${isPositive ? '0,150,0' : '150,0,0'},0.2)`
        : `rgba(${isPositive ? '150,0,0' : '0,150,0'},0.2)`;

    return { arrow, arrowColor, backgroundColor };
  };

  const getBasicColorFormatter = memoizeOne(function getBasicColorFormatter(
    originalData: DataRecord[] | undefined,
    originalColumns: DataColumnMeta[],
    selectedColumns?: ConditionalFormattingConfig[],
  ) {
    // Transform data
    const relevantColumns = selectedColumns
      ? originalColumns.filter(col =>
        selectedColumns.some(scol => scol?.column?.includes(col.key)),
      )
      : originalColumns;

    return originalData?.map(originalItem => {
      const item: { [key: string]: BasicColorFormatterType } = {};
      relevantColumns.forEach(origCol => {
        if (
          (origCol.isMetric || origCol.isPercentMetric) &&
          !origCol.key.includes(ensureIsArray(timeOffsets)[0]) &&
          origCol.isNumeric
        ) {
          const originalValue = originalItem[origCol.key] || 0;
          const comparisonValue = origCol.isMetric
            ? originalItem?.[
            `${origCol.key}__${ensureIsArray(timeOffsets)[0]}`
            ] || 0
            : originalItem[
            `%${origCol.key.slice(1)}__${ensureIsArray(timeOffsets)[0]}`
            ] || 0;
          const { percentDifferenceNum } = calculateDifferences(
            originalValue as number,
            comparisonValue as number,
          );

          if (selectedColumns) {
            selectedColumns.forEach(col => {
              if (col?.column?.includes(origCol.key)) {
                const { arrow, arrowColor, backgroundColor } =
                  calculateBasicStyle(
                    percentDifferenceNum,
                    col.colorScheme || comparisonColorScheme,
                  );
                item[col.column] = {
                  mainArrow: arrow,
                  arrowColor,
                  backgroundColor,
                };
              }
            });
          } else {
            const { arrow, arrowColor, backgroundColor } = calculateBasicStyle(
              percentDifferenceNum,
              comparisonColorScheme,
            );
            item[`${origCol.key}`] = {
              mainArrow: arrow,
              arrowColor,
              backgroundColor,
            };
          }
        }
      });
      return item;
    });
  });

  const getBasicColorFormatterForColumn = (
    originalData: DataRecord[] | undefined,
    originalColumns: DataColumnMeta[],
    conditionalFormatting?: ConditionalFormattingConfig[],
  ) => {
    const selectedColumns = conditionalFormatting?.filter(
      (config: ConditionalFormattingConfig) =>
        config.column &&
        (config.colorScheme === ColorSchemeEnum.Green ||
          config.colorScheme === ColorSchemeEnum.Red),
    );

    return selectedColumns?.length
      ? getBasicColorFormatter(originalData, originalColumns, selectedColumns)
      : undefined;
  };

  const timeGrain = extractTimegrain(formData);

  const nonCustomNorInheritShifts = ensureIsArray(formData.time_compare).filter(
    (shift: string) => shift !== 'custom' && shift !== 'inherit',
  );
  const customOrInheritShifts = ensureIsArray(formData.time_compare).filter(
    (shift: string) => shift === 'custom' || shift === 'inherit',
  );

  let timeOffsets: string[] = [];

  if (isUsingTimeComparison && !isEmpty(nonCustomNorInheritShifts)) {
    timeOffsets = nonCustomNorInheritShifts;
  }

  // Shifts for custom or inherit time comparison
  if (isUsingTimeComparison && !isEmpty(customOrInheritShifts)) {
    if (customOrInheritShifts.includes('custom')) {
      timeOffsets = timeOffsets.concat([formData.start_date_offset]);
    }
    if (customOrInheritShifts.includes('inherit')) {
      timeOffsets = timeOffsets.concat(['inherit']);
    }
  }
  const comparisonSuffix = isUsingTimeComparison
    ? ensureIsArray(timeOffsets)[0]
    : '';

  const [metrics, percentMetrics, columns] = processColumns(chartProps);
  let comparisonColumns: DataColumnMeta[] = [];
  if (isUsingTimeComparison) {
    comparisonColumns = processComparisonColumns(
      columns,
      chartProps,
      comparisonSuffix,
    );
  }

  let baseQuery;
  let countQuery;
  let totalQuery;
  let rowCount;
  if (serverPagination) {
    [baseQuery, countQuery, totalQuery] = queriesData;
    rowCount = (countQuery?.data?.[0]?.rowcount as number) ?? 0;
  } else {
    [baseQuery, totalQuery] = queriesData;
    rowCount = baseQuery?.rowcount ?? 0;
  }
  const data = processDataRecords(baseQuery?.data, columns);
  const comparisonData = processComparisonDataRecords(
    baseQuery?.data,
    columns,
    comparisonSuffix,
  );
  const totals =
    showTotals && queryMode === QueryMode.Aggregate
      ? isUsingTimeComparison
        ? processComparisonTotals(comparisonSuffix, totalQuery?.data)
        : totalQuery?.data[0]
      : undefined;

  let passedData = isUsingTimeComparison ? comparisonData || [] : data;
  let passedColumns = isUsingTimeComparison ? comparisonColumns : columns;
  let passedTotals = totals;

  // Apply sorting for non-transpose mode (before transpose)
  if (!enable_pivot && sortOrder !== "none" && queryMode === QueryMode.Aggregate && timeseries_limit_metric) {
    // Find the metric column to sort by
    const sortMetricLabel = getMetricLabel(timeseries_limit_metric);
    const sortColumn = passedColumns.find(col => col.key === sortMetricLabel);

    if (sortColumn && sortColumn.isMetric) {
      passedData = [...passedData].sort((a, b) => {
        const aValue = a[sortColumn.key];
        const bValue = b[sortColumn.key];

        // Handle null/undefined values
        if (aValue == null && bValue == null) return 0;
        if (aValue == null) return 1;
        if (bValue == null) return -1;

        // Sort based on sortDesc
        return sortOrder === "desc"
          ? (bValue as number) - (aValue as number)
          : (aValue as number) - (bValue as number);
      });
    }
  }

  // Handle pivot/transpose AFTER comparison processing
  if (enable_pivot) {
    const { transposedData, transposedColumns } = transposeData(
      passedData,
      passedColumns,
      formDataMetrics,
      showTotals,
      formData.row_config,
      show_all_segments,
      all_segments_position,
      column_sort_order
    );
    passedData = transposedData;
    passedColumns = transposedColumns;

    // Apply sorting for transpose mode (after transpose)
    if (sortOrder !== "none") {

      // In transpose mode, find the metric row that corresponds to the sort metric
      const sortableRows = passedData.filter(row =>
        !row.__isHeading && !row.__is_summary__
      );

      // If we found the metric row, sort all non-heading/non-summary rows by rowTotal
      if (sortableRows.length > 0) {
        const headingRowsIndex: { index: number, row: DataRecord }[] = [];
        passedData.filter((row, index) => {
          if (row.__isHeading) {
            headingRowsIndex.push({
              index,
              row
            });
            return true;
          }
          return false;
        });
        const summaryRows = passedData.filter(row => row.__is_summary__);
        const dataRows = passedData.filter(row => !row.__isHeading && !row.__is_summary__);

        const sortedDataRows = [...dataRows].sort((a, b) => {
          // Sort by rowTotal (which represents the total across all segments)
          const aValue = a.rowTotal;
          const bValue = b.rowTotal;

          // Handle null/undefined values
          if (aValue == null && bValue == null) return 0;
          if (aValue == null) return 1;
          if (bValue == null) return -1;

          // Sort based on sortDesc
          return sortOrder === "desc"
            ? (bValue as number) - (aValue as number)
            : (aValue as number) - (bValue as number);
        });

        let headingSummaryIndexPointer = 0;
        const sortedData: DataRecord[] = [];
        for (let i = 0; i < passedData.length; i++) {
          // prioritize heading rows, then data rows, then summary rows for same index
          if (headingRowsIndex[headingSummaryIndexPointer] && i === headingRowsIndex[headingSummaryIndexPointer].index) {
            sortedData.push(headingRowsIndex[headingSummaryIndexPointer].row);
            headingSummaryIndexPointer++;
          }
          else if (sortedDataRows[i - headingRowsIndex.length] && i >= headingRowsIndex.length && i < headingRowsIndex.length + sortedDataRows.length) {
            sortedData.push(sortedDataRows[i - headingRowsIndex.length]);
          }
        }

        // Reconstruct the data maintaining heading positions and moving summary to desired position
        passedData = sortedData;

        // Handle summary row positioning separately
        if (summaryRows.length > 0) {
          if (summary_position === 'top') {
            passedData = [...summaryRows, ...passedData];
          } else {
            passedData = [...passedData, ...summaryRows];
          }
        }
      }
    }

    // Find and remove the summary row if present
    let summaryRowIdx = transposedData.findIndex(row => row.__is_summary__);
    let summaryRow = summaryRowIdx !== -1 ? transposedData.splice(summaryRowIdx, 1)[0] : undefined;

    // Insert summary row at the desired position
    if (summaryRow) {
      if (summary_position === 'top') {
        transposedData.unshift(summaryRow);
      } else {
        transposedData.push(summaryRow);
      }
    }

    // When transposed, totals are already included in the data as a row
    passedTotals = undefined;
  }

  const basicColorFormatters =
    comparisonColorEnabled && getBasicColorFormatter(baseQuery?.data, columns);
  const columnColorFormatters =
    getColorFormatters(conditionalFormatting, passedData) ??
    defaultColorFormatters;

  const basicColorColumnFormatters = getBasicColorFormatterForColumn(
    baseQuery?.data,
    columns,
    conditionalFormatting,
  );

  const startDateOffset = chartProps.rawFormData?.start_date_offset;

  return {
    height,
    width,
    isRawRecords: queryMode === QueryMode.Raw,
    data: passedData,
    totals: passedTotals,
    columns: passedColumns,
    serverPagination,
    metrics,
    percentMetrics,
    serverPaginationData: serverPagination
      ? serverPaginationData
      : defaultServerPaginationData,
    setDataMask,
    alignPositiveNegative,
    colorPositiveNegative,
    showCellBars,
    sortDesc: sortOrder,
    includeSearch,
    rowCount,
    pageSize: serverPagination
      ? serverPageLength
      : getPageSize(pageLength, passedData.length, passedColumns.length),
    filters: filterState.filters,
    emitCrossFilters,
    onChangeFilter,
    columnColorFormatters,
    timeGrain,
    allowRearrangeColumns,
    allowRenderHtml,
    onContextMenu,
    isUsingTimeComparison,
    basicColorFormatters,
    startDateOffset,
    basicColorColumnFormatters,
    rowConfig: chartProps.rawFormData.row_config,
    transposeColumnConfig: chartProps.rawFormData.transpose_column_config,
    custom_css,
  };
};

export default transformProps;
