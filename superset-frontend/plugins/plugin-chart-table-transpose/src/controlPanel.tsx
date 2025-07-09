/* eslint-disable camelcase */
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
  ColumnMeta,
  ColumnOption,
  ControlConfig,
  ControlPanelConfig,
  ControlPanelsContainerProps,
  ControlPanelState,
  ControlState,
  ControlStateMapping,
  D3_TIME_FORMAT_OPTIONS,
  Dataset,
  defineSavedMetrics,
  getStandardizedControls,
  QueryModeLabel,
  sections,
  sharedControls,
} from '@superset-ui/chart-controls';
import {
  AdhocMetric,
  AdhocMetricSimple,
  ensureIsArray,
  GenericDataType,
  isAdhocColumn,
  isPhysicalColumn,
  QueryFormColumn,
  QueryMode,
  SMART_DATE_ID,
  t,
} from '@superset-ui/core';

import { isEmpty } from 'lodash';
import { PAGE_SIZE_OPTIONS } from './consts';
import { ColorSchemeEnum } from './types';

// Define the type locally since it's not exported from @superset-ui/chart-controls
type ColumnConfigFormLayout = {
  [key: string]: any;
};

export const TRANSPOSE_CONFIG_FORM_LAYOUT: ColumnConfigFormLayout = {
  [GenericDataType.String]: [
    [
      'columnWidth',
      { name: 'horizontalAlign', override: { defaultValue: 'left' } },
    ],
    ['truncateLongCells'],
    ['indent', 'boldText', 'italicText'],
  ],
  [GenericDataType.Numeric]: [
    {
      tab: t('Display'),
      children: [
        [
          'columnWidth',
          { name: 'horizontalAlign', override: { defaultValue: 'right' } },
        ],
        ['showCellBars'],
        ['alignPositiveNegative'],
        ['colorPositiveNegative'],
      ],
    },
    {
      tab: t('Number formatting'),
      children: [
        ['d3NumberFormat'],
        ['d3SmallNumberFormat'],
        ['currencyFormat'],
      ],
    },
  ],
  [GenericDataType.Temporal]: [
    [
      'columnWidth',
      { name: 'horizontalAlign', override: { defaultValue: 'left' } },
    ],
    ['d3TimeFormat'],
  ],
  [GenericDataType.Boolean]: [
    [
      'columnWidth',
      { name: 'horizontalAlign', override: { defaultValue: 'left' } },
    ],
  ],
};

// Add a new config form layout for row headers
export const TRANSPOSE_ROW_CONFIG_FORM_LAYOUT: ColumnConfigFormLayout = {
  [GenericDataType.String]: [
    [
      { name: 'horizontalAlign', override: { defaultValue: 'left' } },
    ],
    ['boldText', 'italicText'],
    ['indent', 'fontSize']
  ],
  [GenericDataType.Numeric]: [
    {
      tab: t('Display'),
      children: [
        [
          'indent',
          { name: 'horizontalAlign', override: { defaultValue: 'right' } },
        ],
      ],
    },
    {
      tab: t('Number formatting'),
      children: [
        ['d3NumberFormat'],
        ['d3SmallNumberFormat'],
        ['currencyFormat'],
      ],
    },
  ],
};

function getQueryMode(controls: ControlStateMapping): QueryMode {
  const mode = controls?.query_mode?.value;
  if (mode === QueryMode.Aggregate || mode === QueryMode.Raw) {
    return mode as QueryMode;
  }
  const rawColumns = controls?.all_columns?.value as
    | QueryFormColumn[]
    | undefined;
  const hasRawColumns = rawColumns && rawColumns.length > 0;
  return hasRawColumns ? QueryMode.Raw : QueryMode.Aggregate;
}

/**
 * Visibility check
 */
function isQueryMode(mode: QueryMode) {
  return ({ controls }: Pick<ControlPanelsContainerProps, 'controls'>) =>
    getQueryMode(controls) === mode;
}

const isAggMode = isQueryMode(QueryMode.Aggregate);
const isRawMode = isQueryMode(QueryMode.Raw);

const validateAggControlValues = (
  controls: ControlStateMapping,
  values: any[],
) => {
  const areControlsEmpty = values.every(val => ensureIsArray(val).length === 0);
  return areControlsEmpty && isAggMode({ controls })
    ? [t('Group By, Metrics or Percentage Metrics must have a value')]
    : [];
};

const queryMode: ControlConfig<'RadioButtonControl'> = {
  type: 'RadioButtonControl',
  label: t('Query mode'),
  default: null,
  options: [
    [QueryMode.Aggregate, QueryModeLabel[QueryMode.Aggregate]],
    [QueryMode.Raw, QueryModeLabel[QueryMode.Raw]],
  ],
  mapStateToProps: ({ controls }) => ({ value: getQueryMode(controls) }),
  rerender: ['all_columns', 'groupby', 'metrics', 'percent_metrics'],
};

const allColumnsControl: typeof sharedControls.groupby = {
  ...sharedControls.groupby,
  label: t('Columns'),
  description: t('Columns to display'),
  multi: true,
  freeForm: true,
  allowAll: true,
  commaChoosesOption: false,
  optionRenderer: c => <ColumnOption showType column={c} />,
  valueRenderer: c => <ColumnOption column={c} />,
  valueKey: 'column_name',
  mapStateToProps: ({ datasource, controls }, controlState) => ({
    options: datasource?.columns || [],
    queryMode: getQueryMode(controls),
    externalValidationErrors:
      isRawMode({ controls }) && ensureIsArray(controlState?.value).length === 0
        ? [t('must have a value')]
        : [],
  }),
  visibility: isRawMode,
  resetOnHide: false,
};

const percentMetricsControl: typeof sharedControls.metrics = {
  ...sharedControls.metrics,
  label: t('Percentage metrics'),
  description: t(
    'Select one or many metrics to display, that will be displayed in the percentages of total. ' +
    'Percentage metrics will be calculated only from data within the row limit. ' +
    'You can use an aggregation function on a column or write custom SQL to create a percentage metric.',
  ),
  visibility: isAggMode,
  resetOnHide: false,
  mapStateToProps: ({ datasource, controls }, controlState) => ({
    columns: datasource?.columns || [],
    savedMetrics: defineSavedMetrics(datasource),
    datasource,
    datasourceType: datasource?.type,
    queryMode: getQueryMode(controls),
    externalValidationErrors: validateAggControlValues(controls, [
      controls.groupby?.value,
      controls.metrics?.value,
      controlState?.value,
    ]),
  }),
  rerender: ['groupby', 'metrics'],
  default: [],
  validators: [],
};

/**
 * Generate comparison column names for a given column.
 */
const generateComparisonColumns = (colname: string) => [
  `${t('Main')} ${colname}`,
  `# ${colname}`,
  `△ ${colname}`,
  `% ${colname}`,
];
/**
 * Generate column types for the comparison columns.
 */
const generateComparisonColumnTypes = (count: number) =>
  Array(count).fill(GenericDataType.Numeric);

const processComparisonColumns = (columns: any[], suffix: string) =>
  columns
    .map(col => {
      if (!col.label.includes(suffix)) {
        return [
          {
            label: `${t('Main')} ${col.label}`,
            value: `${t('Main')} ${col.value}`,
          },
          {
            label: `# ${col.label}`,
            value: `# ${col.value}`,
          },
          {
            label: `△ ${col.label}`,
            value: `△ ${col.value}`,
          },
          {
            label: `% ${col.label}`,
            value: `% ${col.value}`,
          },
        ];
      }
      return [];
    })
    .flat();

const PIVOT_CONTROLS = {
  label: t('Transpose Options'),
  expanded: false,
  controlSetRows: [
    [
      {
        name: 'enable_pivot',
        config: {
          type: 'CheckboxControl',
          label: t('Transpose Table'),
          default: false,
          description: t('Transpose rows and columns of the table'),
          renderTrigger: true,
        },
      },
    ],
  ],
};

// Remove the old pivot controls (pivot_rows, pivot_columns, pivot_metric, pivot_aggfunc)

const config: ControlPanelConfig = {
  controlPanelSections: [
    {
      label: t('Query'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'query_mode',
            config: queryMode,
          },
        ],
        [
          {
            name: 'groupby',
            override: {
              multi: false,
              visibility: isAggMode,
              resetOnHide: false,
              mapStateToProps: (
                state: ControlPanelState,
                controlState: ControlState,
              ) => {
                const { controls } = state;
                const originalMapStateToProps =
                  sharedControls?.groupby?.mapStateToProps;
                const newState =
                  originalMapStateToProps?.(state, controlState) ?? {};
                newState.externalValidationErrors = validateAggControlValues(
                  controls,
                  [
                    controls.metrics?.value,
                    controls.percent_metrics?.value,
                    controlState.value,
                  ],
                );

                return newState;
              },
              rerender: ['metrics', 'percent_metrics'],
            },
          },
        ],
        [
          {
            name: 'time_grain_sqla',
            config: {
              ...sharedControls.time_grain_sqla,
              visibility: ({ controls }) => {
                const dttmLookup = Object.fromEntries(
                  ensureIsArray(controls?.groupby?.options).map(option => [
                    option.column_name,
                    option.is_dttm,
                  ]),
                );

                return ensureIsArray(controls?.groupby.value)
                  .map(selection => {
                    if (isAdhocColumn(selection)) {
                      return true;
                    }
                    if (isPhysicalColumn(selection)) {
                      return !!dttmLookup[selection];
                    }
                    return false;
                  })
                  .some(Boolean);
              },
            },
          },
          'temporal_columns_lookup',
        ],
        [
          {
            name: 'metrics',
            override: {
              validators: [],
              visibility: isAggMode,
              resetOnHide: false,
              mapStateToProps: (
                { controls, datasource, form_data }: ControlPanelState,
                controlState: ControlState,
              ) => ({
                columns: datasource?.columns[0]?.hasOwnProperty('filterable')
                  ? (datasource as Dataset)?.columns?.filter(
                    (c: ColumnMeta) => c.filterable,
                  )
                  : datasource?.columns,
                savedMetrics: defineSavedMetrics(datasource),
                // current active adhoc metrics
                selectedMetrics:
                  form_data.metrics ||
                  (form_data.metric ? [form_data.metric] : []),
                datasource,
                externalValidationErrors: validateAggControlValues(controls, [
                  controls.groupby?.value,
                  controls.percent_metrics?.value,
                  controlState.value,
                ]),
              }),
              rerender: ['groupby', 'percent_metrics'],
            },
          },
          {
            name: 'all_columns',
            config: allColumnsControl,
          },
        ],
        [
          {
            name: 'percent_metrics',
            config: {
              ...percentMetricsControl,
              visibility: ({ controls }: ControlPanelsContainerProps) =>
                isAggMode({ controls }) && !Boolean(controls?.enable_pivot?.value)
            },
          },
        ],
        ['adhoc_filters'],
        [
          {
            name: 'timeseries_limit_metric',
            override: {
              visibility: ({ controls }: ControlPanelsContainerProps) =>
                isAggMode({ controls }) && !Boolean(controls?.enable_pivot?.value),
              resetOnHide: false,
            },
          },
          {
            name: 'order_by_cols',
            config: {
              type: 'SelectControl',
              label: t('Ordering'),
              description: t('Order results by selected columns'),
              multi: true,
              default: [],
              mapStateToProps: ({ datasource }) => ({
                choices: datasource?.hasOwnProperty('order_by_choices')
                  ? (datasource as Dataset)?.order_by_choices
                  : datasource?.columns || [],
              }),
              visibility: isRawMode,
              resetOnHide: false,
            },
          },
        ],
        [
          {
            name: 'server_pagination',
            config: {
              type: 'CheckboxControl',
              label: t('Server pagination'),
              description: t(
                'Enable server side pagination of results (experimental feature)',
              ),
              default: false,
            },
          },
        ],
        [
          {
            name: 'row_limit',
            override: {
              default: 1000,
              visibility: ({ controls }: ControlPanelsContainerProps) =>
                !controls?.server_pagination?.value,
            },
          },
          {
            name: 'server_page_length',
            config: {
              type: 'SelectControl',
              freeForm: true,
              label: t('Server Page Length'),
              default: 10,
              choices: PAGE_SIZE_OPTIONS,
              description: t('Rows per page, 0 means no pagination'),
              visibility: ({ controls }: ControlPanelsContainerProps) =>
                Boolean(controls?.server_pagination?.value),
            },
          },
        ],
        [
          {
            name: 'order_sort',
            config: {
              type: 'RadioButtonControl',
              label: t('Sort order'),
              default: "none",
              options: [
                ["none", t('None')],
                ["asc", t('Ascending')],
                ["desc", t('Descending')],
              ],
              description: t(
                'Choose the sort order for the results. None means no sorting will be applied.',
              ),
              visibility: ({ controls }: ControlPanelsContainerProps) =>
                isAggMode({ controls }) && Boolean(controls?.enable_pivot?.value),
              resetOnHide: false,
            },
          },
        ],
        [
          {
            name: 'show_all_segments',
            config: {
              type: 'CheckboxControl',
              label: t('Show All Segments column'),
              default: true,
              description: t('Show or hide the All Segments total column in transposed table'),
              visibility: ({ controls }: ControlPanelsContainerProps) =>
                isAggMode({ controls }) && Boolean(controls?.enable_pivot?.value),
              resetOnHide: false,
            },
          },
          {
            name: 'all_segments_position',
            config: {
              type: 'RadioButtonControl',
              label: t('All Segments position'),
              default: 'start',
              options: [
                ['start', t('Start')],
                ['end', t('End')],
              ],
              description: t('Choose whether to display the All Segments column at the start or end of the table'),
              visibility: ({ controls }: ControlPanelsContainerProps) =>
                isAggMode({ controls }) && 
                Boolean(controls?.enable_pivot?.value) && 
                Boolean(controls?.show_all_segments?.value),
              resetOnHide: false,
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'show_totals',
            config: {
              type: 'CheckboxControl',
              label: t('Show summary'),
              default: false,
              description: t(
                'Show total aggregations of selected metrics. Note that row limit does not apply to the result.',
              ),
              visibility: isAggMode,
              resetOnHide: false,
            },
          },
          {
            name: 'summary_position',
            config: {
              type: 'RadioButtonControl',
              label: t('Summary position'),
              default: 'bottom',
              options: [
                ['top', t('Top')],
                ['bottom', t('Bottom')],
              ],
              description: t('Choose whether to display the summary at the top or bottom of the table.'),
              visibility: ({ controls }) => Boolean(controls?.show_totals?.value),
              renderTrigger: true,
            },
          },
        ],
      ],
    },
    {
      label: t('Options'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'table_timestamp_format',
            config: {
              type: 'SelectControl',
              freeForm: true,
              label: t('Timestamp format'),
              default: SMART_DATE_ID,
              renderTrigger: true,
              clearable: false,
              choices: D3_TIME_FORMAT_OPTIONS,
              description: t('D3 time format for datetime columns'),
            },
          },
        ],
        [
          {
            name: 'page_length',
            config: {
              type: 'SelectControl',
              freeForm: true,
              renderTrigger: true,
              label: t('Page length'),
              default: null,
              choices: PAGE_SIZE_OPTIONS,
              description: t('Rows per page, 0 means no pagination'),
              visibility: ({ controls }: ControlPanelsContainerProps) =>
                !controls?.server_pagination?.value,
            },
          },
          null,
        ],
        [
          {
            name: 'include_search',
            config: {
              type: 'CheckboxControl',
              label: t('Search box'),
              renderTrigger: true,
              default: false,
              description: t('Whether to include a client-side search box'),
            },
          },
        ],
        [
          {
            name: 'allow_rearrange_columns',
            config: {
              type: 'CheckboxControl',
              label: t('Allow columns to be rearranged'),
              renderTrigger: true,
              default: false,
              description: t(
                "Allow end user to drag-and-drop column headers to rearrange them. Note their changes won't persist for the next time they open the chart.",
              ),
              visibility: ({ controls }) =>
                isEmpty(controls?.time_compare?.value),
            },
          },
        ],
        [
          {
            name: 'allow_render_html',
            config: {
              type: 'CheckboxControl',
              label: t('Render columns in HTML format'),
              renderTrigger: true,
              default: true,
              description: t(
                'Renders table cells as HTML when applicable. For example, HTML <a> tags will be rendered as hyperlinks.',
              ),
            },
          },
        ],
        [
          {
            name: 'column_config',
            config: {
              type: 'ColumnConfigControl',
              label: t('Customize columns'),
              description: t('Further customize how to display each column'),
              width: 400,
              height: 320,
              renderTrigger: true,
              visibility: ({ controls }: ControlPanelsContainerProps) =>
                !controls?.enable_pivot?.value,
              shouldMapStateToProps() {
                return true;
              },
              mapStateToProps(explore, _, chart) {

                const timeComparisonStatus = !!explore?.controls?.time_compare?.value;

                const { colnames: _colnames, coltypes: _coltypes } =
                  chart?.queriesResponse?.[0] ?? {};
                let colnames: string[] = _colnames || [];
                let coltypes: GenericDataType[] = _coltypes || [];
                const enablePivot = explore?.form_data?.enable_pivot;

                if (enablePivot && colnames.length > 0) {
                  // When transposed, rows become columns
                  // The original columns (except the first groupby column) become row headers
                  // The metrics become the new columns

                  // Get the groupby columns (usually the first column(s) that are strings)
                  const groupbyColumns = ensureIsArray(explore?.form_data?.groupby);
                  const groupbyColumnNames = groupbyColumns.map(col => {
                    if (typeof col === 'string') {
                      return col;
                    } else if (col && typeof col === 'object') {
                      if (isPhysicalColumn(col)) {
                        return col;
                      } else if (isAdhocColumn(col)) {
                        return col.label || 'Column';
                      }
                      return 'Column';
                    }
                    return 'Column';
                  });

                  // When transposed, the structure is:
                  // First column: 'metric' (contains metric names)
                  // Second column: 'Total' (if totals are enabled)
                  // Following columns: Values from the first groupby column (these become column headers)

                  // Get the actual data values that will become column headers
                  const dataValues = chart?.queriesResponse?.[0]?.data || [];
                  const firstGroupbyColumn = groupbyColumnNames[0];

                  // Extract unique values from the first groupby column
                  const uniqueColumnValues = firstGroupbyColumn && dataValues.length > 0
                    ? [...new Set(dataValues.map((row: any) => row[firstGroupbyColumn]))]
                      .filter(val => val !== null && val !== undefined)
                      .map(val => String(val))
                    : [];

                  // Build the transposed column structure
                  colnames = ['metric']; // First column is always 'metric'
                  coltypes = [GenericDataType.String];

                  // Add Total column if totals are enabled
                  if (explore?.form_data?.show_totals) {
                    colnames.push('Total');
                    coltypes.push(GenericDataType.Numeric);
                  }

                  // Add columns for each unique value from the groupby
                  uniqueColumnValues.forEach(colValue => {
                    colnames.push(colValue);
                    coltypes.push(GenericDataType.Numeric);
                  });
                }

                if (timeComparisonStatus) {
                  /**
                   * Replace numeric columns with sets of comparison columns.
                   */
                  const updatedColnames: string[] = [];
                  const updatedColtypes: GenericDataType[] = [];
                  colnames.forEach((colname, index) => {
                    if (coltypes[index] === GenericDataType.Numeric) {
                      updatedColnames.push(
                        ...generateComparisonColumns(colname),
                      );
                      updatedColtypes.push(...generateComparisonColumnTypes(4));
                    } else {
                      updatedColnames.push(colname);
                      updatedColtypes.push(coltypes[index]);
                    }
                  });

                  colnames = updatedColnames;
                  coltypes = updatedColtypes;
                }

                return {
                  columnsPropsObject: { colnames, coltypes },
                  configFormLayout: TRANSPOSE_CONFIG_FORM_LAYOUT,
                };
              },
            },
          },
        ],
        [
          {
            name: 'row_config',
            config: {
              type: 'ColumnConfigControl',
              label: t('Customize row headers in Metrics'),
              description: t('Customize how to display metric row headers when table is transposed'),
              width: 400,
              height: 320,
              renderTrigger: true,
              visibility: ({ controls }: ControlPanelsContainerProps) =>
                Boolean(controls?.enable_pivot?.value),
              shouldMapStateToProps() {
                return true;
              },
              mapStateToProps(explore, _, chart) {
                const enablePivot = explore?.form_data?.enable_pivot;

                if (!enablePivot) {
                  return {
                    columnsPropsObject: { colnames: [], coltypes: [] },
                    configFormLayout: TRANSPOSE_ROW_CONFIG_FORM_LAYOUT,
                  };
                }

                // Get the metrics that will become row headers
                const metrics = ensureIsArray(explore?.form_data?.metrics);
                const rowNames: string[] = [];
                const rowTypes: GenericDataType[] = [];

                metrics.forEach(metric => {
                  if (metric) {
                    if (typeof metric === 'string') {
                      // Simple metric (column name)
                      rowNames.push(metric);
                      rowTypes.push(GenericDataType.Numeric); // Assume numeric for simple metrics
                    } else if (typeof metric === 'object' && (metric as any).emptyRowHeading !== true) {
                      const adhocMetric = metric as AdhocMetric;
                      const label = adhocMetric.label ||
                        ('sqlExpression' in adhocMetric ? adhocMetric.sqlExpression : null) ||
                        ('column' in adhocMetric && (adhocMetric as AdhocMetricSimple).column?.column_name) ||
                        'Metric';
                      rowNames.push(label);

                      // Check if it's an aggregate metric
                      const isAggregateMetric =
                        (adhocMetric.expressionType === 'SQL' && adhocMetric.sqlExpression) ||
                        (adhocMetric.expressionType === 'SIMPLE' && adhocMetric.aggregate);

                      // Set data type based on whether it's an aggregate
                      rowTypes.push(isAggregateMetric ? GenericDataType.Numeric : GenericDataType.String);
                    }
                  }
                });

                // Add row headers from heading metrics
                const rowHeaders = metrics
                  .filter((metric): metric is AdhocMetric & { emptyRowHeadingText: string } => {
                    if (typeof metric === 'object' && metric !== null) {
                      const colName = (metric as AdhocMetricSimple).column?.column_name;
                      return typeof colName === 'string' && colName.startsWith('__heading');
                    }
                    return false;
                  })
                  .map(metric => metric.emptyRowHeadingText);

                rowHeaders.forEach(header => {
                  rowNames.push(header);
                  rowTypes.push(GenericDataType.String);
                });

                return {
                  columnsPropsObject: { colnames: rowNames, coltypes: rowTypes },
                  configFormLayout: TRANSPOSE_ROW_CONFIG_FORM_LAYOUT,
                };
              },
            },
          },
        ],
      ],
    },
    {
      label: t('Visual formatting'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'show_cell_bars',
            config: {
              type: 'CheckboxControl',
              label: t('Show Cell bars'),
              renderTrigger: true,
              default: true,
              description: t(
                'Whether to display a bar chart background in table columns',
              ),
            },
          },
        ],
        [
          {
            name: 'align_pn',
            config: {
              type: 'CheckboxControl',
              label: t('Align +/-'),
              renderTrigger: true,
              default: false,
              description: t(
                'Whether to align background charts with both positive and negative values at 0',
              ),
            },
          },
        ],
        [
          {
            name: 'color_pn',
            config: {
              type: 'CheckboxControl',
              label: t('add colors to cell bars for +/-'),
              renderTrigger: true,
              default: true,
              description: t(
                'Whether to colorize numeric values by whether they are positive or negative',
              ),
            },
          },
        ],
        [
          {
            name: 'comparison_color_enabled',
            config: {
              type: 'CheckboxControl',
              label: t('basic conditional formatting'),
              renderTrigger: true,
              visibility: ({ controls }) =>
                !isEmpty(controls?.time_compare?.value),
              default: false,
              description: t(
                'This will be applied to the whole table. Arrows (↑ and ↓) will be added to ' +
                'main columns for increase and decrease. Basic conditional formatting can be ' +
                'overwritten by conditional formatting below.',
              ),
            },
          },
        ],
        [
          {
            name: 'comparison_color_scheme',
            config: {
              type: 'SelectControl',
              label: t('color type'),
              default: ColorSchemeEnum.Green,
              renderTrigger: true,
              choices: [
                [ColorSchemeEnum.Green, 'Green for increase, red for decrease'],
                [ColorSchemeEnum.Red, 'Red for increase, green for decrease'],
              ],
              visibility: ({ controls }) =>
                !isEmpty(controls?.time_compare?.value) &&
                Boolean(controls?.comparison_color_enabled?.value),
              description: t(
                'Adds color to the chart symbols based on the positive or ' +
                'negative change from the comparison value.',
              ),
            },
          },
        ],
        [
          {
            name: 'conditional_formatting',
            config: {
              type: 'ConditionalFormattingControl',
              renderTrigger: true,
              label: t('Custom Conditional Formatting'),
              extraColorChoices: [
                {
                  value: ColorSchemeEnum.Green,
                  label: t('Green for increase, red for decrease'),
                },
                {
                  value: ColorSchemeEnum.Red,
                  label: t('Red for increase, green for decrease'),
                },
              ],
              description: t(
                'Apply conditional color formatting to numeric columns',
              ),
              shouldMapStateToProps() {
                return true;
              },
              mapStateToProps(explore, _, chart) {
                const verboseMap = explore?.datasource?.hasOwnProperty(
                  'verbose_map',
                )
                  ? (explore?.datasource as Dataset)?.verbose_map
                  : (explore?.datasource?.columns ?? {});
                const chartStatus = chart?.chartStatus;
                const { colnames, coltypes } =
                  chart?.queriesResponse?.[0] ?? {};
                const numericColumns =
                  Array.isArray(colnames) && Array.isArray(coltypes)
                    ? colnames
                      .filter(
                        (colname: string, index: number) =>
                          coltypes[index] === GenericDataType.Numeric,
                      )
                      .map((colname: string) => ({
                        value: colname,
                        label: Array.isArray(verboseMap)
                          ? colname
                          : (verboseMap[colname] ?? colname),
                      }))
                    : [];
                const columnOptions = explore?.controls?.time_compare?.value
                  ? processComparisonColumns(
                    numericColumns || [],
                    ensureIsArray(
                      explore?.controls?.time_compare?.value,
                    )[0]?.toString() || '',
                  )
                  : numericColumns;

                return {
                  removeIrrelevantConditions: chartStatus === 'success',
                  columnOptions,
                  verboseMap,
                };
              },
            },
          },
        ],
      ],
      visibility: ({ controls }: ControlPanelsContainerProps) =>
        !Boolean(controls?.enable_pivot?.value)
    },
    {
      label: t('Custom Css'),
      expanded: false,
      controlSetRows: [
        [
          {
            name: 'custom_css',
            config: {
              type: 'TextAreaControl',
              label: t('Custom CSS'),
              renderTrigger: true,
              default: '',
              description: t('Apply custom CSS to the table. Use .superset-data-ui-table to target the table element.'),
              language: 'css',
              minLines: 10,
              maxLines: 30,
            },
          },
        ],
      ],
      visibility: ({ controls }: ControlPanelsContainerProps) =>
        Boolean(controls?.enable_pivot?.value)
    },
    {
      ...sections.timeComparisonControls({
        multi: false,
        showCalculationType: false,
        showFullChoices: false,
      }),
      visibility: ({ controls }: ControlPanelsContainerProps) =>
        isAggMode({ controls }) && !Boolean(controls?.enable_pivot?.value)
    },
    PIVOT_CONTROLS,
  ],
  formDataOverrides: formData => ({
    ...formData,
    metrics: getStandardizedControls().popAllMetrics(),
    groupby: getStandardizedControls().popAllColumns(),
  }),
};

export default config;
