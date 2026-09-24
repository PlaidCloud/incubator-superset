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
import { t } from '@apache-superset/core/translation';
import { GenericDataType } from '@apache-superset/core/common';
import {
  ControlPanelConfig,
  ControlPanelsContainerProps,
  ControlPanelState,
  ControlSetItem,
  ControlState,
  D3_TIME_FORMAT_OPTIONS,
  sharedControls,
} from '@superset-ui/chart-controls';
import {
  ensureIsArray,
  getColumnLabel,
  getMetricLabel,
  QueryFormColumn,
  QueryFormMetric,
  validateNonEmpty,
} from '@superset-ui/core';

const columnLabels = (cols: unknown): string[] =>
  ensureIsArray(cols).map(c => getColumnLabel(c as QueryFormColumn));
const metricLabels = (metrics: unknown): string[] =>
  ensureIsArray(metrics).map(m => getMetricLabel(m as QueryFormMetric));

const singleColumn = (
  name: string,
  label: string,
  description: string,
  required = false,
): ControlSetItem => ({
  name,
  config: {
    ...sharedControls.groupby,
    label,
    description,
    multi: false,
    validators: required ? [validateNonEmpty] : [],
  },
});

const fontSize = (name: string, label: string, def = 12): ControlSetItem => ({
  name,
  config: {
    type: 'TextControl',
    label,
    isInt: true,
    renderTrigger: true,
    default: def,
  },
});

const fontColor = (
  name: string,
  label: string,
  def: { r: number; g: number; b: number; a: number },
): ControlSetItem => ({
  name,
  config: {
    type: 'ColorPickerControl',
    label,
    renderTrigger: true,
    default: def,
  },
});

const hAlign = (name: string, label: string, def = 'left'): ControlSetItem => ({
  name,
  config: {
    type: 'RadioButtonControl',
    label,
    description: t('Horizontal alignment'),
    renderTrigger: true,
    default: def,
    options: [
      ['left', t('Left')],
      ['center', t('Center')],
      ['right', t('Right')],
    ],
  },
});

const WHITE = { r: 255, g: 255, b: 255, a: 1 };
const BLACK = { r: 0, g: 0, b: 0, a: 1 };

const config: ControlPanelConfig = {
  controlPanelSections: [
    {
      label: t('Query'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'groupbyRows',
            config: {
              ...sharedControls.groupby,
              label: t('Rows'),
              description: t(
                'Hierarchy columns, outer to inner. Each level gets its own subtotal row and a collapsible marker.',
              ),
              rerender: ['default_collapsed_level', 'order_by_col'],
              validators: [validateNonEmpty],
            },
          },
        ],
        [
          {
            name: 'metrics',
            config: {
              ...sharedControls.metrics,
              validators: [],
              rerender: ['marker_progress_col', 'order_by_col'],
            },
          },
        ],
        [
          singleColumn(
            'date_start_col',
            t('Start date'),
            t('Column with marker start dates'),
            true,
          ),
        ],
        [
          singleColumn(
            'date_end_col',
            t('End date'),
            t('Column with marker end dates'),
            true,
          ),
        ],
        ['adhoc_filters'],
        [
          {
            name: 'emit_full_hierarchy',
            config: {
              type: 'CheckboxControl',
              label: t('Cross Filter hierarchy'),
              description: t(
                'Emit every level of the clicked row as a cross filter (otherwise only the innermost level)',
              ),
              default: true,
            },
          },
        ],
        [
          {
            name: 'row_limit',
            config: {
              ...sharedControls.row_limit,
              label: t('Cell limit'),
              description: t('Limits the number of cells that get retrieved.'),
            },
          },
        ],
        [
          {
            name: 'order_by_col',
            config: {
              type: 'SelectControl',
              label: t('Sort by'),
              description: t(
                'Hierarchy column or metric used to order sibling rows. Empty keeps the hierarchy order.',
              ),
              multi: false,
              clearable: true,
              default: [],
              renderTrigger: true,
              shouldMapStateToProps: () => true,
              mapStateToProps: (state: ControlPanelState) => ({
                options: [
                  ...columnLabels(state?.form_data?.groupbyRows),
                  ...metricLabels(state?.form_data?.metrics),
                ].map(v => ({ label: v, value: v })),
              }),
            },
          },
        ],
        [
          {
            name: 'order_desc',
            config: {
              type: 'CheckboxControl',
              label: t('Sort Descending'),
              default: true,
              renderTrigger: true,
              description: t('Whether to sort descending or ascending'),
            },
          },
        ],
        [
          {
            name: 'default_collapsed_level',
            config: {
              type: 'SelectControl',
              label: t('Default collapsed level'),
              description: t(
                'Levels (counted from the innermost) that start collapsed. 0 = everything expanded.',
              ),
              renderTrigger: false,
              default: 0,
              multi: false,
              visibility: ({ controls }: ControlPanelsContainerProps) =>
                ensureIsArray(controls?.groupbyRows?.value).length > 0,
              shouldMapStateToProps: () => true,
              mapStateToProps: (state: ControlPanelState) => {
                const rows = columnLabels(state?.form_data?.groupbyRows);
                const n = rows.length;
                return {
                  options: rows.map((r, i) => ({
                    label: `${i} - ${r}`,
                    value: n - i - 1,
                  })),
                };
              },
            },
          },
        ],
        [
          {
            name: 'marker_progress_col',
            config: {
              type: 'SelectControl',
              label: t('Progress indicator'),
              description: t(
                'Metric (0..1) painted as the filled share of each marker',
              ),
              multi: false,
              clearable: true,
              renderTrigger: false,
              visibility: ({ controls }: ControlPanelsContainerProps) =>
                ensureIsArray(controls?.metrics?.value).length > 0,
              shouldMapStateToProps: () => true,
              mapStateToProps: (
                state: ControlPanelState,
                controlState: ControlState,
              ) => {
                const options = metricLabels(state?.controls?.metrics?.value);
                const value = controlState?.value;
                return {
                  options: options.map(v => ({ label: v, value: v })),
                  value: options.includes(value as string) ? value : null,
                };
              },
            },
          },
        ],
      ],
    },
    {
      label: t('Inner marker description'),
      tabOverride: 'data',
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'marker_description_cols',
            config: {
              ...sharedControls.groupby,
              label: t('Description columns'),
              description: t(
                'Columns shown as a second text line inside the marker',
              ),
              validators: [],
              multi: true,
            },
          },
        ],
      ],
    },
    {
      label: t('Markers details on the sides'),
      tabOverride: 'data',
      expanded: true,
      controlSetRows: [
        [
          singleColumn(
            'marker_label_left_col',
            t('Left'),
            t('Column with data to display to the left of the marker'),
          ),
        ],
        [
          singleColumn(
            'marker_label_right_col',
            t('Right'),
            t('Column with data to display to the right of the marker'),
          ),
        ],
        [
          singleColumn(
            'marker_label_top_col',
            t('Top'),
            t('Column with data to display to the top of the marker'),
          ),
        ],
        [
          singleColumn(
            'marker_label_bottom_col',
            t('Bottom'),
            t('Column with data to display to the bottom of the marker'),
          ),
        ],
      ],
    },
    {
      label: t('Options'),
      tabOverride: 'data',
      expanded: false,
      controlSetRows: [
        [
          {
            name: 'showGrandTotal',
            config: {
              type: 'CheckboxControl',
              label: t('Show grand total'),
              default: true,
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'hideExpandedRows',
            config: {
              type: 'CheckboxControl',
              label: t('Hide totals in expanded rows'),
              default: false,
              renderTrigger: true,
            },
          },
        ],
      ],
    },
    {
      label: t('Tablespace options'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'valueFormat',
            config: { ...sharedControls.y_axis_format, label: t('Value format') },
          },
        ],
        [
          {
            name: 'date_format',
            config: {
              type: 'SelectControl',
              freeForm: true,
              label: t('Date format'),
              default: '%d.%m.%Y',
              renderTrigger: true,
              choices: D3_TIME_FORMAT_OPTIONS,
              description: t('D3 time format for datetime columns'),
            },
          },
        ],
        [fontSize('value_font_size', t('Font size value'))],
        [fontSize('header_font_size', t('Font size headers'))],
        [hAlign('label_align', t('Headers horizontal alignment'))],
        [
          {
            name: 'metrics_config',
            config: {
              type: 'ColumnConfigControl',
              label: t('Customize metrics'),
              description: t('Number format per metric'),
              renderTrigger: true,
              configFormLayout: {
                [GenericDataType.Numeric]: [['d3NumberFormat']],
                [GenericDataType.Temporal]: [['d3TimeFormat']],
                [GenericDataType.String]: [],
                [GenericDataType.Boolean]: [],
              },
              shouldMapStateToProps: () => true,
              mapStateToProps(
                explore: ControlPanelState,
                _: ControlState,
                chart?: { queriesResponse?: { colnames?: string[]; coltypes?: number[] }[] },
              ) {
                const q1 = chart?.queriesResponse?.[1];
                const wanted = metricLabels(explore?.controls?.metrics?.value);
                const colnames: string[] = [];
                const coltypes: number[] = [];
                (q1?.colnames ?? []).forEach((c, i) => {
                  if (wanted.includes(c)) {
                    colnames.push(c);
                    coltypes.push(q1?.coltypes?.[i] ?? 0);
                  }
                });
                return { columnsPropsObject: { colnames, coltypes } };
              },
            },
          },
        ],
      ],
    },
    {
      label: t('Chart markers'),
      expanded: true,
      controlSetRows: [
        ['color_scheme'],
        [
          {
            name: 'show_marker_label',
            config: {
              type: 'CheckboxControl',
              label: t('Show markers labels'),
              renderTrigger: true,
              default: true,
            },
          },
        ],
        [fontSize('marker_font_size', t('Font size'))],
        [fontColor('marker_font_color', t('Font color'), WHITE)],
        [
          {
            name: 'marker_height',
            config: {
              type: 'TextControl',
              label: t('Markers height'),
              isInt: true,
              renderTrigger: true,
              default: 24,
            },
          },
        ],
        [hAlign('marker_label_align', t('Marker label horizontal alignment'), 'center')],
      ],
    },
    {
      label: t('Description inside markers'),
      expanded: false,
      controlSetRows: [
        [fontSize('marker_description_font_size', t('Font size'))],
        [fontColor('marker_description_font_color', t('Font color'), WHITE)],
        [hAlign('marker_description_label_align', t('Horizontal alignment'), 'center')],
      ],
    },
    {
      label: t('Side marker details'),
      expanded: false,
      controlSetRows: [
        [fontSize('marker_detail_font_size', t('Font size'))],
        [fontColor('marker_detail_font_color', t('Font color'), BLACK)],
      ],
    },
    {
      label: t('Hints'),
      expanded: false,
      controlSetRows: [
        [
          {
            name: 'show_hint',
            config: {
              type: 'CheckboxControl',
              label: t('Show hint'),
              renderTrigger: true,
              default: true,
              description: t('Show a tooltip for table rows and chart markers'),
            },
          },
        ],
        [
          {
            name: 'hint_wrap_text',
            config: {
              type: 'CheckboxControl',
              label: t('Wrap the text'),
              renderTrigger: true,
              default: true,
            },
          },
        ],
        [fontSize('hint_font_size', t('Font size'))],
        [
          {
            name: 'hint_trigger',
            config: {
              type: 'SelectControl',
              label: t('Hint trigger'),
              renderTrigger: true,
              default: 'hover',
              multi: false,
              choices: [
                ['hover', t('Hover')],
                ['click', t('Click')],
              ],
            },
          },
        ],
      ],
    },
    {
      label: t('Current date line'),
      expanded: false,
      controlSetRows: [
        [
          {
            name: 'show_day_line',
            config: {
              type: 'CheckboxControl',
              label: t('Show current date line'),
              renderTrigger: true,
              default: true,
              description: t(
                'Show a vertical line on today if the calendar contains the current date',
              ),
            },
          },
        ],
      ],
    },
    {
      label: t('Table legend settings'),
      expanded: false,
      controlSetRows: [
        [
          {
            name: 'show_legend',
            config: {
              type: 'CheckboxControl',
              label: t('Show legend'),
              renderTrigger: true,
              default: true,
            },
          },
        ],
        [
          {
            name: 'legend_name',
            config: {
              type: 'TextControl',
              label: t('Legend description'),
              renderTrigger: true,
              default: '',
            },
          },
        ],
        [fontSize('legend_font_size', t('Legend font size'))],
      ],
    },
    {
      label: t('Timeline settings'),
      expanded: false,
      controlSetRows: [
        [
          {
            name: 'timeline_format',
            config: {
              type: 'SelectControl',
              label: t('Timeline display format'),
              renderTrigger: true,
              multi: true,
              default: ['P1Y'],
              choices: [
                ['P1M', t('Months')],
                ['P1Y', t('Years')],
                ['P3M', t('Quarters')],
                ['P1W', t('Weeks')],
                ['P1D', t('Days')],
              ],
              description: t(
                'Header rows of the calendar. Rows too narrow for the current zoom are hidden automatically.',
              ),
            },
          },
        ],
        [fontSize('timeline_font_size', t('Timeline font size'), 10)],
        [
          {
            name: 'slider_values',
            config: {
              type: 'TextControl',
              label: t('Slider value start'),
              renderTrigger: true,
              dontRefreshOnChange: true,
              visibility: () => false,
            },
          },
        ],
      ],
    },
  ],
};

export default config;
