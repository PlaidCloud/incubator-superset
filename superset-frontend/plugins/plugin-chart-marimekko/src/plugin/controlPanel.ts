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
import { t, validateNonEmpty } from '@superset-ui/core';
import {
  ControlPanelConfig,
  sharedControls,
  D3_FORMAT_OPTIONS,
  // D3_FORMAT_DOCS,
} from '@superset-ui/chart-controls';

const config: ControlPanelConfig = {
  /**
   * The control panel is split into two tabs: "Query" and
   * "Chart Options". The controls that define the inputs to
   * the chart data request, such as columns and metrics, usually
   * reside within "Query", while controls that affect the visual
   * appearance or functionality of the chart are under the
   * "Chart Options" section.
   *
   * There are several predefined controls that can be used.
   * Some examples:
   * - groupby: columns to group by (translated to GROUP BY statement)
   * - series: same as groupby, but single selection.
   * - metrics: multiple metrics (translated to aggregate expression)
   * - metric: sane as metrics, but single selection
   * - adhoc_filters: filters (translated to WHERE or HAVING
   *   depending on filter type)
   * - row_limit: maximum number of rows (translated to LIMIT statement)
   *
   * If a control panel has both a `series` and `groupby` control, and
   * the user has chosen `col1` as the value for the `series` control,
   * and `col2` and `col3` as values for the `groupby` control,
   * the resulting query will contain three `groupby` columns. This is because
   * we considered `series` control a `groupby` query field and its value
   * will automatically append the `groupby` field when the query is generated.
   *
   * It is also possible to define custom controls by importing the
   * necessary dependencies and overriding the default parameters, which
   * can then be placed in the `controlSetRows` section
   * of the `Query` section instead of a predefined control.
   *
   * import { validateNonEmpty } from '@superset-ui/core';
   * import {
   *   sharedControls,
   *   ControlConfig,
   *   ControlPanelConfig,
   * } from '@superset-ui/chart-controls';
   *
   * const myControl: ControlConfig<'SelectControl'> = {
   *   name: 'secondary_entity',
   *   config: {
   *     ...sharedControls.entity,
   *     type: 'SelectControl',
   *     label: t('Secondary Entity'),
   *     mapStateToProps: state => ({
   *       sharedControls.columnChoices(state.datasource)
   *       .columns.filter(c => c.groupby)
   *     })
   *     validators: [validateNonEmpty],
   *   },
   * }
   *
   * In addition to the basic drop down control, there are several predefined
   * control types (can be set via the `type` property) that can be used. Some
   * commonly used examples:
   * - SelectControl: Dropdown to select single or multiple values,
       usually columns
   * - MetricsControl: Dropdown to select metrics, triggering a modal
       to define Metric details
   * - AdhocFilterControl: Control to choose filters
   * - CheckboxControl: A checkbox for choosing true/false values
   * - SliderControl: A slider with min/max values
   * - TextControl: Control for text data
   *
   * For more control input types, check out the `incubator-superset` repo
   * and open this file: superset-frontend/src/explore/components/controls/index.js
   *
   * To ensure all controls have been filled out correctly, the following
   * validators are provided
   * by the `@superset-ui/core/lib/validator`:
   * - validateNonEmpty: must have at least one value
   * - validateInteger: must be an integer value
   * - validateNumber: must be an integer or decimal value
   */

  // For control input types, see: superset-frontend/src/explore/components/controls/index.js
  controlPanelSections: [
    {
      label: t('Query'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'cols',
            config: {
              ...sharedControls.groupby,
              label: t('Columns'),
              description: t('Columns to group by'),
            },
          },
        ],
        [
          {
            name: 'metrics',
            config: {
              ...sharedControls.metrics,
              // it's possible to add validators to controls if
              // certain selections/types need to be enforced
              validators: [validateNonEmpty],
            },
          },
        ],
        ['adhoc_filters'],
        [
          {
            name: 'row_limit',
            config: sharedControls.row_limit,
          },
        ],
      ],
    },
    {
      label: t('Chart Options'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'title',
            config: {
              type: 'TextControl',
              default: '',
              renderTrigger: true,
              label: t('Chart Title'),
              description: t('The title for the chart'),
            },
          },
        ],
        [
          {
            name: 'show_legend',
            config: {
              type: 'CheckboxControl',
              label: t('Show Legend'),
              default: true,
              renderTrigger: true,
              description: t('Whether to display the legend'),
            },
          },
        ],
        [
          {
            name: 'show_labels',
            config: {
              type: 'CheckboxControl',
              label: t('Show Labels'),
              default: true,
              renderTrigger: true,
              description: t('Show value labels inside the bars'),
            },
          },
        ],
        [
          {
            name: 'label_color',
            config: {
              type: 'ColorPickerControl',
              label: t('Label Color'),
              description: t('Color of the labels inside bars'),
              default: { r: 246, g: 246, b: 246, a: 1 },
              renderTrigger: true,
              visibility: ({ controls }) => !!controls?.show_labels?.value,
            },
          },
        ],
        [
          {
            name: 'x_axis_label',
            config: {
              type: 'TextControl',
              default: '',
              renderTrigger: true,
              label: t('X Axis Label'),
              description: t('Label for the X axis'),
            },
          },
        ],
        [
          {
            name: 'y_axis_label',
            config: {
              type: 'TextControl',
              default: '',
              renderTrigger: true,
              label: t('Y Axis Label'),
              description: t('Label for the Y axis'),
            },
          },
        ],
      ],
    },
    {
      label: t('Mekko Controls'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'height_key',
            config: {
              type: 'SelectControl',
              default: null,
              renderTrigger: true,
              label: t('Height Key (Y Axis)'),
              description: t('Column to determine the height of the bar'),
              validators: [validateNonEmpty],
              mapStateToProps: ({ datasource }) => ({
                choices:
                  datasource?.columns?.map(c => [
                    c.column_name,
                    c.column_name,
                  ]) || [],
                operators: datasource?.columns || [],
              }),
            },
          },
        ],
        [
          {
            name: 'width_key',
            config: {
              type: 'SelectControl',
              default: null,
              renderTrigger: true,
              label: t('Width Key (X Axis)'),
              description: t('Column to determine the width of the column'),
              validators: [validateNonEmpty],
              mapStateToProps: ({ datasource }) => ({
                choices:
                  datasource?.columns?.map(c => [
                    c.column_name,
                    c.column_name,
                  ]) || [],
                operators: datasource?.columns || [],
              }),
            },
          },
        ],
        [
          {
            name: 'sort_by_column',
            config: {
              type: 'SelectControl',
              label: t('Sort By'),
              default: null,
              description: t('Column to sort the data by'),
              renderTrigger: true,
              clearable: true,
              mapStateToProps: ({ datasource }) => ({
                choices:
                  datasource?.columns?.map(c => [
                    c.column_name,
                    c.column_name,
                  ]) || [],
                operators: datasource?.columns || [],
              }),
            },
          },
        ],
        [
          {
            name: 'sort_order',
            config: {
              type: 'SelectControl',
              label: t('Sort Order'),
              default: 'DESC',
              choices: [
                ['ASC', t('Ascending')],
                ['DESC', t('Descending')],
              ],
              renderTrigger: true,
              description: t('Sort direction'),
              visibility: ({ controls }) => !!controls?.sort_by_column?.value,
            },
          },
        ],
        [
          {
            name: 'show_percentage',
            config: {
              type: 'CheckboxControl',
              label: t('Show Percentage'),
              default: false,
              renderTrigger: true,
              description: t(
                'Show values as percentages instead of absolute numbers',
              ),
            },
          },
        ],
      ],
    },
    {
      label: t('Tooltip'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'tooltip_number_format',
            config: {
              type: 'SelectControl',
              freeForm: true,
              label: t('Tooltip Number Format'),
              renderTrigger: true,
              default: 'SMART_NUMBER',
              choices: D3_FORMAT_OPTIONS,
              description: t('Format for tooltip values'),
            },
          },
        ],
        [
          {
            name: 'tooltip_include_column',
            config: {
              type: 'CheckboxControl',
              label: t('Include Column Names'),
              default: true,
              renderTrigger: true,
              description: t('Include column names in tooltip'),
            },
          },
        ],
        [
          {
            name: 'tooltip_show_percentage',
            config: {
              type: 'CheckboxControl',
              label: t('Show Percentages in Tooltip'),
              default: true,
              renderTrigger: true,
              description: t('Include percentage values in tooltip'),
            },
          },
        ],
      ],
    },
  ],
};

export default config;
