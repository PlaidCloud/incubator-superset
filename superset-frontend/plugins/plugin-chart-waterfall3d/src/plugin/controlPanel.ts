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
import { validateNonEmpty } from '@superset-ui/core';
import {
  ControlPanelConfig,
  dndGroupByControl,
  sharedControls,
  D3_FORMAT_DOCS,
  D3_FORMAT_OPTIONS,
} from '@superset-ui/chart-controls';

const config: ControlPanelConfig = {
  controlPanelSections: [
    {
      label: t('Query'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'stepColumn',
            config: {
              ...dndGroupByControl,
              label: t('Steps (X / bridge)'),
              multi: false,
              description: t(
                'Dimension whose ordered values form the bridge steps ' +
                  '(e.g. cost/activity leaves, or margin stages).',
              ),
              validators: [validateNonEmpty],
            },
          },
        ],
        [
          {
            name: 'seriesColumn',
            config: {
              ...dndGroupByControl,
              label: t('Series (depth / 3rd dimension)'),
              multi: false,
              description: t(
                'Dimension placed on the depth axis — one waterfall per value.',
              ),
              validators: [validateNonEmpty],
            },
          },
        ],
        [
          {
            name: 'metric',
            config: {
              ...sharedControls.metric,
              label: t('Metric'),
              description: t(
                'Metric whose signed values are bridged step by step',
              ),
              validators: [validateNonEmpty],
            },
          },
        ],
        [
          {
            name: 'seriesOrderByColumn',
            config: {
              type: 'SelectControl',
              label: t('Order Series By Column'),
              description: t(
                'Column used to order the bridge steps (it is added to the ' +
                  'group by). Falls back to the metric if unset.',
              ),
              mapStateToProps: state => ({
                choices: (state.datasource?.columns || []).map(col => [
                  col.column_name,
                  col.column_name,
                ]),
                default: state.form_data?.stepColumn || '',
              }),
              clearable: true,
              renderTrigger: false,
            },
          },
        ],
        [
          {
            name: 'seriesOrderDirection',
            config: {
              type: 'SelectControl',
              label: t('Order Direction'),
              choices: [
                ['ASC', t('Ascending')],
                ['DESC', t('Descending')],
              ],
              default: 'ASC',
              clearable: false,
              renderTrigger: false,
              description: t(
                'Ordering direction for the steps, used with "Order Series By Column"',
              ),
              visibility: ({ controls }) =>
                Boolean(controls?.seriesOrderByColumn?.value),
            },
          },
        ],
        [
          {
            name: 'tooltip_column',
            config: {
              type: 'SelectControl',
              label: t('Tooltip Column'),
              description: t(
                'Extra column surfaced in the hover tooltip (should be ' +
                  'functionally dependent on the step/series).',
              ),
              mapStateToProps: state => ({
                choices: (state.datasource?.columns || []).map(col => [
                  col.column_name,
                  col.column_name,
                ]),
              }),
              clearable: true,
              resetOnHide: false,
            },
          },
        ],
        ['adhoc_filters'],
        ['row_limit'],
      ],
    },
    {
      label: t('Chart Options'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'showTotal',
            config: {
              type: 'CheckboxControl',
              label: t('Show Total'),
              default: true,
              renderTrigger: true,
              description: t('Add a total bar at the end of each waterfall'),
            },
          },
        ],
        [
          {
            name: 'totalLabel',
            config: {
              type: 'TextControl',
              label: t('Total Label'),
              renderTrigger: true,
              default: 'Total',
              description: t('Label for the total step'),
              visibility: ({ controls }) => Boolean(controls?.showTotal?.value),
            },
          },
        ],
        [
          {
            name: 'useFirstValueAsSubtotal',
            config: {
              type: 'CheckboxControl',
              label: t('Use first value as subtotal'),
              default: false,
              renderTrigger: true,
              description: t(
                'Render the first bar of each waterfall as a subtotal',
              ),
            },
          },
        ],
        [
          {
            name: 'show_value',
            config: {
              type: 'CheckboxControl',
              label: t('Show Value'),
              default: false,
              renderTrigger: true,
              description: t('Show the metric value as a label on each bar'),
            },
          },
        ],
        [
          {
            name: 'bold_labels',
            config: {
              type: 'SelectControl',
              label: t('Bold Labels'),
              default: 'both',
              choices: [
                ['none', t('None')],
                ['total', t('Total Only')],
                ['subtotal', t('Subtotal Only')],
                ['both', t('Both Total and Subtotal')],
              ],
              renderTrigger: true,
              description: t('Which value labels to render in bold'),
              visibility: ({ controls }) =>
                Boolean(controls?.show_value?.value),
            },
          },
        ],
        [
          {
            name: 'show_legend',
            config: {
              type: 'CheckboxControl',
              label: t('Show legend'),
              default: false,
              renderTrigger: true,
              description: t(
                'Show a legend keying the increase/decrease/total colors',
              ),
            },
          },
        ],
        [
          {
            name: 'showConnectors',
            config: {
              type: 'CheckboxControl',
              label: t('Show Connectors'),
              default: true,
              renderTrigger: true,
              description: t(
                'Draw connector lines linking each step to the next',
              ),
            },
          },
        ],
        [
          {
            name: 'stickWidth',
            config: {
              type: 'SliderControl',
              label: t('Bar Width'),
              renderTrigger: true,
              default: 10,
              min: 2,
              max: 30,
              step: 1,
              description: t('Thickness of each floating bar'),
            },
          },
        ],
        [
          {
            name: 'autoRotate',
            config: {
              type: 'CheckboxControl',
              label: t('Auto Rotate'),
              default: false,
              renderTrigger: true,
              description: t('Continuously rotate the 3D scene'),
            },
          },
        ],
        [
          {
            name: 'valueFormat',
            config: {
              type: 'SelectControl',
              freeForm: true,
              label: t('Value Format'),
              renderTrigger: true,
              default: 'SMART_NUMBER',
              choices: D3_FORMAT_OPTIONS,
              description: D3_FORMAT_DOCS,
            },
          },
        ],
        ['currency_format'],
      ],
    },
    {
      label: t('Colors'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'increaseColor',
            config: {
              label: t('Increase'),
              type: 'ColorPickerControl',
              default: { r: 90, g: 193, b: 137, a: 1 },
              renderTrigger: true,
              description: t('Color for positive (increase) steps'),
            },
          },
          {
            name: 'decreaseColor',
            config: {
              label: t('Decrease'),
              type: 'ColorPickerControl',
              default: { r: 224, g: 67, b: 85, a: 1 },
              renderTrigger: true,
              description: t('Color for negative (decrease) steps'),
            },
          },
          {
            name: 'totalColor',
            config: {
              label: t('Total'),
              type: 'ColorPickerControl',
              default: { r: 59, g: 130, b: 246, a: 1 },
              renderTrigger: true,
              description: t('Color for total bars'),
            },
          },
          {
            name: 'subtotalColor',
            config: {
              label: t('Subtotal'),
              type: 'ColorPickerControl',
              default: { r: 139, g: 92, b: 246, a: 1 },
              renderTrigger: true,
              description: t(
                'Color for subtotal bars (first value as subtotal)',
              ),
            },
          },
        ],
        [
          {
            name: 'labelColor',
            config: {
              label: t('Label text'),
              type: 'ColorPickerControl',
              default: { r: 20, g: 40, b: 100, a: 1 },
              renderTrigger: true,
              description: t(
                'Text color for the step, series and axis labels. ' +
                  'Value labels follow their bar (increase/decrease) color.',
              ),
            },
          },
        ],
      ],
    },
    {
      label: t('Axis Labels'),
      expanded: false,
      controlSetRows: [
        [
          {
            name: 'xAxisLabel',
            config: {
              type: 'TextControl',
              label: t('X Axis Label'),
              renderTrigger: true,
              default: '',
              description: t('Custom label for the X (steps) axis'),
            },
          },
        ],
        [
          {
            name: 'xAxisNameGap',
            config: {
              type: 'TextControl',
              isInt: true,
              label: t('X Axis Title Margin'),
              renderTrigger: true,
              default: 25,
              description: t('Distance between the X axis title and the axis'),
            },
          },
        ],
        [
          {
            name: 'yAxisLabel',
            config: {
              type: 'TextControl',
              label: t('Y Axis Label'),
              renderTrigger: true,
              default: '',
              description: t('Custom label for the Y (series) axis'),
            },
          },
        ],
        [
          {
            name: 'yAxisNameGap',
            config: {
              type: 'TextControl',
              isInt: true,
              label: t('Y Axis Title Margin'),
              renderTrigger: true,
              default: 25,
              description: t('Distance between the Y axis title and the axis'),
            },
          },
        ],
        [
          {
            name: 'zAxisLabel',
            config: {
              type: 'TextControl',
              label: t('Z Axis Label'),
              renderTrigger: true,
              default: '',
              description: t('Custom label for the Z (value) axis'),
            },
          },
        ],
      ],
    },
  ],
};

export default config;
