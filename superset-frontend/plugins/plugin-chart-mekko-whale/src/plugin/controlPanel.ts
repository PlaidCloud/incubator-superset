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
} from '@superset-ui/chart-controls';

const config: ControlPanelConfig = {
  controlPanelSections: [
    {
      label: t('Query'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'groupby',
            config: {
              ...sharedControls.groupby,
              label: t('Dimension'),
              description: t('The dimension to group by (e.g., Company, Product)'),
              multi: false,
              validators: [validateNonEmpty],
            },
          },
        ],
        [
          {
            name: 'metric',
            config: {
              ...sharedControls.metric,
              label: t('Y-Axis'),
              description: t('The metric to accumulate on the Y-axis (e.g., Profit)'),
              validators: [validateNonEmpty],
            },
          },
        ],
        [
          {
            name: 'secondary_metric',
            config: {
              ...sharedControls.metric,
              label: t('X-Axis'),
              description: t('The metric to accumulate on the X-axis (e.g., Revenue)'),
              validators: [validateNonEmpty],
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
            name: 'sort_by',
            config: {
              type: 'SelectControl',
              label: t('Sort By'),
              default: 'profit_margin',
              choices: [
                ['profit', t('Profit (Metric 1)')],
                ['revenue', t('Revenue (Metric 2)')],
                ['profit_margin', t('Profit Margin (M1/M2)')],
              ],
              renderTrigger: true,
              description: t('Criteria for sorting items before accumulation'),
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
            },
          },
        ],
      ],
    },
    {
      label: t('Colors'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'use_default_colors',
            config: {
              type: 'CheckboxControl',
              label: t('Use Default Colors'),
              default: true,
              renderTrigger: true,
              description: t('Use the default green-to-red gradient colors'),
            },
          },
        ],
        [
          {
            name: 'color1',
            config: {
              label: t('Start Color (Positive Start)'),
              type: 'ColorPickerControl',
              default: { r: 0, g: 100, b: 0, a: 1 },
              renderTrigger: true,
              visibility: ({ controls }) => !controls?.use_default_colors?.value,
            },
          },
        ],
        [
          {
            name: 'color2',
            config: {
              label: t('Mid Color (Positive End)'),
              type: 'ColorPickerControl',
              default: { r: 144, g: 238, b: 144, a: 1 },
              renderTrigger: true,
              visibility: ({ controls }) => !controls?.use_default_colors?.value,
            },
          },
        ],
        [
          {
            name: 'color3',
            config: {
              label: t('Mid Color (Negative Start)'),
              type: 'ColorPickerControl',
              default: { r: 255, g: 182, b: 193, a: 1 },
              renderTrigger: true,
              visibility: ({ controls }) => !controls?.use_default_colors?.value,
            },
          },
        ],
        [
          {
            name: 'color4',
            config: {
              label: t('End Color (Negative End)'),
              type: 'ColorPickerControl',
              default: { r: 139, g: 0, b: 0, a: 1 },
              renderTrigger: true,
              visibility: ({ controls }) => !controls?.use_default_colors?.value,
            },
          },
        ],
      ],
    },
    {
      label: t('Axes'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'y_axis_format',
            config: {
              type: 'SelectControl',
              freeForm: true,
              label: t('Y Axis Format'),
              renderTrigger: true,
              default: 'SMART_NUMBER',
              choices: D3_FORMAT_OPTIONS,
            },
          },
        ],
        [
          {
            name: 'x_axis_format',
            config: {
              type: 'SelectControl',
              freeForm: true,
              label: t('X Axis Format'),
              renderTrigger: true,
              default: 'SMART_NUMBER',
              choices: D3_FORMAT_OPTIONS,
            },
          },
        ],
      ],
    },
  ],
};

export default config;
