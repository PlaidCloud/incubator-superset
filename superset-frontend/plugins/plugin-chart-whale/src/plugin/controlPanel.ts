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
  getStandardizedControls,
  dndGroupByControl,
  sharedControls,
  D3_FORMAT_DOCS,
  D3_FORMAT_OPTIONS,
} from '@superset-ui/chart-controls';
import { WhaleChartType } from '../types';

const config: ControlPanelConfig = {
  /**
   * The control panel is split into sections.
   * Each section has a name and can have multiple controls.
   */
  controlPanelSections: [
    {
      label: t('Query'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'columns',
            config: {
              ...dndGroupByControl,
              label: t('X-Axis'),
              multi: false,
              description: t('Column to use for the X-axis'),
              validators: [validateNonEmpty],
            },
          },
        ],
        ['metrics'],
        [
          {
            name: 'tooltipOnlyMetrics',
            config: {
              ...sharedControls.metrics,
              label: t('Tooltip-only Metrics'),
              description: t('Metrics that will appear in the tooltip but not be plotted on the chart'),
              validators: [],
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
            name: 'chartType',
            config: {
              type: 'SelectControl',
              label: t('Chart Type'),
              description: t('Choose between a whale chart or bar chart'),
              default: WhaleChartType.Whale,
              choices: [
                [WhaleChartType.Whale, t('Whale Chart')],
                [WhaleChartType.Bar, t('Ranked Bar Chart')],
              ],
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'zoomable',
            config: {
              type: 'CheckboxControl',
              label: t('Data Zoom'),
              default: false,
              renderTrigger: true,
              description: t('Enable data zooming controls'),
            },
          },
        ],
        [
          {
            name: 'showPareto',
            config: {
              type: 'CheckboxControl',
              label: t('Show 80/20 Pareto Line'),
              default: false,
              description: t('Show the classic 80/20 Pareto reference line'),
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'showValueOnHover',
            config: {
              type: 'CheckboxControl',
              label: t('Show Values on Hover'),
              default: true,
              description: t('Show detailed values when hovering over points'),
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
        ['color_scheme'],
        [
          {
            name: 'useManualColors',
            config: {
              type: 'CheckboxControl',
              label: t('Set Custom Colors'),
              default: true,
              renderTrigger: true,
              description: t('Use custom colors instead of superset theme colors'),
            },
          },
        ],
        [
          {
            name: 'positive_color',
            config: {
              label: t('Positive'),
              type: 'ColorPickerControl',
              default: { r: 90, g: 193, b: 137, a: 1 },
              renderTrigger: true,
              description: t('Color for positive values'),
              visibility: ({ controls }) => Boolean(controls?.useManualColors?.value),
            },
          },
          {
            name: 'neutral_color',
            config: {
              label: t('Neutral'),
              type: 'ColorPickerControl',
              default: { r: 102, g: 102, b: 102, a: 1 },
              renderTrigger: true,
              description: t('Color for zero values'),
              visibility: ({ controls }) => Boolean(controls?.useManualColors?.value),
            },
          },
          {
            name: 'negative_color',
            config: {
              label: t('Negative'),
              type: 'ColorPickerControl',
              default: { r: 224, g: 67, b: 85, a: 1 },
              renderTrigger: true,
              description: t('Color for negative values'),
              visibility: ({ controls }) => Boolean(controls?.useManualColors?.value),
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
              label: t('Number Format'),
              renderTrigger: true,
              default: 'SMART_NUMBER',
              choices: D3_FORMAT_OPTIONS,
              description: `${D3_FORMAT_DOCS}`,
            },
          },
        ],
      ],
    },
  ],
  formDataOverrides: formData => ({
    ...formData,
    metrics: getStandardizedControls().popAllMetrics(),
  }),
};

export default config;
