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
              validators: []

            }
          }
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
                [WhaleChartType.Bar, t('Bar Chart')],
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
            name: 'autoDetectYAxisScale',
            config: {
              type: 'CheckboxControl',
              label: t('Auto Dual Axis'),
              default: true,
              description: t(
                'Automatically detect metrics with different scales and plot them on a secondary Y-axis',
              ),
              renderTrigger: true,
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
      label: t('Whale Chart Settings'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'headerText',
            config: {
              type: 'TextControl',
              default: '',
              renderTrigger: true,
              label: t('Header Text'),
              description: t('The text you want to see in the header'),
            },
          },
        ],
        [
          {
            name: 'headerFontSize',
            config: {
              type: 'SelectControl',
              label: t('Header Font Size'),
              default: 'xl',
              choices: [
                // [value, label]
                ['xxs', t('xx-small')],
                ['xs', t('x-small')],
                ['s', t('small')],
                ['m', t('medium')],
                ['l', t('large')],
                ['xl', t('x-large')],
                ['xxl', t('xx-large')],
              ],
              renderTrigger: true,
              description: t('The size of your header font'),
            },
          },
        ],
        [
          {
            name: 'boldText',
            config: {
              type: 'CheckboxControl',
              label: t('Bold Text'),
              default: false,
              renderTrigger: true,
              description: t('A checkbox to make the header bold'),
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
