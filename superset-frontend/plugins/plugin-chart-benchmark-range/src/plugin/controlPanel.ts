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
} from '@superset-ui/chart-controls';
import {
  BenchmarkRangeSortBy,
  BenchmarkRangeSortOrder,
  PercentValueMode,
} from '../types';

const metricControl = (name: string, label: string, description: string) => ({
  name,
  config: {
    ...sharedControls.metric,
    label: t(label),
    description: t(description),
    validators: [],
  },
});

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
              label: t('Profit Center'),
              description: t('Category column shown on the Y-axis'),
              multi: false,
              validators: [validateNonEmpty],
            },
          },
        ],
        [
          metricControl(
            'q1_metric',
            'IQR Lower',
            'Metric for the lower bound of the interquartile range',
          ),

        ],
        [metricControl(
          'q3_metric',
          'IQR Upper',
          'Metric for the upper bound of the interquartile range',
        ),],
        [
          metricControl(
            'median_metric',
            'Median',
            'Metric for the median marker',
          ),

        ],
        [
          metricControl(
            'target_metric',
            'Target',
            'Metric for the target marker',
          ),
        ],
        [
          metricControl(
            'actual_metric',
            'Actual',
            'Metric for the actual marker',
          ),
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
            name: 'percent_value_mode',
            config: {
              type: 'SelectControl',
              label: t('Percent Value Mode'),
              default: PercentValueMode.Auto,
              renderTrigger: true,
              choices: [
                [PercentValueMode.Auto, t('Auto')],
                [PercentValueMode.Percent, t('Values are percentages')],
                [PercentValueMode.Fraction, t('Values are fractions')],
              ],
              description: t(
                'Use Auto to treat values between -1 and 1 as fractions, otherwise as percentage points',
              ),
            },
          },
        ],
        [
          {
            name: 'sort_by',
            config: {
              type: 'SelectControl',
              label: t('Sort By'),
              default: BenchmarkRangeSortBy.Category,
              renderTrigger: true,
              choices: [
                [BenchmarkRangeSortBy.Category, t('Profit Center')],
                [BenchmarkRangeSortBy.Q1, t('IQR Lower')],
                [BenchmarkRangeSortBy.Q3, t('IQR Upper')],
                [BenchmarkRangeSortBy.Median, t('Median')],
                [BenchmarkRangeSortBy.Target, t('Target')],
                [BenchmarkRangeSortBy.Actual, t('Actual')],
              ],
            },
          },
          {
            name: 'sort_order',
            config: {
              type: 'SelectControl',
              label: t('Sort Order'),
              default: BenchmarkRangeSortOrder.Asc,
              renderTrigger: true,
              choices: [
                [BenchmarkRangeSortOrder.Asc, t('Ascending')],
                [BenchmarkRangeSortOrder.Desc, t('Descending')],
              ],
            },
          },
        ],
        [
          {
            name: 'show_filter_controls',
            config: {
              type: 'CheckboxControl',
              label: t('Show Filter Controls'),
              default: true,
              renderTrigger: true,
              description: t('Show in-chart dropdown filters'),
            },
          },
          {
            name: 'show_legend',
            config: {
              type: 'CheckboxControl',
              label: t('Show Legend'),
              default: true,
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'x_axis_label',
            config: {
              type: 'TextControl',
              label: t('X Axis Label'),
              default: t('% Value'),
              renderTrigger: true,
            },
          },
        ],
      ],
    },
  ],
};

export default config;
