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

const columnControl = (name: string, label: string) => ({
  name,
  config: {
    ...sharedControls.groupby,
    label: t(label),
    description: t(`Optional dataset column to use for the ${label} dropdown`),
    multi: false,
    visibility: ({ controls }: { controls?: Record<string, any> }) =>
      Boolean(controls?.show_filter_controls?.value),
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
        [metricControl('bar_left_pct', 'Bar Left Pct', 'Left position of the IQR bar')],
        [metricControl('bar_width_pct', 'Bar Width Pct', 'Width of the IQR bar')],
        [metricControl('median_pct', 'Median Pct', 'Position of the median marker')],
        [metricControl('target_pct', 'Target Pct', 'Position of the target marker')],
        [metricControl('actual_pct', 'Actual Pct', 'Position of the actual marker')],
        [metricControl('margin_low_f', 'Margin Low F', 'Formatted low margin for tooltip')],
        [metricControl('margin_high_f', 'Margin High F', 'Formatted high margin for tooltip')],
        [metricControl('margin_median_f', 'Margin Median F', 'Formatted median margin for tooltip')],
        [metricControl('margin_target_f', 'Margin Target F', 'Formatted target margin for tooltip')],
        [metricControl('margin_actual_f', 'Margin Actual F', 'Formatted actual margin for tooltip')],
        [metricControl('gap_metric', 'Gap', 'Formatted actual-vs-target gap for tooltip')],
        ['adhoc_filters'],
        ['row_limit'],
      ],
    },
    {
      label: t('Chart Filters'),
      expanded: false,
      controlSetRows: [
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
        ],
        [columnControl('period_filter', 'Period')],
        [columnControl('entity_type_filter', 'Entity Type')],
        [columnControl('region_filter', 'Region')],
        [columnControl('country_filter', 'Country')],
        [columnControl('entity_filter', 'Entity')],
        [columnControl('function_filter', 'Function')],
        [columnControl('profit_center_filter', 'Profit Center')],
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
