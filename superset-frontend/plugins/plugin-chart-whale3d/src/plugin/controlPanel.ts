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
            name: 'entityColumn',
            config: {
              ...dndGroupByControl,
              label: t('Entity (X / ranked)'),
              multi: false,
              description: t(
                'Dimension ranked along the X axis, e.g. customer or product. ' +
                  'Entities are sorted by the metric and accumulated into the curve.',
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
                'Dimension placed on the depth axis — one whale curve per value.',
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
              description: t('Metric accumulated into the curve height'),
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
            name: 'displayMode',
            config: {
              type: 'SelectControl',
              label: t('Display Mode'),
              default: 'ribbons',
              renderTrigger: true,
              clearable: false,
              choices: [
                ['ribbons', t('Ribbons (one curve per category)')],
                ['surface', t('Surface (whale landscape)')],
              ],
              description: t(
                'Draw a separate 3D line per category, or a continuous surface ' +
                  'resampled onto a common percentile grid.',
              ),
            },
          },
        ],
        [
          {
            name: 'zMode',
            config: {
              type: 'SelectControl',
              label: t('Curve Value'),
              default: 'percent',
              renderTrigger: true,
              clearable: false,
              choices: [
                ['percent', t('Cumulative % (0–100)')],
                ['absolute', t('Cumulative absolute value')],
              ],
              description: t(
                'Whether the curve height is the cumulative percentage or the ' +
                  'cumulative absolute metric value.',
              ),
            },
          },
        ],
        [
          {
            name: 'fillCurves',
            config: {
              type: 'CheckboxControl',
              label: t('Fill Curves'),
              default: false,
              renderTrigger: true,
              description: t(
                'Fill the area under each curve down to the baseline ' +
                  '(ribbons mode only).',
              ),
              visibility: ({ controls }) =>
                (controls?.displayMode?.value ?? 'ribbons') === 'ribbons',
            },
          },
        ],
        [
          {
            name: 'fillOpacity',
            config: {
              type: 'SliderControl',
              label: t('Fill Opacity'),
              renderTrigger: true,
              default: 0.7,
              min: 0.1,
              max: 1,
              step: 0.05,
              description: t('Opacity of the filled area under each curve'),
              visibility: ({ controls }) =>
                (controls?.displayMode?.value ?? 'ribbons') === 'ribbons' &&
                Boolean(controls?.fillCurves?.value),
            },
          },
        ],
        [
          {
            name: 'showPareto',
            config: {
              type: 'CheckboxControl',
              label: t('Show 80/20 Pareto Reference'),
              default: false,
              renderTrigger: true,
              description: t(
                'Draw the classic 80/20 Pareto reference line at each category ' +
                  '(ribbons mode only).',
              ),
              visibility: ({ controls }) =>
                (controls?.displayMode?.value ?? 'ribbons') === 'ribbons',
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
            name: 'gridResolution',
            config: {
              type: 'TextControl',
              isInt: true,
              label: t('Surface Resolution'),
              renderTrigger: true,
              default: 20,
              description: t(
                'Number of percentile steps used to resample each curve for the ' +
                  'surface (higher = smoother).',
              ),
              visibility: ({ controls }) =>
                controls?.displayMode?.value === 'surface',
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
      ],
    },
    {
      label: t('Colors'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'colorMode',
            config: {
              type: 'SelectControl',
              label: t('Color By'),
              default: 'gradient',
              renderTrigger: true,
              clearable: false,
              choices: [
                ['gradient', t('Value (gradient by height)')],
                ['category', t('Category (color scheme)')],
              ],
              description: t(
                'Color by curve height (gradient) or by the series category ' +
                  '(color scheme). Surface mode always uses the gradient.',
              ),
            },
          },
        ],
        [
          {
            name: 'showVisualMap',
            config: {
              type: 'CheckboxControl',
              label: t('Show Color Legend'),
              default: true,
              renderTrigger: true,
              description: t('Show the visual map color legend (gradient mode)'),
            },
          },
        ],
        [
          {
            name: 'color_scheme',
            config: {
              ...sharedControls.color_scheme,
              renderTrigger: true,
              visibility: ({ controls }: { controls: any }) =>
                controls?.colorMode?.value === 'category',
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
              description: t('Custom label for the X (percentile) axis'),
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
              description: t('Custom label for the Z (cumulative) axis'),
            },
          },
        ],
      ],
    },
  ],
};

export default config;
