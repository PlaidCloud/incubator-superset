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
            name: 'x_axis',
            config: {
              ...dndGroupByControl,
              label: t('X Axis'),
              multi: false,
              description: t('Dimension for the X axis (columns of the grid)'),
              validators: [validateNonEmpty],
            },
          },
        ],
        [
          {
            name: 'y_axis',
            config: {
              ...dndGroupByControl,
              label: t('Y Axis'),
              multi: false,
              description: t('Dimension for the Y axis (depth of the grid)'),
              validators: [validateNonEmpty],
            },
          },
        ],
        [
          {
            name: 'metric',
            config: {
              ...sharedControls.metric,
              label: t('Metric (Z / Height)'),
              description: t('Metric that drives the height of each 3D bar'),
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
            name: 'showVisualMap',
            config: {
              type: 'CheckboxControl',
              label: t('Show Color Legend'),
              default: true,
              renderTrigger: true,
              description: t(
                'Show the visual map color legend (gradient by height)',
              ),
              visibility: ({ controls }) =>
                (controls?.colorMode?.value ?? 'gradient') === 'gradient',
            },
          },
        ],
        [
          {
            name: 'showLabel',
            config: {
              type: 'CheckboxControl',
              label: t('Show Values'),
              default: false,
              renderTrigger: true,
              description: t('Show the metric value on top of each bar'),
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
            name: 'yAxisFormat',
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
                'Color bars by their height value (gradient) or by a category color scheme',
              ),
            },
          },
        ],
        [
          {
            name: 'colorByAxis',
            config: {
              type: 'SelectControl',
              label: t('Color Categories By'),
              default: 'x',
              renderTrigger: true,
              clearable: false,
              choices: [
                ['x', t('X Axis')],
                ['y', t('Y Axis')],
              ],
              description: t('Which dimension determines each category color'),
              visibility: ({ controls }) =>
                controls?.colorMode?.value === 'category',
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
              description: t('Custom label for the X axis'),
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
              description: t('Custom label for the Y axis'),
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
              description: t('Custom label for the Z (height) axis'),
            },
          },
        ],
      ],
    },
  ],
};

export default config;
