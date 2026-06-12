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
              default: { r: 102, g: 102, b: 102, a: 1 },
              renderTrigger: true,
              description: t('Color for total bars'),
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
