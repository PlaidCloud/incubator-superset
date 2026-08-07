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
import {
  ControlPanelConfig,
  ControlPanelsContainerProps,
  sharedControls,
} from '@superset-ui/chart-controls';

const config: ControlPanelConfig = {
  controlPanelSections: [
    {
      label: t('Query'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'dimension',
            config: {
              ...sharedControls.entity,
              label: t('Category'),
              description: t('Column plotted along the (vertical) category axis'),
              validators: [],
            },
          },
        ],
        [
          {
            name: 'metrics',
            config: {
              ...sharedControls.metrics,
              description: t(
                'One or more signed measures — negative values point left. ' +
                  'Multiple metrics render as grouped diverging bars.',
              ),
            },
          },
        ],
        ['adhoc_filters'],
        ['row_limit'],
      ],
    },
    {
      label: t('Legend'),
      expanded: false,
      controlSetRows: [
        [
          {
            name: 'show_legend',
            config: {
              type: 'CheckboxControl',
              label: t('Show legend'),
              renderTrigger: true,
              default: true,
              description: t('Whether to display a legend for the chart'),
            },
          },
        ],
        [
          {
            name: 'legendType',
            config: {
              type: 'SelectControl',
              freeForm: false,
              label: t('Type'),
              choices: [
                ['scroll', t('Scroll')],
                ['plain', t('List')],
              ],
              default: 'scroll',
              renderTrigger: true,
              description: t('Legend type'),
              visibility: (props: ControlPanelsContainerProps) =>
                Boolean(props.controls?.show_legend?.value),
            },
          },
        ],
        [
          {
            name: 'legendOrientation',
            config: {
              type: 'SelectControl',
              freeForm: false,
              label: t('Orientation'),
              choices: [
                ['top', t('Top')],
                ['bottom', t('Bottom')],
                ['left', t('Left')],
                ['right', t('Right')],
              ],
              default: 'top',
              renderTrigger: true,
              description: t('Legend Orientation'),
              visibility: (props: ControlPanelsContainerProps) =>
                Boolean(props.controls?.show_legend?.value),
            },
          },
        ],
        [
          {
            name: 'legendMargin',
            config: {
              type: 'TextControl',
              label: t('Margin'),
              renderTrigger: true,
              isInt: true,
              default: null,
              description: t('Additional padding for legend.'),
              visibility: (props: ControlPanelsContainerProps) =>
                Boolean(props.controls?.show_legend?.value),
            },
          },
        ],
      ],
    },
    {
      label: t('Chart Options'),
      expanded: true,
      controlSetRows: [
        ['color_scheme'],
        [
          {
            name: 'showLabels',
            config: {
              type: 'CheckboxControl',
              label: t('Show value labels'),
              default: true,
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'positiveColor',
            config: {
              type: 'TextControl',
              label: t('Positive color (single metric)'),
              description: t(
                'Hex color for positive bars when a single metric is used',
              ),
              default: '#2e7d32',
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'negativeColor',
            config: {
              type: 'TextControl',
              label: t('Negative color (single metric)'),
              description: t(
                'Hex color for negative bars when a single metric is used',
              ),
              default: '#c0392b',
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'numberFormat',
            config: {
              ...sharedControls.y_axis_format,
              label: t('Number format'),
            },
          },
        ],
        [
          {
            name: 'barCategoryLabel',
            config: {
              type: 'TextControl',
              label: t('Value axis label'),
              default: '',
              renderTrigger: true,
            },
          },
        ],
      ],
    },
  ],
  controlOverrides: {
    dimension: { validators: [] },
  },
};

export default config;
