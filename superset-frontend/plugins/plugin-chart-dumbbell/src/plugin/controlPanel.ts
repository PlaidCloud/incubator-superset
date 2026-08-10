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

const SYMBOL_CHOICES: [string, string][] = [
  ['circle', t('Circle')],
  ['diamond', t('Diamond')],
  ['triangle', t('Triangle')],
  ['rect', t('Square')],
  ['roundRect', t('Rounded square')],
  ['pin', t('Pin')],
  ['arrow', t('Arrow')],
  ['none', t('None')],
];

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
              description: t(
                'Column plotted along the (vertical) category axis',
              ),
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
                'Two or more measures. The first is the origin, the last the ' +
                  'destination; a connector joins them per category (dumbbell).',
              ),
            },
          },
        ],
        ['adhoc_filters'],
        ['row_limit'],
      ],
    },
    {
      label: t('Markers & Connector'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'originSymbol',
            config: {
              type: 'SelectControl',
              freeForm: false,
              label: t('Origin icon'),
              description: t('Marker shape for the first metric (origin)'),
              default: 'circle',
              choices: SYMBOL_CHOICES,
              renderTrigger: true,
            },
          },
          {
            name: 'originColor',
            config: {
              type: 'TextControl',
              label: t('Origin color'),
              description: t(
                'Hex color for the origin marker (blank = scheme)',
              ),
              default: '',
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'destinationSymbol',
            config: {
              type: 'SelectControl',
              freeForm: false,
              label: t('Destination icon'),
              description: t('Marker shape for the last metric (destination)'),
              default: 'diamond',
              choices: SYMBOL_CHOICES,
              renderTrigger: true,
            },
          },
          {
            name: 'destinationColor',
            config: {
              type: 'TextControl',
              label: t('Destination color'),
              description: t(
                'Hex color for the destination marker (blank = scheme)',
              ),
              default: '',
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'symbolSize',
            config: {
              type: 'SliderControl',
              label: t('Icon size'),
              default: 14,
              min: 4,
              max: 40,
              step: 1,
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'lineWidth',
            config: {
              type: 'SliderControl',
              label: t('Connector width'),
              default: 4,
              min: 1,
              max: 20,
              step: 1,
              renderTrigger: true,
            },
          },
          {
            name: 'lineColor',
            config: {
              type: 'TextControl',
              label: t('Connector / arrow color'),
              description: t('Hex color for the connector line and its arrow'),
              // eslint-disable-next-line theme-colors/no-literal-colors
              default: '#bbbbbb',
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'lineArrow',
            config: {
              type: 'CheckboxControl',
              label: t('Arrow (origin → destination)'),
              description: t('Draw a directional arrowhead at the destination'),
              default: false,
              renderTrigger: true,
            },
          },
        ],
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
      expanded: false,
      controlSetRows: [
        ['color_scheme'],
        [
          {
            name: 'sortBy',
            config: {
              type: 'SelectControl',
              label: t('Sort categories by'),
              default: 'none',
              renderTrigger: true,
              choices: [
                ['none', t('Query order')],
                ['first', t('First metric')],
                ['gap', t('Gap (max − min)')],
              ],
              description: t('Order the categories along the axis'),
            },
          },
        ],
        [
          {
            name: 'showLabels',
            config: {
              type: 'CheckboxControl',
              label: t('Show value labels'),
              default: false,
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'chartMargin',
            config: {
              type: 'SliderControl',
              label: t('Chart margin'),
              description: t('Extra padding around the plot area (all sides)'),
              default: 0,
              min: 0,
              max: 120,
              step: 4,
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
            name: 'valueAxisLabel',
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
