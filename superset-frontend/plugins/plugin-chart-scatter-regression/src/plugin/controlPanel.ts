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
            name: 'entity',
            config: {
              ...sharedControls.entity,
              label: t('Point / Entity'),
              description: t('Column identifying each plotted point'),
              validators: [],
            },
          },
        ],
        [
          {
            name: 'series',
            config: {
              ...sharedControls.series,
              label: t('Series (color)'),
              description: t('Optional: split points into colored series'),
              validators: [],
            },
          },
        ],
        [
          {
            name: 'x',
            config: { ...sharedControls.x, label: t('X metric') },
          },
        ],
        [
          {
            name: 'y',
            config: { ...sharedControls.y, label: t('Y metric') },
          },
        ],
        ['adhoc_filters'],
        ['row_limit'],
      ],
    },
    {
      label: t('Regression'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'showRegression',
            config: {
              type: 'CheckboxControl',
              label: t('Show regression line'),
              default: true,
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'regressionType',
            config: {
              type: 'SelectControl',
              label: t('Regression type'),
              default: 'linear',
              renderTrigger: true,
              choices: [
                ['linear', t('Linear')],
                ['exponential', t('Exponential')],
                ['logarithmic', t('Logarithmic')],
                ['power', t('Power')],
                ['polynomial', t('Polynomial')],
              ],
            },
          },
        ],
        [
          {
            name: 'polynomialOrder',
            config: {
              type: 'SliderControl',
              label: t('Polynomial order'),
              default: 2,
              min: 2,
              max: 6,
              step: 1,
              renderTrigger: true,
              visibility: (props: ControlPanelsContainerProps) =>
                props.controls?.regressionType?.value === 'polynomial',
            },
          },
        ],
        [
          {
            name: 'showEquation',
            config: {
              type: 'CheckboxControl',
              label: t('Show equation & R²'),
              default: true,
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
            name: 'showZoom',
            config: {
              type: 'CheckboxControl',
              label: t('Enable zoom'),
              description: t(
                'Scroll/drag to zoom on both axes, plus a toolbox with ' +
                  'box-zoom, restore and save-as-image',
              ),
              default: true,
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'pointSize',
            config: {
              type: 'SliderControl',
              label: t('Point size'),
              default: 10,
              min: 2,
              max: 40,
              step: 1,
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'logXAxis',
            config: {
              type: 'CheckboxControl',
              label: t('Log scale (X)'),
              default: false,
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'logYAxis',
            config: {
              type: 'CheckboxControl',
              label: t('Log scale (Y)'),
              default: false,
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
            name: 'xAxisLabel',
            config: {
              type: 'TextControl',
              label: t('X axis label'),
              default: '',
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'yAxisLabel',
            config: {
              type: 'TextControl',
              label: t('Y axis label'),
              default: '',
              renderTrigger: true,
            },
          },
        ],
      ],
    },
  ],
  controlOverrides: {
    entity: { validators: [] },
  },
};

export default config;
