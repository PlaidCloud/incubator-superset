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
            name: 'timeColumn',
            config: {
              ...sharedControls.entity,
              label: t('Timeline dimension'),
              description: t(
                'Column whose distinct values become the animation frames',
              ),
              validators: [],
            },
          },
        ],
        [
          {
            name: 'entity',
            config: {
              ...sharedControls.entity,
              label: t('Bubble / Entity'),
              description: t('Column identifying each bubble'),
              validators: [],
            },
          },
        ],
        [
          {
            name: 'series',
            config: {
              ...sharedControls.series,
              label: t('Category (color)'),
              description: t('Optional: color bubbles by category'),
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
        [
          {
            name: 'size',
            config: {
              ...sharedControls.size,
              label: t('Bubble size metric'),
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
        [
          {
            name: 'autoPlay',
            config: {
              type: 'CheckboxControl',
              label: t('Auto-play timeline'),
              default: true,
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'showPeriodLabel',
            config: {
              type: 'CheckboxControl',
              label: t('Show period watermark'),
              description: t(
                'Display the current period (e.g. year) as a large faded ' +
                  'label behind the bubbles',
              ),
              default: true,
              renderTrigger: true,
            },
          },
        ],
        [
          {
            name: 'maxBubbleSize',
            config: {
              type: 'SliderControl',
              label: t('Max bubble size'),
              default: 60,
              min: 10,
              max: 120,
              step: 5,
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
        ['color_scheme'],
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
    timeColumn: { validators: [] },
  },
};

export default config;
