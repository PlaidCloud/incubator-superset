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
import { t } from '@superset-ui/core';
import { ControlPanelConfig, sharedControls } from '@superset-ui/chart-controls';

const config: ControlPanelConfig = {
  controlPanelSections: [
    {
      label: t('Query'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'task_column',
            config: {
              ...sharedControls.entity,
              label: t('Task Name'),
              description: t('Column containing task names'),
            },
          },
        ],
        [
          {
            name: 'category_column',
            config: {
              ...sharedControls.entity,
              label: t('Category'),
              description: t('Column for grouping tasks (y-axis categories)'),
            },
          },
        ],
        [
          {
            name: 'parent_column',
            config: {
              ...sharedControls.entity,
              label: t('Parent Task'),
              description: t('Column containing parent task ID for nested hierarchy (optional)'),
            },
          },
        ],
        [
          {
            name: 'start_time_column',
            config: {
              ...sharedControls.entity,
              label: t('Start Time'),
              description: t('Column containing task start times'),
            },
          },
        ],
        [
          {
            name: 'end_time_column',
            config: {
              ...sharedControls.entity,
              label: t('End Time'),
              description: t('Column containing task end times'),
            },
          },
        ],
        ['adhoc_filters'],
        [
          {
            name: 'row_limit',
            config: sharedControls.row_limit,
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
            name: 'title',
            config: {
              type: 'TextControl',
              default: 'Gantt Chart',
              renderTrigger: true,
              label: t('Chart Title'),
              description: t('Title displayed at the top of the chart'),
            },
          },
        ],
        [
          {
            name: 'bar_height_ratio',
            config: {
              type: 'SliderControl',
              label: t('Bar Height Ratio'),
              renderTrigger: true,
              min: 0.2,
              max: 1,
              step: 0.1,
              default: 0.6,
              description: t('Ratio of bar height to row height'),
            },
          },
        ],
        [
          {
            name: 'zoomable',
            config: {
              type: 'CheckboxControl',
              label: t('Enable Zoom'),
              renderTrigger: true,
              default: true,
              description: t('Enable zoom and pan controls'),
            },
          },
        ],
        ['color_scheme'],
      ],
    },
    {
      label: t('Grouping & Nesting'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'default_expand_level',
            config: {
              type: 'SelectControl',
              label: t('Default Expand Level'),
              renderTrigger: true,
              default: 2,
              choices: [
                [-1, t('All Collapsed')],
                [0, t('Root Level Only')],
                [1, t('Level 1')],
                [2, t('Level 2')],
                [3, t('Level 3')],
                [10, t('All Expanded')],
              ],
              description: t(
                'Default nesting level to expand on initial load. ' +
                  'Tasks at or below this level will be expanded.',
              ),
            },
          },
        ],
        [
          {
            name: 'show_group_summary',
            config: {
              type: 'CheckboxControl',
              label: t('Show Group Summary Bars'),
              renderTrigger: true,
              default: true,
              description: t(
                'Display summary bars for groups showing the span from earliest start to latest end of children',
              ),
            },
          },
        ],
        [
          {
            name: 'indent_size',
            config: {
              type: 'SliderControl',
              label: t('Indent Size'),
              renderTrigger: true,
              min: 5,
              max: 30,
              step: 5,
              default: 15,
              description: t('Indentation size in pixels for each nesting level'),
            },
          },
        ],
      ],
    },
  ],
};

export default config;
