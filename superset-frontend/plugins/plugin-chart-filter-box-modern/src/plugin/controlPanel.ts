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
  dndGroupByControl,
} from '@superset-ui/chart-controls';

const config: ControlPanelConfig = {
  controlPanelSections: [
    {
      label: t('Filters configuration'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'filter_columns',
            config: {
              ...dndGroupByControl,
              label: t('Filter columns'),
              description: t('Columns to expose as filter dropdowns'),
              multi: true,
              validators: [],
            },
          },
        ],
        [
          {
            name: 'instant_filtering',
            config: {
              type: 'CheckboxControl',
              label: t('Instant filtering'),
              renderTrigger: true,
              default: false,
              description: t(
                'Apply filters as they change instead of showing an [Apply] button',
              ),
            },
          },
        ],
        ['row_limit'],
        ['adhoc_filters'],
      ],
    },
  ],
  controlOverrides: {
    adhoc_filters: {
      label: t('Limit selector values'),
      description: t('These filters apply to the values available in the dropdowns'),
    },
  },
};

export default config;
