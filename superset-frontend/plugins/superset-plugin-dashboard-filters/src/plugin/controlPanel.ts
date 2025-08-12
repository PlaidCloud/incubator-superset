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
import {
  ControlPanelConfig,
  sharedControls,
} from '@superset-ui/chart-controls';

const config: ControlPanelConfig = {
  /**
   * The control panel is split into two tabs: "Query" and
   * "Chart Options". The controls that define the inputs to
   * the chart data request, such as columns and metrics, usually
   * reside within "Query", while controls that affect the visual
   * appearance or functionality of the chart are under the
   * "Chart Options" section.
   *
   * There are several predefined controls that can be used.
   * Some examples:
   * - groupby: columns to group by (translated to GROUP BY statement)
   * - series: same as groupby, but single selection.
   * - metrics: multiple metrics (translated to aggregate expression)
   * - metric: sane as metrics, but single selection
   * - adhoc_filters: filters (translated to WHERE or HAVING
   *   depending on filter type)
   * - row_limit: maximum number of rows (translated to LIMIT statement)
   *
   * If a control panel has both a `series` and `groupby` control, and
   * the user has chosen `col1` as the value for the `series` control,
   * and `col2` and `col3` as values for the `groupby` control,
   * the resulting query will contain three `groupby` columns. This is because
   * we considered `series` control a `groupby` query field and its value
   * will automatically append the `groupby` field when the query is generated.
   *
   * It is also possible to define custom controls by importing the
   * necessary dependencies and overriding the default parameters, which
   * can then be placed in the `controlSetRows` section
   * of the `Query` section instead of a predefined control.
   *
   * import { validateNonEmpty } from '@superset-ui/core';
   * import {
   *   sharedControls,
   *   ControlConfig,
   *   ControlPanelConfig,
   * } from '@superset-ui/chart-controls';
   *
   * const myControl: ControlConfig<'SelectControl'> = {
   *   name: 'secondary_entity',
   *   config: {
   *     ...sharedControls.entity,
   *     type: 'SelectControl',
   *     label: t('Secondary Entity'),
   *     mapStateToProps: state => ({
   *       sharedControls.columnChoices(state.datasource)
   *       .columns.filter(c => c.groupby)
   *     })
   *     validators: [validateNonEmpty],
   *   },
   * }
   *
   * In addition to the basic drop down control, there are several predefined
   * control types (can be set via the `type` property) that can be used. Some
   * commonly used examples:
   * - SelectControl: Dropdown to select single or multiple values,
       usually columns
   * - MetricsControl: Dropdown to select metrics, triggering a modal
       to define Metric details
   * - AdhocFilterControl: Control to choose filters
   * - CheckboxControl: A checkbox for choosing true/false values
   * - SliderControl: A slider with min/max values
   * - TextControl: Control for text data
   *
   * For more control input types, check out the `incubator-superset` repo
   * and open this file: superset-frontend/src/explore/components/controls/index.js
   *
   * To ensure all controls have been filled out correctly, the following
   * validators are provided
   * by the `@superset-ui/core/lib/validator`:
   * - validateNonEmpty: must have at least one value
   * - validateInteger: must be an integer value
   * - validateNumber: must be an integer or decimal value
   */

  // For control input types, see: superset-frontend/src/explore/components/controls/index.js
  controlPanelSections: [
    {
      label: t('Query'),
      expanded: true,
      controlSetRows: [
        [
          {
            name: 'col',
            config: {
              ...sharedControls.groupby,
              label: t('Column'),
              description: t('Column to fetch distinct values from'),
              multi: false,
            },
          },
        ],
        [
          {
            name: 'allow_multiple',
            config: {
              type: 'CheckboxControl',
              label: t('Allow multiple values'),
              default: false,
            },
          },
        ],
        [
          {
            name: 'has_default_value',
            config: {
              type: 'CheckboxControl',
              label: t('Has default value'),
              default: false,
            },
          },
        ],
        [
          {
            name: 'default_value',
            config: {
              type: 'SelectAsyncControl',
              label: t('Default value'),
              description: t('Default value for the filter'),
              mutator: (data: any) => {
                const { result } = data;
                if (!result) {
                  return [];
                }
                const options = result[0].data;
                const key = Object.keys(options[0])[0];
                return options.map((o: any) => ({
                  value: o[key],
                  label: o[key],
                }));
              },
              multi: false,
              freeForm: true,
              method: 'POST',
              dataEndpoint: '/api/v1/chart/data',
              visibility: ({ controls }: { controls: any }) =>
                Boolean(controls?.has_default_value?.value),
              postPayload: {"datasource":{"id":26,"type":"table"},"force":false,"queries":[{"filters":[],"extras":{"having":"","where":""},"applied_time_extras":{},"columns":["channel_1"],"metrics":[],"orderby":[["channel_1",true]],"annotation_layers":[],"row_limit":1000,"series_limit":0,"order_desc":true,"url_params":{"native_filters_key":"oB-BqY_0C-Q"},"custom_params":{},"custom_form_data":{}}],"form_data":{"enableEmptyFilter":false,"defaultToFirstItem":false,"multiSelect":true,"searchAllOptions":false,"inverseSelection":false,"datasource":"26__table","groupby":["channel_1"],"adhoc_filters":[],"extra_filters":[],"extra_form_data":{},"metrics":["count"],"row_limit":1000,"showSearch":true,"defaultValue":["cypress-tests"],"url_params":{"native_filters_key":"oB-BqY_0C-Q"},"inView":true,"viz_type":"filter_select","type":"NATIVE_FILTER","dashboardId":6,"force":false,"result_format":"json","result_type":"full"},"result_format":"json","result_type":"full"}
            },
          },
        ],
      ],
    },
  ],
};

export default config;
