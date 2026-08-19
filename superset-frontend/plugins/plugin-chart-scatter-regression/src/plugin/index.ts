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
import { ChartMetadata, ChartPlugin } from '@superset-ui/core';
import { t } from '@apache-superset/core/translation';
import buildQuery from './buildQuery';
import controlPanel from './controlPanel';
import transformProps from './transformProps';
import thumbnail from '../images/thumbnail.png';
import {
  ScatterRegressionChartProps,
  ScatterRegressionFormData,
} from '../types';

export default class PluginChartScatterRegression extends ChartPlugin<
  ScatterRegressionFormData,
  ScatterRegressionChartProps
> {
  constructor() {
    const metadata = new ChartMetadata({
      category: t('Correlation'),
      name: t('Scatter Regression'),
      description: t(
        'Scatter plot with a fitted regression trend line ' +
          '(linear, exponential, logarithmic, power, or polynomial) and R². ' +
          'Regression is computed client-side in pure TypeScript (no extra dependency).',
      ),
      tags: [t('Scatter'), t('Trend'), t('Correlation'), t('ECharts')],
      thumbnail,
    });

    super({
      buildQuery,
      controlPanel,
      loadChart: () => import('../PluginChartScatterRegression'),
      metadata,
      transformProps,
    });
  }
}
