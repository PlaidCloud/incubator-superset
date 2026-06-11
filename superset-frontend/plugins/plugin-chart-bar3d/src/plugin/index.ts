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
import { ChartMetadata, ChartPlugin } from '@superset-ui/core';
import buildQuery from './buildQuery';
import controlPanel from './controlPanel';
import transformProps from './transformProps';
import thumbnail from '../images/thumbnail.png';
import { Bar3DFormData, Bar3DChartProps } from '../types';

export default class PluginChartBar3D extends ChartPlugin<
  Bar3DFormData,
  Bar3DChartProps
> {
  constructor() {
    const metadata = new ChartMetadata({
      category: t('Distribution'),
      description: t(
        '3D bar chart (echarts-gl). Plots a metric as bar height across two ' +
          'categorical dimensions (X and Y), colored by value.',
      ),
      name: t('3D Bar Chart'),
      tags: [t('3D'), t('Bar'), t('Distribution'), t('Comparison'), t('ECharts')],
      thumbnail,
    });

    super({
      buildQuery,
      controlPanel,
      loadChart: () => import('../Bar3DChart'),
      metadata,
      transformProps,
    });
  }
}
