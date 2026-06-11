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
import { Whale3DFormData, Whale3DChartProps } from '../types';

export default class PluginChartWhale3D extends ChartPlugin<
  Whale3DFormData,
  Whale3DChartProps
> {
  constructor() {
    const metadata = new ChartMetadata({
      category: t('KPI'),
      description: t(
        '3D whale curve (echarts-gl). Plots the cumulative distribution of a ' +
          'metric across ranked entities, with a third dimension as depth — ' +
          'one whale curve per category, or a continuous "whale landscape" ' +
          'surface.',
      ),
      name: t('3D Whale Curve'),
      tags: [
        t('3D'),
        t('Business'),
        t('Distribution'),
        t('Pareto'),
        t('ECharts'),
      ],
      thumbnail,
    });

    super({
      buildQuery,
      controlPanel,
      loadChart: () => import('../Whale3DChart'),
      metadata,
      transformProps,
    });
  }
}
