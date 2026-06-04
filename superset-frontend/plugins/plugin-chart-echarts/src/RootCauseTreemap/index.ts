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
import { Behavior } from '@superset-ui/core';
import thumbnail from '../Treemap/images/thumbnail.png';
import { EchartsChartPlugin } from '../types';
import buildQuery from './buildQuery';
import controlPanel from './controlPanel';
import transformProps from './transformProps';
import { RootCauseTreemapChartProps, RootCauseTreemapFormData } from './types';

export default class EchartsRootCauseTreemapChartPlugin extends EchartsChartPlugin<
  RootCauseTreemapFormData,
  RootCauseTreemapChartProps
> {
  constructor() {
    super({
      buildQuery,
      controlPanel,
      loadChart: () => import('./EchartsRootCauseTreemap'),
      metadata: {
        behaviors: [
          Behavior.InteractiveChart,
          Behavior.DrillToDetail,
          Behavior.DrillBy,
        ],
        category: t('Part of a Whole'),
        credits: ['https://echarts.apache.org'],
        description: t(
          'Analyze hierarchical root causes by sizing tiles by contribution and coloring them by a performance metric.',
        ),
        name: t('Root Cause Treemap'),
        tags: [
          t('Business'),
          t('Comparison'),
          t('ECharts'),
          t('Multi-Levels'),
          t('Proportional'),
          t('Root Cause'),
        ],
        thumbnail,
      },
      transformProps,
    });
  }
}
