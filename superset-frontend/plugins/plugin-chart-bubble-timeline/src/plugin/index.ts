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
import { BubbleTimelineChartProps, BubbleTimelineFormData } from '../types';

export default class PluginChartBubbleTimeline extends ChartPlugin<
  BubbleTimelineFormData,
  BubbleTimelineChartProps
> {
  constructor() {
    const metadata = new ChartMetadata({
      category: t('Correlation'),
      name: t('Bubble Timeline'),
      description: t(
        'Animated (Gapminder-style) bubble chart: X vs Y with bubble size as ' +
          'a third measure, animated across a timeline dimension. Rendered ' +
          'with ECharts.',
      ),
      tags: [t('Bubble'), t('Time'), t('Correlation'), t('ECharts')],
      thumbnail,
    });

    super({
      buildQuery,
      controlPanel,
      loadChart: () => import('../PluginChartBubbleTimeline'),
      metadata,
      transformProps,
    });
  }
}
