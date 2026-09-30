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
import { Behavior, ChartMetadata, ChartPlugin } from '@superset-ui/core';
import buildQuery from './buildQuery';
import controlPanel from './controlPanel';
import transformProps from './transformProps';
import thumbnail from '../images/thumbnail.png';

/**
 * Pivot Gantt: a hierarchical pivot table (rows + metrics + subtotals) with a
 * Gantt calendar on the right. Modelled after the `pivot_gantt` chart of the
 * "Superset TA" fork; keeps the same viz key and form_data names so charts
 * exported from that fork load unchanged.
 */
export default class PluginChartPivotGantt extends ChartPlugin {
  constructor() {
    const metadata = new ChartMetadata({
      behaviors: [Behavior.InteractiveChart],
      category: t('Table'),
      description: t(
        'Hierarchical pivot table with per-level subtotals and a Gantt calendar: one marker per row between a start and an end date, with progress, labels, legend, zoom slider and current-day line.',
      ),
      name: t('Pivot Gantt'),
      tags: [t('Additive'), t('Report'), t('Gantt'), t('Table'), t('Time')],
      thumbnail,
    });

    super({
      buildQuery,
      controlPanel,
      loadChart: () => import('../PivotGantt'),
      metadata,
      transformProps,
    });
  }
}
