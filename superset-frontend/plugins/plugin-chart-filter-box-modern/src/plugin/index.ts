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
import {
  FilterBoxModernFormData,
  FilterBoxModernTransformedProps,
} from '../types';

export default class FilterBoxModernChartPlugin extends ChartPlugin<
  FilterBoxModernFormData,
  FilterBoxModernTransformedProps
> {
  constructor() {
    const metadata = new ChartMetadata({
      behaviors: [Behavior.InteractiveChart],
      category: t('Tools'),
      name: t('Filter Box (modern)'),
      description: t(
        'In-dashboard filter card: multiple dropdowns that emit cross-filters via dataMask. ' +
          'Loads up to 1000 values per column and searches client-side, so no ILIKE is sent ' +
          '(Databend-safe).',
      ),
      tags: [t('Tool'), t('Filter')],
    });

    super({
      buildQuery,
      controlPanel,
      loadChart: () => import('../FilterBoxModern'),
      metadata,
      transformProps,
    });
  }
}
