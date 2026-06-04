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
import {
  BenchmarkRangeChartProps,
  BenchmarkRangeQueryFormData,
} from '../types';

export default class BenchmarkRangeChartPlugin extends ChartPlugin<
  BenchmarkRangeQueryFormData,
  BenchmarkRangeChartProps
> {
  constructor() {
    const metadata = new ChartMetadata({
      behaviors: [Behavior.InteractiveChart],
      category: t('KPI'),
      description: t(
        'Horizontal benchmarking range chart with IQR bars and median, target, and actual markers.',
      ),
      name: t('Benchmarking Range Chart'),
      tags: [t('Benchmark'), t('IQR'), t('KPI'), t('Distribution')],
      thumbnail,
    });

    super({
      buildQuery,
      controlPanel,
      loadChart: () => import('../PluginChartBenchmarkRange'),
      metadata,
      transformProps,
    });
  }
}
