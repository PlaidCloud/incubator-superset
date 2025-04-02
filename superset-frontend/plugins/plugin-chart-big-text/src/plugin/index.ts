/*
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

import { t, ChartMetadata, ChartPlugin } from '@superset-ui/core';
import transformProps from './transformProps';
import buildQuery from './buildQuery';
import example1 from '../images/BigNumber.jpg';
import example2 from '../images/BigNumber2.jpg';
import thumbnail from '../images/thumbnail.png';
import controlPanel from './controlPanel';

const metadata = new ChartMetadata({
  category: t('Ranking'),
  credits: ['https://github.com/jasondavies/d3-cloud'],
  description: t(
    'Visualizes the words in a column that appear the most often. Bigger font corresponds to higher frequency.',
  ),
  exampleGallery: [{ url: example1 }, { url: example2 }],
  name: t('Big Text'),
  tags: [
    t('Aesthetic'),
    t('Categorical'),
    t('Comparison'),
    t('Description'),
    t('Density'),
    t('Single Metric'),
  ],
  thumbnail,
});

export default class BigNumberNewChartPlugin extends ChartPlugin {
  constructor() {
    super({
      buildQuery,
      loadChart: () => import('../chart/BigText'),
      metadata,
      transformProps,
      controlPanel,
    });
  }
}
