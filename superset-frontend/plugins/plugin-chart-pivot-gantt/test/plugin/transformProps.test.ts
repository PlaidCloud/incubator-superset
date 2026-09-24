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
import { ChartProps } from '@superset-ui/core';
import transformProps from '../../src/plugin/transformProps';

const chartProps = new ChartProps({
  width: 800,
  height: 600,
  formData: {
    groupbyRows: ['stage', 'substage'],
    metrics: ['cost', 'progress'],
    dateStartCol: 'start',
    dateEndCol: ['end'],
    markerProgressCol: 'progress',
    markerLabelTopCol: [],
    markerDescriptionCols: ['owner'],
    timelineFormat: ['P3M', 'P1Y', 'bogus'],
    markerHeight: '40',
    markerFontColor: { r: 1, g: 2, b: 3, a: 1 },
    sliderValues: { start: 1000, end: 2000 },
    hintTrigger: 'click',
  },
  rawFormData: { metrics_config: { progress: { d3NumberFormat: '.2%' } } },
  queriesData: [
    {
      data: [
        { stage: 'A', substage: 'a1', start: 1, end: 2, owner: 'x' },
        { stage: 'B', substage: 'b1', start: 3, end: 4, owner: 'y' },
      ],
    },
    { data: [{ cost: 10, progress: 0.5 }] },
    { data: [{ stage: 'A', cost: 4, progress: 0.2 }] },
    { data: [{ stage: 'A', substage: 'a1', cost: 4, progress: 0.2 }] },
  ],
  hooks: { setDataMask: () => {}, setControlValue: () => {} },
} as any);

describe('PivotGantt transformProps', () => {
  const props = transformProps(chartProps);

  test('splits the query results', () => {
    expect(props.data).toHaveLength(2);
    expect(props.grandTotals).toEqual({ cost: 10, progress: 0.5 });
    expect(props.totals).toHaveLength(2);
  });

  test('resolves column labels and options', () => {
    expect(props.rows).toEqual(['stage', 'substage']);
    expect(props.metricNames).toEqual(['cost', 'progress']);
    expect(props.dateStartCol).toBe('start');
    expect(props.dateEndCol).toBe('end');
    expect(props.progressMetric).toBe('progress');
    expect(props.labelCols.top).toBeUndefined();
    expect(props.labelCols.description).toEqual(['owner']);
    expect(props.markerOptions.height).toBe(40);
    expect(props.markerOptions.fontColor).toBe('rgba(1, 2, 3, 1)');
    expect(props.hintOptions.trigger).toBe('click');
    expect(props.sliderStart).toBe(1000);
    expect(props.sliderEnd).toBe(2000);
  });

  test('keeps only known granularities', () => {
    expect(props.timelineOptions.granularity).toEqual(['P3M', 'P1Y']);
  });

  test('builds one number formatter per metric', () => {
    expect(typeof props.metricFormatters.cost).toBe('function');
    expect(typeof props.metricFormatters.progress).toBe('function');
  });

  test('assigns one colour per first-level value', () => {
    expect(props.markersColors.map(c => c.value)).toEqual(['A', 'B']);
  });
});
