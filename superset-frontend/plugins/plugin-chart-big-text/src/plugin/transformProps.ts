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

import { getValueFormatter } from '@superset-ui/core';
import { BigNumberTotalChartProps, BigNumberVizProps } from '../types';

export default function transformProps(
  chartProps: BigNumberTotalChartProps,
): BigNumberVizProps {
  const {
    width,
    height,
    queriesData,
    formData,
    hooks,
    datasource: { currencyFormats = {}, columnFormats = {} },
  } = chartProps;
  const {
    subHeaderColorPicker,
    headerFontSize,
    metric = 'value',
    subheader = '',
    subheaderFontSize,
    textColor,
    color,
    yAxisFormat,
    currencyFormat,
  } = formData;
  const { data = [] } = queriesData[0];
  // const metricName = getMetricLabel(metric);
  const formattedSubheader = subheader;
  const bigNumber: any = Object.values(data[0])[0];
  const mainColor = `rgb(${textColor?.r}, ${textColor?.g}, ${textColor?.b})`;
  const subheaderColor = `rgb(${subHeaderColorPicker?.r}, ${subHeaderColorPicker?.g}, ${subHeaderColorPicker?.b})`;
  const mainHeaderColor = `rgb(${color?.r}, ${color?.g}, ${color?.b})`;

  const numberFormatter = getValueFormatter(
    metric,
    currencyFormats,
    columnFormats,
    yAxisFormat,
    currencyFormat,
  );

  const headerFormatter = numberFormatter;

  const { onContextMenu } = hooks;

  return {
    width,
    height,
    bigNumber,
    mainColor,
    headerFormatter,
    color,
    subheaderColor,
    mainHeaderColor,
    headerFontSize,
    subheaderFontSize,
    subheader: formattedSubheader,
    onContextMenu,
  };
}
