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
import {
  useRef,
  useEffect,
  forwardRef,
  useImperativeHandle,
  useCallback,
  Ref,
} from 'react';
import { styled } from '@apache-superset/core/theme';
import { EChartsType, init } from 'echarts';
import { EchartsHandler, EchartsProps, EchartsStylesProps } from '../types';

const Styles = styled.div<EchartsStylesProps>`
  height: ${({ height }) => height}px;
  width: ${({ width }) => width}px;
`;

function Echart(
  { width, height, echartOptions, eventHandlers, refs }: EchartsProps,
  ref: Ref<EchartsHandler>,
) {
  const divRef = useRef<HTMLDivElement>(null);
  if (refs) {
    // eslint-disable-next-line no-param-reassign
    refs.divRef = divRef;
  }
  const chartRef = useRef<EChartsType>();

  useImperativeHandle(ref, () => ({
    getEchartInstance: () => chartRef.current as any,
  }));

  const getChartInstance = useCallback(() => {
    if (!divRef.current) return null;
    if (!chartRef.current) {
      chartRef.current = init(divRef.current);
    }
    return chartRef.current;
  }, []);

  useEffect(() => {
    const chart = getChartInstance();
    if (!chart || !echartOptions) return;
    Object.entries(eventHandlers || {}).forEach(([name, handler]) => {
      chart.off(name);
      chart.on(name, handler as any);
    });
    chart.setOption(echartOptions, true);
  }, [echartOptions, eventHandlers, getChartInstance]);

  useEffect(() => {
    getChartInstance();
    return () => {
      if (chartRef.current) {
        chartRef.current.dispose();
        chartRef.current = undefined;
      }
    };
  }, [getChartInstance]);

  useEffect(() => {
    if (chartRef.current) {
      chartRef.current.resize({ width, height });
    }
  }, [width, height]);

  return <Styles ref={divRef} height={height} width={width} />;
}

export default forwardRef(Echart);
