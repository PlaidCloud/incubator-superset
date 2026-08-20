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
  useMemo,
  Ref,
} from 'react';
import { styled } from '@apache-superset/core/theme';
import { t } from '@apache-superset/core/translation';
import { EChartsType, init } from 'echarts';
import { EchartsHandler, EchartsProps, EchartsStylesProps } from '../types';

const Styles = styled.div<EchartsStylesProps>`
  height: ${({ height }) => height}px;
  width: ${({ width }) => width}px;
`;

const Fallback = styled.div<EchartsStylesProps>`
  height: ${({ height }) => height}px;
  width: ${({ width }) => width}px;
  display: flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  color: ${({ theme }) => theme.colorTextTertiary};
`;

// echarts-gl swallows a failed WebGL context — LayerGL's constructor catches the
// error and leaves `renderer` null — and then dereferences it on the next
// resize, which surfaces to the user as a chart-wide "Cannot read properties of
// null (reading 'resize')". Probe for the context up front so a browser that
// cannot grant one gets a readable message instead of a crash.
function isWebglAvailable(): boolean {
  try {
    const probe = document.createElement('canvas');
    return Boolean(
      probe.getContext('webgl') || probe.getContext('experimental-webgl'),
    );
  } catch {
    return false;
  }
}

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
  const hasWebgl = useMemo(isWebglAvailable, []);

  useImperativeHandle(ref, () => ({
    getEchartInstance: () => chartRef.current as any,
  }));

  const getChartInstance = useCallback(() => {
    if (!divRef.current || !hasWebgl) return null;
    if (!chartRef.current) {
      chartRef.current = init(divRef.current);
    }
    return chartRef.current;
  }, [hasWebgl]);

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
    if (chartRef.current && !chartRef.current.isDisposed()) {
      chartRef.current.resize({ width, height });
    }
  }, [width, height]);

  if (!hasWebgl) {
    return (
      <Fallback height={height} width={width}>
        {t(
          'This chart needs WebGL, which the browser did not provide. Closing other 3D charts or tabs and reloading usually frees one up.',
        )}
      </Fallback>
    );
  }

  return <Styles ref={divRef} height={height} width={width} />;
}

export default forwardRef(Echart);
