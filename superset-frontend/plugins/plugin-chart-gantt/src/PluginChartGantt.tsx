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
import { useEffect, useRef } from 'react';
import { styled } from '@superset-ui/core';
import * as echarts from 'echarts';
import { PluginChartGanttProps } from './types';

const StyledContainer = styled.div<{ height: number; width: number }>`
  height: ${({ height }) => height}px;
  width: ${({ width }) => width}px;
`;

export default function PluginChartGantt(props: PluginChartGanttProps) {
  const { height, width, echartOptions } = props;
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);

  // Initialize and update chart
  useEffect(() => {
    if (chartRef.current) {
      if (!chartInstance.current) {
        chartInstance.current = echarts.init(chartRef.current);
      }
      chartInstance.current.setOption(echartOptions, true);
    }

    return () => {
      if (chartInstance.current) {
        chartInstance.current.dispose();
        chartInstance.current = null;
      }
    };
  }, [echartOptions]);

  // Handle resize
  useEffect(() => {
    if (chartInstance.current) {
      chartInstance.current.resize({ width, height });
    }
  }, [width, height]);

  return <StyledContainer ref={chartRef} height={height} width={width} />;
}
