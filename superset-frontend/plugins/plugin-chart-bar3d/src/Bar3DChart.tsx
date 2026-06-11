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
// Importing echarts-gl registers the 3D components (bar3D, grid3D, *Axis3D)
// on the shared echarts instance as a side effect. Must come after echarts.
import 'echarts-gl';
import { Bar3DTransformedProps } from './types';
import Echart from './components/Echart';

export default function Bar3DChart(props: Bar3DTransformedProps) {
  const { height, width, echartOptions, refs } = props;
  return (
    <Echart
      refs={refs}
      height={height * 0.999}
      width={width * 0.999}
      echartOptions={echartOptions}
    />
  );
}
