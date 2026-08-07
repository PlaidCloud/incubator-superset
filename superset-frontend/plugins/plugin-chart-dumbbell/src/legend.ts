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
export type LegendType = 'scroll' | 'plain';
export type LegendOrientation = 'top' | 'bottom' | 'left' | 'right';

export interface LegendOptions {
  show: boolean;
  type: LegendType;
  orientation: LegendOrientation;
  margin: number | null;
}

export interface GridBox {
  left: number;
  right: number;
  top: number;
  bottom: number;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function buildLegend(o: LegendOptions, data?: string[]): any {
  const horizontal = o.orientation === 'top' || o.orientation === 'bottom';
  const m = Number(o.margin) || 0;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const legend: any = {
    show: o.show,
    type: o.type,
    orient: horizontal ? 'horizontal' : 'vertical',
  };
  if (data) legend.data = data;
  switch (o.orientation) {
    case 'bottom':
      legend.bottom = m;
      legend.left = 'center';
      break;
    case 'left':
      legend.left = m;
      legend.top = 'middle';
      break;
    case 'right':
      legend.right = m;
      legend.top = 'middle';
      break;
    case 'top':
    default:
      legend.top = m;
      legend.left = 'center';
      break;
  }
  return legend;
}

// Extend the grid so the legend does not overlap the plot area.
export function padGridForLegend(o: LegendOptions, base: GridBox): GridBox {
  if (!o.show) return base;
  const m = Number(o.margin) || 0;
  const g = { ...base };
  switch (o.orientation) {
    case 'bottom':
      g.bottom += 34 + m;
      break;
    case 'left':
      g.left += 100 + m;
      break;
    case 'right':
      g.right += 100 + m;
      break;
    case 'top':
    default:
      g.top += 34 + m;
      break;
  }
  return g;
}
