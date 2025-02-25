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
import Echart from '../components/Echart';
import { WaterfallChartTransformedProps } from './types';
import { EventHandlers } from '../types';
import { EChartsCoreOption } from 'echarts/core';

export default function EchartsWaterfall(
  props: WaterfallChartTransformedProps,
) {
  const {
    height,
    width,
    echartOptions,
    refs,
    onLegendStateChanged,
    formData: {
      sortXAxis,
      orientation,
      showTotal,
      useFirstValueAsSubtotal,
      totalColor,
      xAxisLabelDistance,
      yAxisLabelDistance,
      boldTotal,
      boldSubTotal
    }
  } = props;

  const eventHandlers: EventHandlers = {
    legendselectchanged: payload => {
      onLegendStateChanged?.(payload.selected);
    },
    legendselectall: payload => {
      onLegendStateChanged?.(payload.selected);
    },
    legendinverseselect: payload => {
      onLegendStateChanged?.(payload.selected);
    },
  };

  const getSubtotalOptions = (options: EChartsCoreOption) => {
    if (!useFirstValueAsSubtotal) return options;

    const xAxisData = [...((options.xAxis as { data: (string | number)[] }).data || [])];

    const processedSeries = ((options.series as any[]) || []).map(series => {
      const newData = series.data.map((dataPoint: any, index: number) => {

        if (index !== 0) return dataPoint;

        const isTransparent = dataPoint?.itemStyle?.color &&
          dataPoint.itemStyle.color === 'transparent';

        if (isTransparent) return dataPoint;

        if (dataPoint.value === '-') return dataPoint;

        const updatedColor = `rgba(${totalColor.r}, ${totalColor.g}, ${totalColor.b}, ${totalColor.a})`;
        return {
          ...dataPoint,
          itemStyle: {
            ...dataPoint.itemStyle,
            color: updatedColor,
            borderColor: updatedColor,
          }
        };
      });

      return {
        ...series,
        data: newData
      };
    });

    return {
      ...options,
      xAxis: {
        ...(options.xAxis as any),
        data: xAxisData
      },
      series: processedSeries
    };
  };

  const getShowTotalOptions = (options: EChartsCoreOption) => {
    if (showTotal) return options;

    const totalsIndex = ((options.series as any[]) || [])
      .find(series => series.name === 'Total')
      ?.data
      .map((dataPoint: any, index: number) => dataPoint.value !== '-' ? index : -1)
      .filter((index: number) => index !== -1) || [];

    const xAxisData = [...((options.xAxis as { data: (string | number)[] }).data || [])]
      .filter((_, index) => !totalsIndex.includes(index));

    const filteredSeries = ((options.series as any[]) || []).map(series => ({
      ...series,
      data: series.data.filter((_: any, index: number) => !totalsIndex.includes(index))
    }));

    return {
      ...options,
      xAxis: {
        ...(options.xAxis as any),
        data: xAxisData
      },
      series: filteredSeries
    };
  };

  const getSortedOptions = (options: EChartsCoreOption) => {
    if (sortXAxis === 'none') return options;
    const xAxisData = [...((options.xAxis as { data: (string | number)[] }).data || [])];

    let sortedData = [...xAxisData];

    sortedData.sort((a, b) => {
      if (typeof a === 'number' && typeof b === 'number') {
        return sortXAxis === 'asc' ? a - b : b - a;
      }
      const aStr = String(a);
      const bStr = String(b);
      return sortXAxis === 'asc' ? aStr.localeCompare(bStr) : bStr.localeCompare(aStr);
    });

    const indexMap = new Map(xAxisData.map((val, index) => [val, index]));

    const sortedSeries = ((options.series as any[]) || []).map(series => ({
      ...series,
      data: sortedData.map(value => {
        const index = indexMap.get(value);
        return index !== undefined ? (series as any).data[index] : null;
      })
    }));

    return {
      ...options,
      xAxis: {
        ...(options.xAxis as any),
        data: sortedData
      },
      series: sortedSeries
    };
  };

  const getFlippedOptions = (options: EChartsCoreOption) => {
    if (orientation === 'vertical') return options;

    return {
      ...options,
      xAxis: {
        ...((options.yAxis as any) || {}),
        type: 'value',
        axisLine: {
          show: true,
          lineStyle: {
            color: '#666666',
            width: 1
          }
        },
        splitLine: {
          show: true,
          lineStyle: {
            color: '#ccc',
            width: 1,
            type: 'solid'
          }
        },
        name: (options.yAxis as any)?.name || '',
        nameLocation: 'middle',
      },
      yAxis: {
        ...((options.xAxis as any) || {}),
        type: 'category',
        axisLine: { show: true },
        data: [...(options.xAxis as any).data].reverse(),
        name: (options.xAxis as any)?.name || '',
        nameLocation: 'middle',
      },
      series: Array.isArray(options.series) ? options.series.map((series: any) => ({
        ...series,
        encode: {
          x: series.encode?.y,
          y: series.encode?.x,
        },
        data: [...series.data].reverse(),
        label: {
          ...(series.label || {}),
          position: series.name === 'Decrease' ? 'left' : 'right'
        }
      })) : [],
    };
  };

  const getSubTotalBoldOptions = (options: EChartsCoreOption) => {
    if (!boldSubTotal) return options

    if (orientation === 'vertical') return {
      ...options,
      xAxis: {
        ...((options.xAxis as any) || {}),
        axisLabel: {
          ...((options.xAxis as any).axisLabel || {}),
          formatter: function (value: string, index: number) {
            if (index === 0) return `{subtotal|${value}}`;
            return value;
          },
          rich: {
            subtotal: {
              fontWeight: 'bold'
            }
          },
        }
      }
    };

    return {
      ...options,
      yAxis: {
        ...((options.yAxis as any) || {}),
        axisLabel: {
          ...((options.yAxis as any).axisLabel || {}),
          formatter: function (value: string, index: number) {
            if (index === (options.yAxis as any).data.length - 1) return `{subtotal|${value}}`;
            return value;
          },
          rich: {
            subtotal: {
              fontWeight: 'bold'
            }
          },
        }
      }
    }
  }

  const getBoldTotalOptions = (options: EChartsCoreOption) => {
    if (!boldTotal) return options;

    const totalsIndex = ((options.series as any[]) || [])
      .find(series => series.name === 'Total')
      ?.data
      .map((dataPoint: any, index: number) => dataPoint.value !== '-' ? index : -1)
      .filter((index: number) => index !== -1) || [];

    if (orientation === 'vertical') return {
      ...options,
      xAxis: {
        ...(options.xAxis as any),
        axisLabel: {
          ...(options.xAxis as any).axisLabel,
          formatter: function (value: string, index: number) {
            if (index === 0 && useFirstValueAsSubtotal) return `{subtotal|${value}}`;
            else if (totalsIndex.includes(index)) return `{total|${value}}`;
            return value;
          },
          rich: {
            ...(options.xAxis as any).axisLabel.rich,
            total: {
              fontWeight: 'bold'
            }
          }
        }
      }
    }

    return {
      ...options,
      yAxis: {
        ...(options.yAxis as any),
        axisLabel: {
          ...(options.yAxis as any).axisLabel,
          formatter: function (value: string, index: number) {
            if (index === (options.yAxis as any).data.length - 1 && useFirstValueAsSubtotal) return `{subtotal|${value}}`;
            else if (totalsIndex.includes(index)) return `{total|${value}}`;
            return value;
          },
          rich: {
            ...((options.yAxis as any).axisLabel.rich || {}),
            total: {
              fontWeight: 'bold'
            }
          }
        }
      }
    }
  }

  const getLabelDistanceOptions = (options: EChartsCoreOption) => {

    if (isNaN(Number(xAxisLabelDistance))) {
      console.error('xAxisLabelDistance should be a number');
      return options;
    }

    if (isNaN(Number(yAxisLabelDistance))) {
      console.error('yAxisLabelDistance should be a number');
      return options;
    }

    return {
      ...options,
      xAxis: {
        ...(options.xAxis as any),
        nameGap: Number(xAxisLabelDistance)
      },
      yAxis: {
        ...(options.yAxis as any),
        nameGap: Number(yAxisLabelDistance)
      }
    };
  }


  const subtotalOptions = getSubtotalOptions(echartOptions);
  const showTotalOptions = getShowTotalOptions(subtotalOptions);
  const sortedEchartOptions = getSortedOptions(showTotalOptions);
  const flippedEchartOptions = getFlippedOptions(sortedEchartOptions);
  const boldSubTotalOptions = getSubTotalBoldOptions(flippedEchartOptions);
  const boldTotalOptions = getBoldTotalOptions(boldSubTotalOptions);
  const labelDistanceOptions = getLabelDistanceOptions(boldTotalOptions);

  return (
    <Echart
      refs={refs}
      height={height}
      width={width}
      echartOptions={labelDistanceOptions}
      eventHandlers={eventHandlers}
    />
  );
}
