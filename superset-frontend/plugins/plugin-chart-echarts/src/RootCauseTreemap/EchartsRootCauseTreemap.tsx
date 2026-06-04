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
  BinaryQueryObjectFilterClause,
  DataRecordValue,
  getColumnLabel,
  getNumberFormatter,
  getTimeFormatter,
} from '@superset-ui/core';
import { useCallback, useRef } from 'react';
import { NULL_STRING } from '../constants';
import Echart from '../components/Echart';
import { EchartsHandler, EventHandlers } from '../types';
import { extractTreePathInfo } from '../Treemap/constants';
import { formatSeriesName } from '../utils/series';
import { RootCauseTreemapTransformedProps } from './types';

const NORMAL_BORDER_COLOR = '#ffffff';
const NORMAL_BORDER_WIDTH = 1;
const HOVER_BORDER_COLOR = '#000000';
const HOVER_BORDER_WIDTH = 2;

function findHoveredRect(element: any): any {
  let current = element;
  let depth = 0;
  const visited = new Set<any>();

  while (current && depth < 12) {
    if (visited.has(current)) {
      return undefined;
    }
    visited.add(current);

    if (current.type === 'rect' && typeof current.style?.fill === 'string') {
      return current;
    }
    if (typeof current.children === 'function') {
      const rectChild = current
        .children()
        .find(
          (child: any) =>
            child.type === 'rect' && typeof child.style?.fill === 'string',
        );
      if (rectChild) {
        return rectChild;
      }
    }
    current = current.parent;
    depth += 1;
  }

  return undefined;
}

export default function EchartsRootCauseTreemap({
  coltypeMapping,
  echartOptions,
  formData,
  groupby,
  height,
  labelMap,
  onContextMenu,
  refs,
  selectedValues,
  width,
}: RootCauseTreemapTransformedProps) {
  const chartRef = useRef<EchartsHandler>(null);
  const hoveredElementRef = useRef<any>();
  const previousZ2Ref = useRef(new WeakMap());

  const resetHoveredBorder = useCallback(() => {
    const hoveredElement = hoveredElementRef.current;
    if (!hoveredElement) {
      return;
    }
    hoveredElement.setStyle({
      stroke: NORMAL_BORDER_COLOR,
      lineWidth: NORMAL_BORDER_WIDTH,
    });
    hoveredElement.z2 = previousZ2Ref.current.get(hoveredElement) || 0;
    previousZ2Ref.current.delete(hoveredElement);
    hoveredElement.dirty?.();
    hoveredElementRef.current = undefined;
  }, []);

  const setHoveredBorder = useCallback(
    eventParams => {
      const targetElement = findHoveredRect(eventParams.event?.target);
      if (!targetElement || targetElement === hoveredElementRef.current) {
        return;
      }
      resetHoveredBorder();
      previousZ2Ref.current.set(targetElement, targetElement.z2 || 0);
      targetElement.setStyle({
        stroke: HOVER_BORDER_COLOR,
        lineWidth: HOVER_BORDER_WIDTH,
      });
      targetElement.z2 = Math.max(targetElement.z2 || 0, 10);
      targetElement.dirty?.();
      hoveredElementRef.current = targetElement;
    },
    [resetHoveredBorder],
  );

  const getCrossFilterDataMask = useCallback(
    (treePathInfo = []) => {
      const { treePath } = extractTreePathInfo(treePathInfo);
      const name = treePath.join(',');
      if (!name || !labelMap[name]) {
        return undefined;
      }
      const selected = Object.values(selectedValues);
      const values = selected.includes(name)
        ? selected.filter(value => value !== name)
        : [name];
      const groupbyValues = values
        .map(value => labelMap[value])
        .filter(Boolean) as DataRecordValue[][];

      return {
        dataMask: {
          extraFormData: {
            filters:
              groupbyValues.length === 0
                ? []
                : groupbyValues[0].map((_, idx) => {
                    const col = groupby[idx];
                    const val = groupbyValues.map(value => value[idx]);
                    if (
                      val.every(item => item === null || item === undefined)
                    ) {
                      return {
                        col,
                        op: 'IS NULL' as const,
                      };
                    }
                    return {
                      col,
                      op: 'IN' as const,
                      val: val as (string | number | boolean)[],
                    };
                  }),
          },
          filterState: {
            value: groupbyValues.length ? groupbyValues : null,
            selectedValues: values.length ? values : null,
          },
        },
        isCurrentValueSelected: selected.includes(name),
      };
    },
    [groupby, labelMap, selectedValues],
  );

  const eventHandlers: EventHandlers = {
    mouseover: setHoveredBorder,
    globalout: resetHoveredBorder,
    click: eventParams => {
      const { treePath } = extractTreePathInfo(eventParams.treePathInfo);
      const targetNodeId = treePath.join(',');
      if (!targetNodeId) {
        return;
      }
      resetHoveredBorder();
      chartRef.current?.getEchartInstance()?.dispatchAction({
        type: 'treemapRootToNode',
        seriesIndex: 0,
        targetNodeId,
      });
    },
    contextmenu: eventParams => {
      if (!onContextMenu) {
        return;
      }
      eventParams.event.stop();
      const { treePath } = extractTreePathInfo(eventParams.treePathInfo);
      if (!treePath.length) {
        return;
      }
      const pointerEvent = eventParams.event.event;
      const records = labelMap[treePath.join(',')] || treePath;
      const drillToDetailFilters: BinaryQueryObjectFilterClause[] = [];
      const drillByFilters: BinaryQueryObjectFilterClause[] = [];
      treePath.forEach((path, idx) => {
        const col = groupby[idx];
        const rawValue = records[idx];
        const val =
          rawValue === null || rawValue === undefined ? NULL_STRING : rawValue;
        drillToDetailFilters.push({
          col,
          op: '==',
          val,
          formattedVal: path,
        });
        drillByFilters.push({
          col,
          op: '==',
          val,
          formattedVal: formatSeriesName(val, {
            timeFormatter: getTimeFormatter(formData.dateFormat),
            numberFormatter: getNumberFormatter(formData.numberFormat),
            coltype: coltypeMapping?.[getColumnLabel(col)],
          }),
        });
      });
      onContextMenu(pointerEvent.clientX, pointerEvent.clientY, {
        drillToDetail: drillToDetailFilters,
        crossFilter: getCrossFilterDataMask(eventParams.treePathInfo),
        drillBy: { filters: drillByFilters, groupbyFieldName: 'columns' },
      });
    },
  };

  return (
    <Echart
      ref={chartRef}
      refs={refs}
      height={height}
      width={width}
      echartOptions={echartOptions}
      eventHandlers={eventHandlers}
      selectedValues={selectedValues}
    />
  );
}
