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
import React, { useEffect, createRef, useState, useRef } from 'react';
import { Select, Button } from 'antd';
import { styled } from '@apache-superset/core/theme';
import type { TimeseriesDataRecord } from '@superset-ui/core';
import {
  SupersetPluginDashboardFiltersProps,
  SupersetPluginDashboardFiltersStylesProps,
} from './types';

// The following Styles component is a <div> element, which has been styled using Emotion
// For docs, visit https://emotion.sh/docs/styled

// Theming variables are provided for your use via a ThemeProvider
// imported from @superset-ui/core. For variables available, please visit
// https://github.com/apache-superset/superset-ui/blob/master/packages/superset-ui-core/src/style/index.ts

const Styles = styled.div<SupersetPluginDashboardFiltersStylesProps>`
  padding: ${({ theme }) => theme.sizeUnit * 4}px;
  border-radius: ${({ theme }) => theme.sizeUnit * 2}px;
  height: ${({ height }) => height}px;
  width: ${({ width }) => width}px;

  /* Horizontal scroll */
  overflow-x: auto;
  overflow-y: auto;
  -webkit-overflow-scrolling: touch;

  pre {
    height: ${({ theme, height }) =>
      height - theme.sizeUnit * 12 - theme.fontSizeHeading3}px;
  }
`;

/**
 * ******************* WHAT YOU CAN BUILD HERE *******************
 *  In essence, a chart is given a few key ingredients to work with:
 *  * Data: provided via `props.data`
 *  * A DOM element
 *  * FormData (your controls!) provided as props by transformProps.ts
 */

export default function SupersetPluginDashboardFilters(
  props: SupersetPluginDashboardFiltersProps,
) {
  const {
    data,
    height,
    width,
    col,
    setDataMask,
    filterState,
    selectState,
    allowMultiple,
    emitCrossFilters,
  } = props;
  const { headerFontSize = 'l', boldText = false } = (props as any) ?? {};

  const originalDataRef = useRef<TimeseriesDataRecord[] | null>(null);

  // Set original data only once
  if (!originalDataRef.current && data) {
    originalDataRef.current = data;
  }

  const key = Array.isArray(col) ? col[0] : col;
  const rootElem = createRef<HTMLDivElement>();

  // State to track selected values
  const [selectedValues, setSelectedValues] = useState<string[]>([]);
  // State to track pending changes (before apply)
  const [pendingValues, setPendingValues] = useState<string[]>([]);

  useEffect(() => {
    if (!setDataMask || !key) return;
    const alreadySet = selectState && Array.isArray(selectState.options);
    const source = originalDataRef.current ?? data;
    if (!alreadySet && source) {
      const uniq = [
        ...new Set(
          source
            .map((item: Record<string, any>) => item[key as string])
            .filter(v => v !== null && v !== undefined),
        ),
      ].map(v => ({ label: String(v), value: String(v) }));
      setDataMask({
        filterState: {
          ...filterState,
          selectState: {
            options: uniq,
          },
        },
      });
    }
    // do not depend on filterState; only initialize once per data/key
  }, [setDataMask, key, data]);

  // Initialize selected values from filterState if available
  useEffect(() => {
    const sv = filterState?.selectedValues ?? [];
    setSelectedValues(sv);
    setPendingValues(sv);
  }, [filterState]);

  useEffect(() => {
    // Remove the header title and position header controls absolutely
    const modifyHeader = () => {
      const currentElement = rootElem.current;
      if (!currentElement) return;

      // Traverse up to find the chart container
      let parent = currentElement.parentElement;
      while (parent) {
        // Look for header title and remove it
        const headerTitle = parent.querySelector('.header-title');
        if (headerTitle) {
          headerTitle.remove();
        }

        // Look for header controls and position them absolutely
        const headerControls = parent.querySelector('.header-controls');
        if (headerControls) {
          (headerControls as HTMLElement).style.position = 'absolute';
          (headerControls as HTMLElement).style.top = '5px';
          (headerControls as HTMLElement).style.right = '8px';
          (headerControls as HTMLElement).style.zIndex = '10';
          (headerControls as HTMLElement).style.background = 'white';
          break;
        }

        parent = parent.parentElement;
        // Stop if we've gone too far up
        if (parent?.classList.contains('dashboard-grid')) break;
      }
    };

    modifyHeader();
  }, []);

  // Handle selection change (doesn't emit immediately)
  const handleSelectionChange = (values: string[]) => {
    setPendingValues(values);
  };

  // Apply filters
  const handleApply = () => {
    if (!emitCrossFilters) {
      return;
    }
    setSelectedValues(pendingValues);

    if (setDataMask && key) {
      const filterPayload = {
        filterState: {
          value: pendingValues.length > 0 ? pendingValues : null,
          selectedValues: pendingValues,
        },
        extraFormData: {
          filters:
            pendingValues.length > 0
              ? [
                  {
                    col: key,
                    op: 'in',
                    val: pendingValues,
                  },
                ]
              : [],
          adhoc_filters:
            pendingValues.length > 0
              ? [
                  {
                    clause: 'WHERE',
                    subject: key,
                    operator: pendingValues.length > 1 ? 'IN' : '==',
                    comparator:
                      pendingValues.length > 1
                        ? pendingValues
                        : pendingValues[0],
                    expressionType: 'SIMPLE',
                  },
                ]
              : [],
        },
      };
      setDataMask(filterPayload);
    }
  };

  // Reset filters
  const handleReset = () => {
    setPendingValues([]);
    setSelectedValues([]);

    // Clear the filter state
    if (setDataMask) {
      setDataMask({
        filterState: {
          value: null,
          selectedValues: [],
        },
        extraFormData: {
          filters: [],
          adhoc_filters: [],
        },
      });
    }
  };

  // Check if there are pending changes
  const hasChanges =
    JSON.stringify(selectedValues) !== JSON.stringify(pendingValues);

  const options = React.useMemo(() => {
    if (selectState && Array.isArray(selectState.options))
      return selectState.options.sort((a: { label: any }, b: { label: any }) =>
        String(a.label).localeCompare(String(b.label)),
      );
    const source = originalDataRef.current ?? data;
    if (!source || !key) return [];
    const uniq = [
      ...new Set(
        source
          .map((item: Record<string, any>) => item[key as string])
          .filter(v => v !== null && v !== undefined),
      ),
    ];
    return uniq
      .map(v => ({ label: String(v), value: String(v) }))
      .sort((a, b) => a.label.localeCompare(b.label));
    // rely on selectState/options rather than current data to keep options stable
  }, [selectState, key]);
  return (
    <Styles
      ref={rootElem}
      height={height}
      width={width}
      headerFontSize={headerFontSize}
      boldText={boldText}
      style={{
        width: '98.5%',
        paddingTop: 0,
        paddingBottom: 0,
        height: '100%',
        display: 'flex',
        gap: '20px',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      <h4 style={{ textWrap: 'nowrap' }}>{key}</h4>
      <Select
        mode={allowMultiple ? 'multiple' : undefined}
        style={{
          width: '100%',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
        showArrow
        placeholder="Select options"
        value={allowMultiple ? pendingValues : (pendingValues[0] ?? undefined)}
        onChange={(val: any) =>
          allowMultiple
            ? handleSelectionChange(val as string[])
            : handleSelectionChange(val ? [val as string] : [])
        }
        options={options}
        showSearch
        filterOption={(input, option) =>
          String(option?.label ?? '')
            .toLowerCase()
            .includes(input.toLowerCase())
        }
      />

      <div style={{ display: 'flex', gap: '5px' }}>
        <Button type="primary" onClick={handleApply} disabled={!hasChanges}>
          Apply ({pendingValues.length})
        </Button>

        <Button
          onClick={handleReset}
          disabled={selectedValues.length === 0 && pendingValues.length === 0}
        >
          Reset
        </Button>
      </div>
    </Styles>
  );
}
