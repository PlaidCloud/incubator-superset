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
import { useState, useEffect, useRef, MouseEvent } from 'react';
import { t } from '@apache-superset/core/translation';
import {
  getNumberFormatter,
  getTimeFormatter,
  SMART_DATE_VERBOSE_ID,
  computeMaxFontSize,
  BRAND_COLOR,
  BinaryQueryObjectFilterClause,
  DTTM_ALIAS,
} from '@superset-ui/core';
import { styled, useTheme } from '@apache-superset/core/theme';
import Echart from '../components/Echart';
import { BigNumberVizProps } from './types';
import { EventHandlers } from '../types';

const defaultNumberFormatter = getNumberFormatter();

const PROPORTION = {
  // text size: proportion of the chart container sans trendline
  METRIC_NAME: 0.125,
  KICKER: 0.1,
  HEADER: 0.3,
  SUBHEADER: 0.125,
  // trendline size: proportion of the whole chart container
  TRENDLINE: 0.3,
};

const HEADER_CONTROL_GAP = '3px';

type ManagedElementStyle = {
  element: HTMLElement;
  priority: string;
  property: string;
  value: string;
};

function BigNumberVis({
  className = '',
  headerFormatter = defaultNumberFormatter,
  formatTime = getTimeFormatter(SMART_DATE_VERBOSE_ID),
  headerFontSize = PROPORTION.HEADER,
  kickerFontSize = PROPORTION.KICKER,
  metricNameFontSize = PROPORTION.METRIC_NAME,
  showMetricName = true,
  mainColor = BRAND_COLOR,
  showTimestamp = false,
  showTrendLine = false,
  startYAxisAtZero = true,
  subheader = '',
  subheaderFontSize = PROPORTION.SUBHEADER,
  subtitleFontSize = PROPORTION.SUBHEADER,
  timeRangeFixed = false,
  ...props
}: BigNumberVizProps) {
  const theme = useTheme();

  // Convert state to hooks
  const [elementsRendered, setElementsRendered] = useState(false);

  // Create refs for each component to measure heights
  const metricNameRef = useRef<HTMLDivElement>(null);
  const kickerRef = useRef<HTMLDivElement>(null);
  const headerRef = useRef<HTMLDivElement>(null);
  const subheaderRef = useRef<HTMLDivElement>(null);
  const subtitleRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Convert componentDidMount
  useEffect(() => {
    // Wait for elements to render and then calculate heights
    const timeout = setTimeout(() => {
      setElementsRendered(true);
    }, 0);
    return () => clearTimeout(timeout);
  }, []);

  // Convert componentDidUpdate - trigger re-render when height or trendline changes
  useEffect(() => {
    // Re-render when height or showTrendLine changes
  }, [props.height, showTrendLine]);

  useEffect(() => {
    const managedStyles: ManagedElementStyle[] = [];
    const trackStyle = (
      element: HTMLElement | null,
      property: string,
      value: string,
      priority = '',
    ) => {
      if (!element) {
        return;
      }
      managedStyles.push({
        element,
        priority: element.style.getPropertyPriority(property),
        property,
        value: element.style.getPropertyValue(property),
      });
      element.style.setProperty(property, value, priority);
    };
    const cleanup = () => {
      managedStyles
        .slice()
        .reverse()
        .forEach(({ element, priority, property, value }) => {
          if (value) {
            element.style.setProperty(property, value, priority);
          } else {
            element.style.removeProperty(property);
          }
        });
    };

    const chartGrid = containerRef.current?.closest(
      '[data-test="chart-grid-component"]',
    ) as HTMLElement | null;
    const sliceHeader = chartGrid?.querySelector(
      '[data-test="slice-header"]',
    ) as HTMLElement | null;
    const title = sliceHeader?.querySelector(
      '.header-title',
    ) as HTMLElement | null;
    const controls = sliceHeader?.querySelector(
      '.header-controls',
    ) as HTMLElement | null;
    const controlChildren = controls
      ? (Array.from(controls.children) as HTMLElement[])
      : [];
    const filterControl =
      controlChildren.find(
        child =>
          child.classList.contains('filter-counts') ||
          Boolean(child.querySelector('.filter-counts')),
      ) ?? null;
    const menuControl =
      controlChildren.find(child =>
        Boolean(child.querySelector('[aria-label="More Options"]')),
      ) ?? null;
    const auxiliaryControls = controlChildren.filter(
      child => child !== filterControl && child !== menuControl,
    );

    if (props.formData?.headerNowrap ?? true) {
      trackStyle(title, 'display', 'block', 'important');
      trackStyle(title, 'white-space', 'nowrap');
      trackStyle(title, 'overflow', 'hidden');
      trackStyle(title, 'text-overflow', 'ellipsis');
      trackStyle(title, '-webkit-line-clamp', 'unset');
      trackStyle(title, '-webkit-box-orient', 'initial');
    }

    if (
      (props.formData?.placeFilterBelow ?? true) &&
      controls &&
      filterControl
    ) {
      trackStyle(controls, 'display', 'flex');
      trackStyle(controls, 'flex-direction', 'column');
      trackStyle(controls, 'align-items', 'flex-end');
      trackStyle(controls, 'height', 'auto');

      [menuControl, ...auxiliaryControls, filterControl].forEach(control => {
        trackStyle(control, 'margin-left', '0px');
      });

      trackStyle(menuControl, 'order', '0');
      trackStyle(menuControl, 'margin-top', '0px');

      auxiliaryControls.forEach(control => {
        trackStyle(control, 'order', '1');
        trackStyle(control, 'margin-top', HEADER_CONTROL_GAP);
      });

      trackStyle(filterControl, 'order', '2');
      trackStyle(filterControl, 'margin-top', HEADER_CONTROL_GAP);
    }

    if (props.formData?.hideFilter) {
      trackStyle(filterControl, 'display', 'none');
    }

    if (containerRef.current && headerFontSize === 0) {
      let element: HTMLElement | null = containerRef.current;
      let foundSliceContainer = false;
      let foundChartContainer = false;

      while (element && element.tagName !== 'BODY') {
        if (
          !foundSliceContainer &&
          element.classList.contains('slice_container')
        ) {
          trackStyle(element, 'height', 'auto');
          trackStyle(element, 'overflow', 'visible');
          foundSliceContainer = true;
        }

        if (
          !foundChartContainer &&
          element.getAttribute('data-test') === 'chart-container'
        ) {
          trackStyle(element, 'display', 'flex');
          trackStyle(element, 'align-items', 'center');
          foundChartContainer = true;
        }

        if (foundSliceContainer && foundChartContainer) {
          break;
        }
        element = element.parentElement;
      }
    }

    return cleanup;
  }, [
    headerFontSize,
    props.formData?.headerNowrap,
    props.formData?.hideFilter,
    props.formData?.placeFilterBelow,
  ]);

  const getClassName = () => {
    const names = `superset-legacy-chart-big-number ${className} ${
      props.bigNumberFallback ? 'is-fallback-value' : ''
    }`;
    if (showTrendLine) return names;
    return `${names} no-trendline`;
  };

  const createTemporaryContainer = () => {
    const container = document.createElement('div');
    container.className = getClassName();
    container.style.position = 'absolute'; // so it won't disrupt page layout
    container.style.opacity = '0'; // and not visible
    return container;
  };

  const shouldRenderKicker = () => {
    const { timestamp } = props;
    return (
      Boolean(formatTime) &&
      showTimestamp &&
      typeof timestamp !== 'string' &&
      typeof timestamp !== 'bigint' &&
      typeof timestamp !== 'boolean'
    );
  };

  const shouldRenderSubtitle = () => {
    const { subtitle, bigNumber } = props;
    return Boolean(subtitle) || bigNumber === null;
  };

  const getAutoHeaderMaxHeight = (availableHeight: number) => {
    if (headerFontSize !== 0) {
      return Math.ceil(headerFontSize * availableHeight);
    }

    const reservedHeights = [
      showMetricName && props.metricName
        ? Math.ceil((metricNameFontSize || 0) * availableHeight)
        : 0,
      shouldRenderKicker()
        ? Math.ceil((kickerFontSize || 0) * availableHeight)
        : 0,
      subheader ? Math.ceil(subheaderFontSize * availableHeight) : 0,
      shouldRenderSubtitle()
        ? Math.ceil(subtitleFontSize * availableHeight)
        : 0,
    ].filter(Boolean);
    const visibleElementCount = reservedHeights.length + 1;
    const totalGapHeight =
      Math.max(visibleElementCount - 1, 0) * theme.sizeUnit * 2;
    const reservedHeight =
      reservedHeights.reduce((sum, value) => sum + value, 0) + totalGapHeight;

    return Math.max(Math.floor(availableHeight - reservedHeight), 1);
  };

  const renderFallbackWarning = () => {
    const { bigNumberFallback } = props;
    if (!formatTime || !bigNumberFallback || showTimestamp) return null;
    return (
      <span
        className="alert alert-warning"
        role="alert"
        title={t(
          `Last available value seen on %s`,
          formatTime(bigNumberFallback[0]),
        )}
      >
        {t('Not up to date')}
      </span>
    );
  };

  const renderMetricName = (maxHeight: number) => {
    const { metricName, width } = props;
    if (!showMetricName || !metricName) return null;

    const text = metricName;

    const container = createTemporaryContainer();
    document.body.append(container);
    const fontSize = computeMaxFontSize({
      text,
      maxWidth: width,
      maxHeight,
      className: 'metric-name',
      container,
    });
    container.remove();

    return (
      <div
        ref={metricNameRef}
        className="metric-name"
        style={{
          fontSize,
          height: 'auto',
        }}
      >
        {text}
      </div>
    );
  };

  const renderKicker = (maxHeight: number) => {
    const { timestamp, width } = props;
    if (
      !formatTime ||
      !showTimestamp ||
      typeof timestamp === 'string' ||
      typeof timestamp === 'bigint' ||
      typeof timestamp === 'boolean'
    )
      return null;

    const text = timestamp === null ? '' : formatTime(timestamp);

    const container = createTemporaryContainer();
    document.body.append(container);
    const className = headerFontSize === 0 ? 'kicker-auto-size' : 'kicker';
    const fontSize = computeMaxFontSize({
      text,
      maxWidth: width,
      maxHeight,
      className,
      container,
    });
    container.remove();

    return (
      <div
        ref={kickerRef}
        className={className}
        style={{
          fontSize,
          height: 'auto',
        }}
      >
        {text}
      </div>
    );
  };

  const renderHeader = (maxHeight: number) => {
    const { bigNumber, width, colorThresholdFormatters, onContextMenu } = props;
    // Format bigNumber based on its type: null/undefined -> "No data", number -> format, else -> string
    let text: string;
    if (bigNumber === null || bigNumber === undefined) {
      text = t('No data');
    } else if (typeof bigNumber === 'number') {
      text = headerFormatter(bigNumber);
    } else {
      // For string/boolean/Date values, convert to number if possible, else show as string
      const numValue = Number(bigNumber);
      text = Number.isNaN(numValue)
        ? String(bigNumber)
        : headerFormatter(numValue);
    }

    const hasThresholdColorFormatter =
      Array.isArray(colorThresholdFormatters) &&
      colorThresholdFormatters.length > 0;

    let numberColor;
    if (hasThresholdColorFormatter) {
      colorThresholdFormatters!.forEach(formatter => {
        const formatterResult = bigNumber
          ? formatter.getColorFromValue(bigNumber as number)
          : false;
        if (formatterResult) {
          numberColor = formatterResult;
        }
      });
    } else {
      numberColor = theme.colorText;
    }

    const container = createTemporaryContainer();
    document.body.append(container);
    const className =
      headerFontSize === 0 ? 'header-line-auto-size' : 'header-line';
    const maxWidth =
      headerFontSize === 0 ? Math.max(width - 8, 0) : width * 0.9;
    const fontSize = computeMaxFontSize({
      text,
      maxWidth,
      maxHeight,
      className,
      container,
    });
    container.remove();

    const handleContextMenu = (e: MouseEvent<HTMLDivElement>) => {
      if (onContextMenu) {
        e.preventDefault();
        onContextMenu(e.nativeEvent.clientX, e.nativeEvent.clientY);
      }
    };

    return (
      <div
        ref={headerRef}
        className={className}
        style={{
          display: 'flex',
          alignItems: 'center',
          fontSize,
          height: 'auto',
          color: numberColor,
        }}
        onContextMenu={handleContextMenu}
      >
        {text}
      </div>
    );
  };

  const rendermetricComparisonSummary = (maxHeight: number) => {
    const { width } = props;
    let fontSize = 0;

    const text = subheader;

    if (text) {
      const container = createTemporaryContainer();
      document.body.append(container);
      const className =
        headerFontSize === 0 ? 'subheader-line-auto-size' : 'subheader-line';
      try {
        fontSize = computeMaxFontSize({
          text,
          maxWidth: width * 0.9,
          maxHeight,
          className,
          container,
        });
      } finally {
        container.remove();
      }

      return (
        <div
          ref={subheaderRef}
          className={className}
          style={{
            fontSize,
            height: headerFontSize === 0 ? 'auto' : maxHeight,
          }}
        >
          {text}
        </div>
      );
    }
    return null;
  };

  const renderSubtitle = (maxHeight: number) => {
    const { subtitle, width, bigNumber, bigNumberFallback } = props;
    let fontSize = 0;

    const NO_DATA_OR_HASNT_LANDED = t(
      'No data after filtering or data is NULL for the latest time record',
    );
    const NO_DATA = t(
      'Try applying different filters or ensuring your datasource has data',
    );

    let text = subtitle;
    if (bigNumber === null) {
      text =
        subtitle || (bigNumberFallback ? NO_DATA : NO_DATA_OR_HASNT_LANDED);
    }

    if (text) {
      const container = createTemporaryContainer();
      document.body.append(container);
      fontSize = computeMaxFontSize({
        text,
        maxWidth: width * 0.9,
        maxHeight,
        className: 'subtitle-line',
        container,
      });
      container.remove();

      return (
        <>
          <div
            ref={subtitleRef}
            className="subtitle-line subheader-line"
            style={{
              fontSize: `${fontSize}px`,
              height: maxHeight,
            }}
          >
            {text}
          </div>
        </>
      );
    }
    return null;
  };

  const renderTrendline = (maxHeight: number) => {
    const {
      width,
      trendLineData,
      echartOptions,
      refs,
      onContextMenu,
      formData,
      xValueFormatter,
    } = props;
    const trendlineFormData =
      formData && 'xAxis' in formData ? formData : undefined;

    // if can't find any non-null values, no point rendering the trendline
    if (!trendLineData?.some(d => d[1] !== null)) {
      return null;
    }

    const eventHandlers: EventHandlers = {
      contextmenu: eventParams => {
        if (onContextMenu) {
          eventParams.event.stop();
          const { data } = eventParams;
          if (data) {
            const pointerEvent = eventParams.event.event;
            const drillToDetailFilters: BinaryQueryObjectFilterClause[] = [];
            drillToDetailFilters.push({
              col:
                trendlineFormData?.xAxis === DTTM_ALIAS
                  ? trendlineFormData?.granularitySqla
                  : trendlineFormData?.xAxis,
              grain: trendlineFormData?.timeGrainSqla,
              op: '==',
              val: data[0],
              formattedVal: xValueFormatter?.(data[0]),
            });
            onContextMenu(pointerEvent.clientX, pointerEvent.clientY, {
              drillToDetail: drillToDetailFilters,
            });
          }
        }
      },
    };

    return (
      echartOptions && (
        <Echart
          refs={refs}
          width={Math.floor(width)}
          height={maxHeight}
          echartOptions={echartOptions}
          eventHandlers={eventHandlers}
          vizType={formData?.vizType}
        />
      )
    );
  };

  const getTotalElementsHeight = () => {
    const marginPerElement = 8; // theme.sizeUnit = 4, so margin-bottom = 8px

    const refs = [
      metricNameRef,
      kickerRef,
      headerRef,
      subheaderRef,
      subtitleRef,
    ];

    // Filter refs to only those with a current element
    const visibleRefs = refs.filter(ref => ref.current);

    const totalHeight = visibleRefs.reduce((sum, ref, index) => {
      const height = ref.current?.offsetHeight || 0;
      const margin = index < visibleRefs.length - 1 ? marginPerElement : 0;
      return sum + height + margin;
    }, 0);

    return totalHeight;
  };

  const shouldApplyOverflow = (availableHeight: number) => {
    if (!elementsRendered) return false;
    const totalHeight = getTotalElementsHeight();
    return totalHeight > availableHeight;
  };

  const { height } = props;
  const componentClassName = getClassName();

  if (showTrendLine) {
    const chartHeight = Math.floor(PROPORTION.TRENDLINE * height);
    const allTextHeight = height - chartHeight;
    const overflow =
      headerFontSize === 0 ? false : shouldApplyOverflow(allTextHeight);

    return (
      <div ref={containerRef} className={componentClassName}>
        <div
          className="text-container"
          style={{
            height: allTextHeight,
            ...(overflow
              ? {
                  display: 'block',
                  boxSizing: 'border-box',
                  overflowX: 'hidden',
                  overflowY: 'auto',
                  width: '100%',
                }
              : {}),
          }}
        >
          {renderFallbackWarning()}
          {renderMetricName(
            Math.ceil(
              (metricNameFontSize || 0) * (1 - PROPORTION.TRENDLINE) * height,
            ),
          )}
          {renderKicker(
            Math.ceil(
              (kickerFontSize || 0) * (1 - PROPORTION.TRENDLINE) * height,
            ),
          )}
          {renderHeader(
            headerFontSize === 0
              ? getAutoHeaderMaxHeight(allTextHeight)
              : Math.ceil(headerFontSize * (1 - PROPORTION.TRENDLINE) * height),
          )}
          {rendermetricComparisonSummary(
            Math.ceil(subheaderFontSize * (1 - PROPORTION.TRENDLINE) * height),
          )}
          {renderSubtitle(
            Math.ceil(subtitleFontSize * (1 - PROPORTION.TRENDLINE) * height),
          )}
        </div>
        {renderTrendline(chartHeight)}
      </div>
    );
  }
  const overflow = headerFontSize === 0 ? false : shouldApplyOverflow(height);
  return (
    <div
      ref={containerRef}
      className={componentClassName}
      style={{
        height,
        ...(overflow
          ? {
              display: 'block',
              boxSizing: 'border-box',
              overflowX: 'hidden',
              overflowY: 'auto',
              width: '100%',
            }
          : {}),
      }}
    >
      <div className="text-container">
        {renderFallbackWarning()}
        {renderMetricName((metricNameFontSize || 0) * height)}
        {renderKicker((kickerFontSize || 0) * height)}
        {renderHeader(getAutoHeaderMaxHeight(height))}
        {rendermetricComparisonSummary(Math.ceil(subheaderFontSize * height))}
        {renderSubtitle(Math.ceil(subtitleFontSize * height))}
      </div>
    </div>
  );
}

const StyledBigNumberVis = styled(BigNumberVis)`
  ${({ theme }) => `
    font-family: ${theme.fontFamily};
    position: relative;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: flex-start;

    &.no-trendline .subheader-line {
      padding-bottom: 0.3em;
    }

    .text-container {
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: flex-start;
      .alert {
        font-size: ${theme.fontSizeSM};
        margin: -0.5em 0 0.4em;
        line-height: 1;
        padding: ${theme.sizeUnit}px;
        border-radius: ${theme.borderRadius}px;
      }
    }

    .kicker {
      line-height: 1em;
      margin-bottom: ${theme.sizeUnit * 2}px;
    }

    .kicker-auto-size {
      line-height: 1em;
      margin-bottom: ${theme.sizeUnit}px;
    }

    .metric-name {
      line-height: 1em;
      margin-bottom: ${theme.sizeUnit * 2}px;
    }

    .header-line {
      position: relative;
      line-height: 1em;
      white-space: nowrap;
      margin-bottom:${theme.sizeUnit * 2}px;
      span {
        position: absolute;
        bottom: 0;
      }
    }

    .header-line-auto-size {
      position: relative;
      line-height: normal;
      white-space: nowrap;
      margin-bottom: ${theme.sizeUnit * 2}px;
      span {
        position: absolute;
        bottom: 0;
      }
    }

    .subheader-line {
      line-height: 1em;
      margin-bottom: ${theme.sizeUnit * 2}px;
    }

    .subheader-line-auto-size {
      line-height: 1.2;
      margin-top: ${theme.sizeUnit + 2}px;
      margin-bottom: ${theme.sizeUnit * 2}px;
      opacity: 0.85;
    }

    .subtitle-line {
      line-height: 1em;
      margin-bottom: ${theme.sizeUnit * 2}px;
    }

    &.is-fallback-value {
      .kicker,
      .header-line,
      .subheader-line,
      .kicker-auto-size,
      .header-line-auto-size,
      .subheader-line-auto-size {
        opacity: 60%;
      }
    }
  `}
`;

export default StyledBigNumberVis;
