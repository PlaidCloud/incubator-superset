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
import { PureComponent, MouseEvent, createRef } from 'react';
import {
  t,
  getNumberFormatter,
  getTimeFormatter,
  SMART_DATE_VERBOSE_ID,
  computeMaxFontSize,
  BRAND_COLOR,
  styled,
  BinaryQueryObjectFilterClause,
} from '@superset-ui/core';
import Echart from '../components/Echart';
import { BigNumberVizProps } from './types';
import { EventHandlers } from '../types';

const defaultNumberFormatter = getNumberFormatter();

const PROPORTION = {
  // text size: proportion of the chart container sans trendline
  KICKER: 0.1,
  HEADER: 0.3,
  SUBHEADER: 0.125,
  // trendline size: proportion of the whole chart container
  TRENDLINE: 0.3,
};

const HEADER_CONTROL_GAP = '3px';

type ManagedHeaderStyle = {
  element: HTMLElement;
  priority: string;
  property: string;
  value: string;
};

class BigNumberVis extends PureComponent<BigNumberVizProps> {
  containerRef = createRef<HTMLDivElement>();

  managedHeaderStyles: ManagedHeaderStyle[] = [];

  static defaultProps = {
    className: '',
    headerFormatter: defaultNumberFormatter,
    formatTime: getTimeFormatter(SMART_DATE_VERBOSE_ID),
    headerFontSize: PROPORTION.HEADER,
    kickerFontSize: PROPORTION.KICKER,
    mainColor: BRAND_COLOR,
    showTimestamp: false,
    showTrendLine: false,
    startYAxisAtZero: true,
    subheader: '',
    subheaderFontSize: PROPORTION.SUBHEADER,
    timeRangeFixed: false,
  };

  componentDidMount() {
    this.adjustSliceContainerHeight();
    this.adjustSliceHeaderLayout();
  }

  componentDidUpdate() {
    this.adjustSliceContainerHeight();
    this.adjustSliceHeaderLayout();
  }

  componentWillUnmount() {
    this.cleanupSliceHeaderLayout();
  }

  getSliceHeaderLayoutOptions() {
    const { formData } = this.props;
    return {
      headerNowrap: formData?.headerNowrap ?? true,
      hideFilter: Boolean(formData?.hideFilter),
      placeFilterBelow: formData?.placeFilterBelow ?? true,
    };
  }

  getSliceHeaderElements() {
    const chartGrid = this.containerRef.current?.closest(
      '[data-test="chart-grid-component"]',
    ) as HTMLElement | null;
    const header = chartGrid?.querySelector(
      '[data-test="slice-header"]',
    ) as HTMLElement | null;
    const title = header?.querySelector('.header-title') as HTMLElement | null;
    const controls = header?.querySelector(
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

    return {
      auxiliaryControls,
      controls,
      filterControl,
      header,
      menuControl,
      title,
    };
  }

  trackHeaderStyle(
    element: HTMLElement | null,
    property: string,
    value: string,
    priority = '',
  ) {
    if (!element) {
      return;
    }

    this.managedHeaderStyles.push({
      element,
      priority: element.style.getPropertyPriority(property),
      property,
      value: element.style.getPropertyValue(property),
    });
    element.style.setProperty(property, value, priority);
  }

  cleanupSliceHeaderLayout() {
    this.managedHeaderStyles
      .slice()
      .reverse()
      .forEach(({ element, priority, property, value }) => {
        if (value) {
          element.style.setProperty(property, value, priority);
        } else {
          element.style.removeProperty(property);
        }
      });
    this.managedHeaderStyles = [];
  }

  stackSliceHeaderControls(
    controls: HTMLElement | null,
    menuControl: HTMLElement | null,
    auxiliaryControls: HTMLElement[],
    filterControl: HTMLElement | null,
  ) {
    if (!controls || !filterControl) {
      return;
    }

    this.trackHeaderStyle(controls, 'display', 'flex');
    this.trackHeaderStyle(controls, 'flex-direction', 'column');
    this.trackHeaderStyle(controls, 'align-items', 'flex-end');
    this.trackHeaderStyle(controls, 'height', 'auto');

    [menuControl, ...auxiliaryControls, filterControl].forEach(control => {
      this.trackHeaderStyle(control, 'margin-left', '0px');
    });

    this.trackHeaderStyle(menuControl, 'order', '0');
    this.trackHeaderStyle(menuControl, 'margin-top', '0px');

    auxiliaryControls.forEach(control => {
      this.trackHeaderStyle(control, 'order', '1');
      this.trackHeaderStyle(control, 'margin-top', HEADER_CONTROL_GAP);
    });

    this.trackHeaderStyle(filterControl, 'order', '2');
    this.trackHeaderStyle(filterControl, 'margin-top', HEADER_CONTROL_GAP);
  }

  // The slice header lives outside the chart body, so the Big Number viz tags
  // its own header container and adjusts only the surrounding header UI.
  adjustSliceHeaderLayout() {
    this.cleanupSliceHeaderLayout();

    const { headerNowrap, hideFilter, placeFilterBelow } =
      this.getSliceHeaderLayoutOptions();
    const { auxiliaryControls, controls, filterControl, menuControl, title } =
      this.getSliceHeaderElements();

    if (headerNowrap) {
      this.trackHeaderStyle(title, 'display', 'block', 'important');
      this.trackHeaderStyle(title, 'white-space', 'nowrap');
      this.trackHeaderStyle(title, 'overflow', 'hidden');
      this.trackHeaderStyle(title, 'text-overflow', 'ellipsis');
      this.trackHeaderStyle(title, '-webkit-line-clamp', 'unset');
      this.trackHeaderStyle(title, '-webkit-box-orient', 'initial');
    }

    if (placeFilterBelow) {
      this.stackSliceHeaderControls(
        controls,
        menuControl,
        auxiliaryControls,
        filterControl,
      );
    }

    if (hideFilter) {
      this.trackHeaderStyle(filterControl, 'display', 'none');
    }
  }

  adjustSliceContainerHeight() {
    if (!this.containerRef.current) return;
    let element: HTMLElement | null = this.containerRef.current;

    // We want to handle both slice_container and chart-container
    let foundSliceContainer = false;
    let foundChartContainer = false;

    while (element && element.tagName !== 'BODY') {
      // 1. Handle auto height on slice_container
      if (
        !foundSliceContainer &&
        element.classList.contains('slice_container')
      ) {
        if (this.props.headerFontSize === 0) {
          element.style.height = 'auto';
          element.style.overflow = 'visible';
        } else {
          element.style.height = '100%';
          element.style.overflow = 'hidden';
        }
        foundSliceContainer = true;
      }

      // 2. Handle vertical centering on data-test="chart-container"
      if (
        !foundChartContainer &&
        element.getAttribute('data-test') === 'chart-container'
      ) {
        if (this.props.headerFontSize === 0) {
          element.style.display = 'flex';
          element.style.alignItems = 'center';
        } else {
          element.style.display = '';
          element.style.alignItems = '';
        }
        foundChartContainer = true;
      }

      // Stop traversing if both are processed
      if (foundSliceContainer && foundChartContainer) {
        break;
      }

      element = element.parentElement;
    }
  }

  getClassName() {
    const { className, showTrendLine, bigNumberFallback } = this.props;
    const names = `superset-legacy-chart-big-number ${className} ${
      bigNumberFallback ? 'is-fallback-value' : ''
    }`;
    if (showTrendLine) return names;
    return `${names} no-trendline`;
  }

  createTemporaryContainer() {
    const container = document.createElement('div');
    container.className = this.getClassName();
    container.style.position = 'absolute'; // so it won't disrupt page layout
    container.style.opacity = '0'; // and not visible
    return container;
  }

  renderFallbackWarning() {
    const { bigNumberFallback, formatTime, showTimestamp } = this.props;
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
  }

  renderKicker(maxHeight: number) {
    const { timestamp, showTimestamp, formatTime, width } = this.props;
    if (
      !formatTime ||
      !showTimestamp ||
      typeof timestamp === 'string' ||
      typeof timestamp === 'bigint' ||
      typeof timestamp === 'boolean'
    )
      return null;

    const text = timestamp === null ? '' : formatTime(timestamp);

    const container = this.createTemporaryContainer();
    document.body.append(container);
    const className =
      this.props.headerFontSize === 0 ? 'kicker-auto-size' : 'kicker';
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
        className={className}
        style={{
          fontSize,
          height: 'auto',
        }}
      >
        {text}
      </div>
    );
  }

  renderHeader(maxHeight: number) {
    const { bigNumber, headerFormatter, width, colorThresholdFormatters } =
      this.props;
    // @ts-ignore
    const text = bigNumber === null ? t('No data') : headerFormatter(bigNumber);

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
      numberColor = 'black';
    }

    const container = this.createTemporaryContainer();
    document.body.append(container);
    const className =
      this.props.headerFontSize === 0 ? 'header-line-auto-size' : 'header-line';
    const maxWidth = this.props.headerFontSize === 0 ? width - 8 : width * 0.9;
    const fontSize = computeMaxFontSize({
      text,
      maxWidth,
      maxHeight,
      className,
      container,
    });
    container.remove();

    const onContextMenu = (e: MouseEvent<HTMLDivElement>) => {
      if (this.props.onContextMenu) {
        e.preventDefault();
        this.props.onContextMenu(e.nativeEvent.clientX, e.nativeEvent.clientY);
      }
    };

    return (
      <div
        className={className}
        style={{
          display: 'flex',
          alignItems: 'center',
          fontSize,
          height: 'auto',
          color: numberColor,
        }}
        onContextMenu={onContextMenu}
      >
        {text}
      </div>
    );
  }

  renderSubheader(maxHeight: number) {
    const { bigNumber, subheader, width, bigNumberFallback, headerFontSize } =
      this.props;
    let fontSize = 0;

    const NO_DATA_OR_HASNT_LANDED = t(
      'No data after filtering or data is NULL for the latest time record',
    );
    const NO_DATA = t(
      'Try applying different filters or ensuring your datasource has data',
    );
    let text = subheader;
    if (bigNumber === null) {
      text = bigNumberFallback ? NO_DATA : NO_DATA_OR_HASNT_LANDED;
    }
    if (text) {
      const container = this.createTemporaryContainer();
      document.body.append(container);
      const className =
        headerFontSize === 0 ? 'subheader-line-auto-size' : 'subheader-line';
      fontSize = computeMaxFontSize({
        text,
        maxWidth: width * 0.9, // max width reduced
        maxHeight,
        className,
        container,
      });
      container.remove();

      return (
        <div
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
  }

  renderTrendline(maxHeight: number) {
    const { width, trendLineData, echartOptions, refs } = this.props;

    // if can't find any non-null values, no point rendering the trendline
    if (!trendLineData?.some(d => d[1] !== null)) {
      return null;
    }

    const eventHandlers: EventHandlers = {
      contextmenu: eventParams => {
        if (this.props.onContextMenu) {
          eventParams.event.stop();
          const { data } = eventParams;
          if (data) {
            const pointerEvent = eventParams.event.event;
            const drillToDetailFilters: BinaryQueryObjectFilterClause[] = [];
            drillToDetailFilters.push({
              col: this.props.formData?.granularitySqla,
              grain: this.props.formData?.timeGrainSqla,
              op: '==',
              val: data[0],
              formattedVal: this.props.xValueFormatter?.(data[0]),
            });
            this.props.onContextMenu(
              pointerEvent.clientX,
              pointerEvent.clientY,
              { drillToDetail: drillToDetailFilters },
            );
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
        />
      )
    );
  }

  render() {
    const {
      showTrendLine,
      height,
      kickerFontSize,
      headerFontSize,
      subheaderFontSize,
    } = this.props;
    const className = this.getClassName();

    if (showTrendLine) {
      const chartHeight = Math.floor(PROPORTION.TRENDLINE * height);
      const allTextHeight = height - chartHeight;

      return (
        <div className={className} ref={this.containerRef}>
          <div
            className="text-container"
            style={{ height: headerFontSize === 0 ? 'auto' : allTextHeight }}
          >
            {this.renderFallbackWarning()}
            {this.renderKicker(
              Math.ceil(
                (kickerFontSize || 0) * (1 - PROPORTION.TRENDLINE) * height,
              ),
            )}
            {this.renderHeader(
              headerFontSize === 0
                ? allTextHeight * 2
                : Math.ceil(
                    headerFontSize * (1 - PROPORTION.TRENDLINE) * height,
                  ),
            )}
            {this.renderSubheader(
              Math.ceil(
                subheaderFontSize * (1 - PROPORTION.TRENDLINE) * height,
              ),
            )}
          </div>
          {this.renderTrendline(chartHeight)}
        </div>
      );
    }

    return (
      <div
        className={className}
        style={{ height: headerFontSize === 0 ? 'auto' : height }}
        ref={this.containerRef}
      >
        {this.renderFallbackWarning()}
        {this.renderKicker((kickerFontSize || 0) * height)}
        {this.renderHeader(
          headerFontSize === 0
            ? height * 2
            : Math.ceil(headerFontSize * height),
        )}
        {this.renderSubheader(Math.ceil(subheaderFontSize * height))}
      </div>
    );
  }
}

export default styled(BigNumberVis)`
  ${({ theme }) => `
    font-family: ${theme.typography.families.sansSerif};
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
        font-size: ${theme.typography.sizes.s};
        margin: -0.5em 0 0.4em;
        line-height: 1;
        padding: ${theme.gridUnit}px;
        border-radius: ${theme.gridUnit}px;
      }
    }

    .kicker {
      line-height: 1em;
      padding-bottom: 2em;
    }

    .kicker-auto-size {
      line-height: 1em;
      padding-bottom: 0.2em;
    }

    .header-line {
      position: relative;
      line-height: 1em;
      white-space: nowrap;
      margin-bottom:${theme.gridUnit * 2}px;
      span {
        position: absolute;
        bottom: 0;
      }
    }

    .header-line-auto-size {
      position: relative;
      line-height: normal;
      white-space: nowrap;
      span {
        position: absolute;
        bottom: 0;
      }
    }

    .subheader-line {
      line-height: 1em;
      padding-bottom: 0;
    }

    .subheader-line-auto-size {
      line-height: 1.2;
      margin-top: 6px;
      opacity: 0.85;
      padding-bottom: 0;
    }

    &.is-fallback-value {
      .kicker,
      .header-line,
      .subheader-line,
      .header-line-auto-size,
      .subheader-line-auto-size,
      .kicker-auto-size {
        opacity: ${theme.opacity.mediumHeavy};
      }
    }
  `}
`;
