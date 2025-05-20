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
import React, { MouseEvent } from 'react';
import {
  t,
  getNumberFormatter,
  createSmartDateVerboseFormatter,
  computeMaxFontSize,
  styled,
} from '@superset-ui/core';
import { BigNumberVizProps } from '../types';
import { BRAND_COLOR } from '../utils';

const defaultNumberFormatter = getNumberFormatter();

const PROPORTION = {
  // text size: proportion of the chart container sans trendline
  KICKER: 0.1,
  HEADER: 0.125,
  SUBHEADER: 0.125,
  // trendline size: proportion of the whole chart container
  TRENDLINE: 0.3,
};

class BigNumberVis extends React.PureComponent<BigNumberVizProps> {
  static defaultProps = {
    className: '',
    headerFormatter: defaultNumberFormatter,
    formatTime: createSmartDateVerboseFormatter(),
    headerFontSize: PROPORTION.HEADER,
    kickerFontSize: PROPORTION.KICKER,
    mainColor: BRAND_COLOR,
    showTimestamp: false,
    showTrendLine: false,
    startYAxisAtZero: true,
    subheader: '',
    unit: '',
    subheaderFontSize: PROPORTION.SUBHEADER,
    timeRangeFixed: false,
    chartTitle: '',
    subheaderColor: '',
    headerColor: '',
  };

  containerRef = React.createRef<HTMLDivElement>();

  getClassName() {
    const { className, showTrendLine, bigNumberFallback } = this.props;
    const fallbackClass = bigNumberFallback ? 'is-fallback-value' : '';
    const names = `superset-legacy-chart-big-number ${className} ${fallbackClass}`;
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
      typeof timestamp === 'boolean'
    )
      return null;
    const text = timestamp === null ? '' :
      typeof timestamp === 'bigint' ? formatTime(Number(timestamp)) : formatTime(timestamp);
    const container = this.createTemporaryContainer();
    document.body.append(container);
    const fontSize = computeMaxFontSize({
      text,
      maxWidth: width,
      maxHeight,
      className: 'kicker',
      container,
    });
    container.remove();
    return (
      <div
        className="kicker"
        style={{
          fontSize,

          height: maxHeight,
        }}
      >
        {text}
      </div>
    );
  }

  componentDidMount() {
    this.applyHeightToParents();
  }

  applyHeightToParents() {
    if (!this.containerRef.current) return;

    // Start from the component's DOM element
    let element: HTMLElement = this.containerRef.current;
    let chartSliceParent: HTMLElement | null = null;

    // First, traverse up to find the chart-slice container
    while (element.parentElement) {
      element = element.parentElement;
      if (element.tagName === 'DIV') {

        if (element.classList.contains('slice_container')) {
          element.style.height = '100%';
        }

        if (element.classList.contains('chart-slice')) {
          chartSliceParent = element;
          element.style.flexDirection = 'row-reverse';
          element.style.alignItems = 'flex-start';
          element.style.justifyContent = 'space-between';
          element.style.height = '100%';
        }

        if (element.classList.contains('dashboard-component')) {
          break;
        }
      }
    }

    // Now find the header-title sibling within the chart-slice container
    if (chartSliceParent) {
      // Find all direct children with class 'header-title'
      const headerTitleNode = chartSliceParent.firstChild?.firstChild;
      const dashboardComponentNode = chartSliceParent.lastChild;

      if (headerTitleNode && headerTitleNode instanceof HTMLElement) {
        console.log('Found header-title element as sibling');
        headerTitleNode.style.display = 'none';
      }

      if (dashboardComponentNode && dashboardComponentNode instanceof HTMLElement) {
        console.log('Found dashboard-component element as sibling');
        dashboardComponentNode.style.height = '100%';
      }

      // Make the slice_container (if present) 100% height
      const sliceContainer = chartSliceParent.closest('.slice_container');
      if (sliceContainer) {
        console.log('Found slice_container, setting height: 100%');
        (sliceContainer as HTMLElement).style.height = '100%';
      }
    }
  }

  renderHeader() {
    const { bigNumber, headerFontSize, width, mainColor, headerFormatter } = this.props;
    // @ts-ignore
    const text =
      bigNumber === null
        ? t('No data')
        : typeof bigNumber === 'number'
          ? headerFormatter(bigNumber).toString()
          : bigNumber ? bigNumber.toString() : t('No data');
    const container = this.createTemporaryContainer();
    document.body.append(container);
    container.remove();

    const onContextMenu = (e: MouseEvent<HTMLDivElement>) => {
      if (this.props.onContextMenu) {
        e.preventDefault();
        this.props.onContextMenu(e.nativeEvent.clientX, e.nativeEvent.clientY);
      }
    };

    const fontSize = computeMaxFontSize({
      text: text.charAt(0),
      maxWidth: width - 8, // Decrease 8px for more precise font size
      idealFontSize: 200 * headerFontSize,
      className: 'header-line',
      container,
    });

    return (
      <div
        className="header-line"
        style={{
          fontSize,
          color: mainColor,
        }}
        onContextMenu={onContextMenu}
      >
        {text}
      </div>
    );
  }

  renderSubheader() {
    const { bigNumber, subheader, width, bigNumberFallback, subheaderColor } =
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
      fontSize = computeMaxFontSize({
        text,
        maxWidth: width,
        idealFontSize: 200 * this.props.subheaderFontSize,
        className: 'subheader-line',
        container,
      });
      container.remove();
      return (
        <div
          className="subheader-line"
          style={{
            fontSize,
            color: subheaderColor,
          }}
        >
          {text}
        </div>
      );
    }
    return null;
  }

  render() {
    const { mainHeaderColor, subheader } =
      this.props;
    const className = this.getClassName();
    
    // Determine if subheader exists
    const hasSubheader = !!subheader;
    
    // Calculate proportional heights based on content
    const headerRatio = hasSubheader ? 0.7 : 1.0; // 70% if subheader exists, 100% otherwise
    const subheaderRatio = hasSubheader ? 0.3 : 0; // 30% if subheader exists, 0 otherwise
    
    return (
      <div
        className={className}
        ref={this.containerRef}
        style={{
          height: "100%", // Use full height instead of height/2
          width: "100%",
          backgroundColor: mainHeaderColor,
          borderRadius: '5px',
          display: "flex",
          flexDirection: "column",
        }}
      >
        {this.renderFallbackWarning()}
        <div style={{ height: `${headerRatio * 100}%`, width: "100%" }}>
          {this.renderHeader()}
        </div>
        {hasSubheader && (
          <div style={{ height: `${subheaderRatio * 100}%`, width: "100%" }}>
            {this.renderSubheader()}
          </div>
        )}
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

    .header-line {
      position: relative;
      line-height: 1em;
      span {
        position: absolute;
        bottom: 0;
      }
    }

    .subheader-line {
      line-height: 1em;
      padding-bottom: 0;
    }

    &.is-fallback-value {
      .kicker,
      .header-line,
      .subheader-line {
        opacity: ${theme.opacity.mediumHeavy};
      }
    }
  `}
`;
