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
import '@testing-library/jest-dom';
import { fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider, supersetTheme } from '@apache-superset/core/theme';
import TableChart from '../src/TableChart';
import transformProps from '../src/transformProps';
import DateWithFormatter from '../src/utils/DateWithFormatter';
import testData from './testData';
import { ProviderWrapper } from './testHelpers';

describe('plugin-chart-table', () => {
  describe('transformProps', () => {
    test('should parse pageLength to pageSize', () => {
      expect(transformProps(testData.basic).pageSize).toBe(20);
      expect(
        transformProps({
          ...testData.basic,
          rawFormData: { ...testData.basic.rawFormData, page_length: '20' },
        }).pageSize,
      ).toBe(20);
      expect(
        transformProps({
          ...testData.basic,
          rawFormData: { ...testData.basic.rawFormData, page_length: '' },
        }).pageSize,
      ).toBe(0);
    });

    test('should memoize data records', () => {
      expect(transformProps(testData.basic).data).toBe(
        transformProps(testData.basic).data,
      );
    });

    test('should memoize columns meta', () => {
      expect(transformProps(testData.basic).columns).toBe(
        transformProps({
          ...testData.basic,
          rawFormData: { ...testData.basic.rawFormData, pageLength: null },
        }).columns,
      );
    });

    test('should format timestamp', () => {
      // eslint-disable-next-line no-underscore-dangle
      const parsedDate = transformProps(testData.basic).data[0]
        .__timestamp as DateWithFormatter;
      expect(String(parsedDate)).toBe('2020-01-01 12:34:56');
      expect(parsedDate.getTime()).toBe(1577882096000);
    });
    test('should process comparison columns when time_compare and comparison_type are set', () => {
      const transformedProps = transformProps(testData.comparison);

      // Check if comparison columns are processed
      const comparisonColumns = transformedProps.columns.filter(
        col =>
          col.label === 'Main' ||
          col.label === '#' ||
          col.label === '△' ||
          col.label === '%',
      );

      expect(comparisonColumns.length).toBeGreaterThan(0);
      expect(comparisonColumns.some(col => col.label === 'Main')).toBe(true);
      expect(comparisonColumns.some(col => col.label === '#')).toBe(true);
      expect(comparisonColumns.some(col => col.label === '△')).toBe(true);
      expect(comparisonColumns.some(col => col.label === '%')).toBe(true);
    });

    test('should not process comparison columns when time_compare is empty', () => {
      const propsWithoutTimeCompare = {
        ...testData.comparison,
        rawFormData: {
          ...testData.comparison.rawFormData,
          time_compare: [],
        },
      };

      const transformedProps = transformProps(propsWithoutTimeCompare);

      // Check if comparison columns are not processed
      const comparisonColumns = transformedProps.columns.filter(
        col =>
          col.label === 'Main' ||
          col.label === '#' ||
          col.label === '△' ||
          col.label === '%',
      );

      expect(comparisonColumns.length).toBe(0);
    });

    test('should correctly apply column configuration for comparison columns', () => {
      const transformedProps = transformProps(testData.comparisonWithConfig);

      const comparisonColumns = transformedProps.columns.filter(
        col =>
          col.key.startsWith('Main') ||
          col.key.startsWith('#') ||
          col.key.startsWith('△') ||
          col.key.startsWith('%'),
      );

      expect(comparisonColumns).toHaveLength(4);

      const mainMetricConfig = comparisonColumns.find(
        col => col.key === 'Main metric_1',
      );
      expect(mainMetricConfig).toBeDefined();
      expect(mainMetricConfig?.config).toEqual({ d3NumberFormat: '.2f' });

      const hashMetricConfig = comparisonColumns.find(
        col => col.key === '# metric_1',
      );
      expect(hashMetricConfig).toBeDefined();
      expect(hashMetricConfig?.config).toEqual({ d3NumberFormat: '.1f' });

      const deltaMetricConfig = comparisonColumns.find(
        col => col.key === '△ metric_1',
      );
      expect(deltaMetricConfig).toBeDefined();
      expect(deltaMetricConfig?.config).toEqual({ d3NumberFormat: '.0f' });

      const percentMetricConfig = comparisonColumns.find(
        col => col.key === '% metric_1',
      );
      expect(percentMetricConfig).toBeDefined();
      expect(percentMetricConfig?.config).toEqual({ d3NumberFormat: '.3f' });
    });

    test('should correctly format comparison columns using getComparisonColFormatter', () => {
      const transformedProps = transformProps(testData.comparisonWithConfig);
      const comparisonColumns = transformedProps.columns.filter(
        col =>
          col.key.startsWith('Main') ||
          col.key.startsWith('#') ||
          col.key.startsWith('△') ||
          col.key.startsWith('%'),
      );

      const formattedMainMetric = comparisonColumns
        .find(col => col.key === 'Main metric_1')
        ?.formatter?.(12345.678);
      expect(formattedMainMetric).toBe('12345.68');

      const formattedHashMetric = comparisonColumns
        .find(col => col.key === '# metric_1')
        ?.formatter?.(12345.678);
      expect(formattedHashMetric).toBe('12345.7');

      const formattedDeltaMetric = comparisonColumns
        .find(col => col.key === '△ metric_1')
        ?.formatter?.(12345.678);
      expect(formattedDeltaMetric).toBe('12346');

      const formattedPercentMetric = comparisonColumns
        .find(col => col.key === '% metric_1')
        ?.formatter?.(0.123456);
      expect(formattedPercentMetric).toBe('0.123');
    });

    test('should set originalLabel for comparison columns when time_compare and comparison_type are set', () => {
      const transformedProps = transformProps(testData.comparison);

      // Check if comparison columns are processed
      const comparisonColumns = transformedProps.columns.filter(
        col =>
          col.label === 'Main' ||
          col.label === '#' ||
          col.label === '△' ||
          col.label === '%',
      );

      expect(comparisonColumns.length).toBeGreaterThan(0);
      expect(comparisonColumns.some(col => col.label === 'Main')).toBe(true);
      expect(comparisonColumns.some(col => col.label === '#')).toBe(true);
      expect(comparisonColumns.some(col => col.label === '△')).toBe(true);
      expect(comparisonColumns.some(col => col.label === '%')).toBe(true);

      // Verify originalLabel for metric_1 comparison columns
      const mainMetric1 = transformedProps.columns.find(
        col => col.key === 'Main metric_1',
      );
      expect(mainMetric1).toBeDefined();
      expect(mainMetric1?.originalLabel).toBe('metric_1');

      const hashMetric1 = transformedProps.columns.find(
        col => col.key === '# metric_1',
      );
      expect(hashMetric1).toBeDefined();
      expect(hashMetric1?.originalLabel).toBe('metric_1');

      const deltaMetric1 = transformedProps.columns.find(
        col => col.key === '△ metric_1',
      );
      expect(deltaMetric1).toBeDefined();
      expect(deltaMetric1?.originalLabel).toBe('metric_1');

      const percentMetric1 = transformedProps.columns.find(
        col => col.key === '% metric_1',
      );
      expect(percentMetric1).toBeDefined();
      expect(percentMetric1?.originalLabel).toBe('metric_1');

      // Verify originalLabel for metric_2 comparison columns
      const mainMetric2 = transformedProps.columns.find(
        col => col.key === 'Main metric_2',
      );
      expect(mainMetric2).toBeDefined();
      expect(mainMetric2?.originalLabel).toBe('metric_2');

      const hashMetric2 = transformedProps.columns.find(
        col => col.key === '# metric_2',
      );
      expect(hashMetric2).toBeDefined();
      expect(hashMetric2?.originalLabel).toBe('metric_2');

      const deltaMetric2 = transformedProps.columns.find(
        col => col.key === '△ metric_2',
      );
      expect(deltaMetric2).toBeDefined();
      expect(deltaMetric2?.originalLabel).toBe('metric_2');

      const percentMetric2 = transformedProps.columns.find(
        col => col.key === '% metric_2',
      );
      expect(percentMetric2).toBeDefined();
      expect(percentMetric2?.originalLabel).toBe('metric_2');
    });
  });

  describe('TableChart', () => {
    test('render basic data', () => {
      render(
        <ThemeProvider theme={supersetTheme}>
          <TableChart {...transformProps(testData.basic)} sticky={false} />,
        </ThemeProvider>,
      );

      const firstDataRow = screen.getAllByRole('rowgroup')[1];
      const cells = firstDataRow.querySelectorAll('td');
      expect(cells).toHaveLength(12);
      expect(cells[0]).toHaveTextContent('2020-01-01 12:34:56');
      expect(cells[1]).toHaveTextContent('Michael');
      // number is not in `metrics` list, so it should output raw value
      // (in real world Superset, this would mean the column is used in GROUP BY)
      expect(cells[2]).toHaveTextContent('2467063');
      // should not render column with `.` in name as `undefined`
      expect(cells[3]).toHaveTextContent('foo');
      expect(cells[6]).toHaveTextContent('2467');
      expect(cells[8]).toHaveTextContent('N/A');
    });

    test('render advanced data', () => {
      render(
        <ThemeProvider theme={supersetTheme}>
          <TableChart {...transformProps(testData.advanced)} sticky={false} />,
        </ThemeProvider>,
      );
      const secondColumnHeader = screen.getByText('Sum of Num');
      expect(secondColumnHeader).toBeInTheDocument();
      expect(secondColumnHeader?.getAttribute('data-column-name')).toEqual('1');

      const firstDataRow = screen.getAllByRole('rowgroup')[1];
      const cells = firstDataRow.querySelectorAll('td');
      expect(cells[0]).toHaveTextContent('Michael');
      expect(cells[2]).toHaveTextContent('12.346%');
      expect(cells[4]).toHaveTextContent('2.47k');
    });

    // `th[1]` is the second column. It only reads that way because the header
    // no longer nests (sc-25372); while it did, `th[1]` was column 0's inner
    // header and this asserted 'name'.
    test('render advanced data with currencies', () => {
      render(
        ProviderWrapper({
          children: (
            <TableChart
              {...transformProps(testData.advancedWithCurrency)}
              sticky={false}
            />
          ),
        }),
      );
      const cells = document.querySelectorAll('td');
      expect(document.querySelectorAll('th')[1]).toHaveTextContent(
        'Sum of Num',
      );
      expect(cells[0]).toHaveTextContent('Michael');
      expect(cells[2]).toHaveTextContent('12.346%');
      expect(cells[4]).toHaveTextContent('$ 2.47k');
    });

    test('render data with a bigint value in a raw record mode', () => {
      render(
        ProviderWrapper({
          children: (
            <TableChart
              {...transformProps(testData.bigint)}
              sticky={false}
              isRawRecords
            />
          ),
        }),
      );
      const cells = document.querySelectorAll('td');
      expect(document.querySelectorAll('th')[0]).toHaveTextContent('name');
      expect(document.querySelectorAll('th')[1]).toHaveTextContent('id');
      expect(cells[0]).toHaveTextContent('Michael');
      expect(cells[1]).toHaveTextContent('4312');
      expect(cells[2]).toHaveTextContent('John');
      expect(cells[3]).toHaveTextContent('1234567890123456789');
    });

    test('render raw data', () => {
      const props = transformProps({
        ...testData.raw,
        rawFormData: { ...testData.raw.rawFormData },
      });
      render(
        ProviderWrapper({
          children: <TableChart {...props} sticky={false} />,
        }),
      );
      const cells = document.querySelectorAll('td');
      expect(document.querySelectorAll('th')[0]).toHaveTextContent('num');
      expect(cells[0]).toHaveTextContent('1234');
      expect(cells[1]).toHaveTextContent('10000');
      expect(cells[1]).toHaveTextContent('0');
    });

    test('render raw data with currencies', () => {
      const props = transformProps({
        ...testData.raw,
        rawFormData: {
          ...testData.raw.rawFormData,
          column_config: {
            num: {
              currencyFormat: { symbol: 'USD', symbolPosition: 'prefix' },
            },
          },
        },
      });
      render(
        ProviderWrapper({
          children: <TableChart {...props} sticky={false} />,
        }),
      );
      const cells = document.querySelectorAll('td');

      expect(document.querySelectorAll('th')[0]).toHaveTextContent('num');
      expect(cells[0]).toHaveTextContent('$ 1.23k');
      expect(cells[1]).toHaveTextContent('$ 10k');
      expect(cells[2]).toHaveTextContent('$ 0');
    });

    test('render small formatted data with currencies', () => {
      const props = transformProps({
        ...testData.raw,
        rawFormData: {
          ...testData.raw.rawFormData,
          column_config: {
            num: {
              d3SmallNumberFormat: '.2r',
              currencyFormat: { symbol: 'USD', symbolPosition: 'prefix' },
            },
          },
        },
        queriesData: [
          {
            ...testData.raw.queriesData[0],
            data: [
              {
                num: 1234,
              },
              {
                num: 0.5,
              },
              {
                num: 0.61234,
              },
            ],
          },
        ],
      });
      render(
        ProviderWrapper({
          children: <TableChart {...props} sticky={false} />,
        }),
      );
      const cells = document.querySelectorAll('td');

      expect(document.querySelectorAll('th')[0]).toHaveTextContent('num');
      expect(cells[0]).toHaveTextContent('$ 1.23k');
      expect(cells[1]).toHaveTextContent('$ 0.50');
      expect(cells[2]).toHaveTextContent('$ 0.61');
    });

    test('render empty data', () => {
      render(
        <ThemeProvider theme={supersetTheme}>
          <TableChart {...transformProps(testData.empty)} sticky={false} />,
        </ThemeProvider>,
      );
      expect(screen.getByText('No records found')).toBeInTheDocument();
    });

    test('render color with column color formatter', () => {
      render(
        ProviderWrapper({
          children: (
            <TableChart
              {...transformProps({
                ...testData.advanced,
                rawFormData: {
                  ...testData.advanced.rawFormData,
                  conditional_formatting: [
                    {
                      colorScheme: '#ACE1C4',
                      column: 'sum__num',
                      operator: '>',
                      targetValue: 2467,
                    },
                  ],
                },
              })}
            />
          ),
        }),
      );

      expect(getComputedStyle(screen.getByTitle('2467063')).background).toBe(
        'rgba(172, 225, 196, 1)',
      );
      expect(getComputedStyle(screen.getByTitle('2467')).background).toBe('');
    });

    test('render cell without color', () => {
      const dataWithEmptyCell = testData.advanced.queriesData[0];
      dataWithEmptyCell.data.push({
        __timestamp: null,
        name: 'Noah',
        sum__num: null,
        '%pct_nice': 0.643,
        'abc.com': 'bazzinga',
      });

      render(
        ProviderWrapper({
          children: (
            <TableChart
              {...transformProps({
                ...testData.advanced,
                queriesData: [dataWithEmptyCell],
                rawFormData: {
                  ...testData.advanced.rawFormData,
                  conditional_formatting: [
                    {
                      colorScheme: '#ACE1C4',
                      column: 'sum__num',
                      operator: '<',
                      targetValue: 12342,
                    },
                  ],
                },
              })}
            />
          ),
        }),
      );
      expect(getComputedStyle(screen.getByTitle('2467')).background).toBe(
        'rgba(172, 225, 196, 0.812)',
      );
      expect(getComputedStyle(screen.getByTitle('2467063')).background).toBe(
        '',
      );
      expect(getComputedStyle(screen.getByText('N/A')).background).toBe('');
    });
    test('should display originalLabel in grouped headers', () => {
      render(
        <ThemeProvider theme={supersetTheme}>
          <TableChart {...transformProps(testData.comparison)} sticky={false} />
        </ThemeProvider>,
      );

      const groupHeaders = screen.getAllByRole('columnheader');
      expect(groupHeaders[0]).toHaveTextContent('metric_1');
      expect(groupHeaders[1]).toHaveTextContent('metric_2');
    });
  });

  // `testData.basic`, and the column is looked up by key rather than by index.
  // Both matter, because `valueRange` is gated on
  // `(isMetric || isRawRecords || isPercentMetric)` (TableChart.tsx):
  //   - under `testData.raw`, `isRawRecords` alone satisfies it, so setting
  //     `isMetric` changes nothing;
  //   - under `testData.advanced`, `sum__num` is already a metric and
  //     `%pct_nice` already a percent metric, so bars appear from columns the
  //     test never touches - and its `columns[0]` is `name`, which is not
  //     numeric and produces no bar either way.
  // `basic` is the only fixture with a numeric, non-metric column and
  // `isRawRecords` false, so here the flag is what decides.
  const cellBarProps = (mutate: (column: any, props: any) => void) => {
    const props = transformProps({
      ...testData.basic,
      rawFormData: { ...testData.basic.rawFormData },
    });
    const column = props.columns.find((c: any) => c.key === 'sum__num');
    expect(column).toBeDefined();
    // `transformProps` hands back the *same* column objects on every call
    // (verified: identity holds across two calls), so a flag set by one case
    // leaks into the next and makes the following mutation inert. Reset before
    // mutating so each case stands on its own.
    column.isMetric = false;
    column.isPercentMetric = false;
    mutate(column, props);
    return props;
  };

  test('renders cell bars for metric and percent-metric columns, and only when toggled on', () => {
    // Scoped to each render's own container: the original queried `document`
    // and accumulated earlier renders. The emotion class hash this test used to
    // pin is gone (sc-25404) - it changed whenever `StyledCell` changed and
    // never expressed the behaviour, which is the cell bars themselves.
    const renderWith = (mutate: (column: any, props: any) => void) =>
      render(
        ProviderWrapper({
          children: <TableChart {...cellBarProps(mutate)} sticky={false} />,
        }),
      ).container;

    // Baseline first: neither flag set, so nothing satisfies the gate. Without
    // this the three cases below cannot tell "the flag turned bars on" from
    // "bars were on anyway".
    const neither = renderWith(() => {});
    expect(neither.querySelectorAll('div.cell-bar')).toHaveLength(0);

    const asMetric = renderWith(column => {
      column.isMetric = true;
    });
    expect(asMetric.querySelectorAll('div.cell-bar').length).toBeGreaterThan(0);
    asMetric
      .querySelectorAll('div.cell-bar')
      .forEach(cell => expect(cell).toHaveClass('positive'));

    const asPercentMetric = renderWith(column => {
      column.isPercentMetric = true;
    });
    expect(
      asPercentMetric.querySelectorAll('div.cell-bar').length,
    ).toBeGreaterThan(0);
    asPercentMetric
      .querySelectorAll('div.cell-bar')
      .forEach(cell => expect(cell).toHaveClass('positive'));

    const toggledOff = renderWith((column, props) => {
      column.isMetric = true;
      props.showCellBars = false;
    });
    expect(toggledOff.querySelectorAll('div.cell-bar')).toHaveLength(0);
  });

  // `row_grouping` puts the table in aggregate mode: group rows are depth 0 and
  // render immediately, and on a group row every non-grouping column is
  // aggregated - the one branch no other fixture reaches. Expanding a group is
  // what reaches depth > 0 and the placeholder branch.
  const groupedFixture = () => ({
    ...testData.basic,
    rawFormData: {
      ...testData.basic.rawFormData,
      row_grouping: ['name'],
    },
  });

  test('never renders a cell inside another cell, in body or footer (sc-25312)', () => {
    // `comparison` carries show_totals, so this exercises the footer too.
    const { container } = render(
      ProviderWrapper({
        children: (
          <TableChart {...transformProps(testData.comparison)} sticky={false} />
        ),
      }),
    );

    expect(container.querySelector('tfoot')).toBeInTheDocument();
    expect(
      [...container.querySelectorAll('td td, td th, th td, th th')].map(
        el => `${el.parentElement?.tagName}>${el.tagName}`,
      ),
    ).toEqual([]);
  });

  test('every body row keeps one element cell per column, grouped rows included (sc-25312)', () => {
    // Asserting *shape* rather than nesting, because a cell that disappears
    // entirely passes a nesting-only assertion. `row_grouping` puts the table in
    // aggregate mode: group rows are depth 0 and render immediately, and on a
    // group row every non-grouping column is aggregated - the one branch no
    // other fixture reaches.
    const { container } = render(
      ProviderWrapper({
        children: (
          <TableChart {...transformProps(groupedFixture())} sticky={false} />
        ),
      }),
    );

    // Direct children only: the header still nests `th` inside `th`
    // (sc-25372), so a descendant selector counts every column twice.
    const headerCount = container.querySelectorAll(
      'thead tr:last-of-type > th',
    ).length;
    expect(headerCount).toBeGreaterThan(0);

    const rows = [...container.querySelectorAll('tbody tr')];
    expect(rows.length).toBeGreaterThan(0);

    rows.forEach(tr => {
      expect(tr.children).toHaveLength(headerCount);
      expect(
        [...tr.childNodes].every(n => n.nodeType === Node.ELEMENT_NODE),
      ).toBe(true);
    });
  });

  test('the header row keeps one element cell per column (sc-25372)', () => {
    // Same shape assertion as the body gate, and for the same reason: nesting
    // is only half the defect. Unwrapping a cell that carries behaviour the
    // inner element does not can make the cell vanish instead, which a
    // nesting-only assertion passes. The invariant that catches both is that
    // the header row and a body row describe the same number of columns.
    const { container } = render(
      ProviderWrapper({
        children: (
          <TableChart {...transformProps(testData.basic)} sticky={false} />
        ),
      }),
    );

    const headerCells = container.querySelectorAll('thead tr:last-of-type > *');
    const bodyCells = container.querySelectorAll('tbody tr:first-of-type > *');

    expect(bodyCells.length).toBeGreaterThan(0);
    expect(headerCells).toHaveLength(bodyCells.length);

    // `> *` counts elements; `childNodes` counts text too. Equal lengths is
    // what rules out a renderer's bare string landing straight in the `tr`.
    const headerNodes =
      container.querySelector('thead tr:last-of-type')?.childNodes ?? [];
    expect([...headerNodes]).toHaveLength(headerCells.length);
  });

  test('row_grouping actually groups: the expander glyph is rendered (sc-25372)', () => {
    // The discriminator. `testData.basic` has three rows and three distinct
    // `name` values, so a row count is identical grouped or not - if
    // `row_grouping` ever stopped flowing through, every grouped assertion
    // below would quietly degrade into a leaf-row check. Only the expander
    // says grouping applied.
    const { container } = render(
      ProviderWrapper({
        children: (
          <TableChart {...transformProps(groupedFixture())} sticky={false} />
        ),
      }),
    );

    expect(container).toHaveTextContent('▶');
  });

  test('expanding a group indents its sub-rows and keeps the row shape (sc-25372)', () => {
    // Closes the other half of the indent: the stylesheet test proves the rule
    // is emitted, this proves a row can match it. `expandedGroups` starts empty,
    // so without a click nothing in the suite ever reaches `depth > 0` - which
    // also leaves the placeholder branch unexercised, since the grouping column
    // only becomes a placeholder on a sub-row.
    const { container } = render(
      ProviderWrapper({
        children: (
          <TableChart {...transformProps(groupedFixture())} sticky={false} />
        ),
      }),
    );

    expect(container.querySelectorAll('tbody tr[data-depth]')).toHaveLength(0);

    const [expander] = screen.getAllByText('▶');
    fireEvent.click(expander);

    const subRows = container.querySelectorAll('tbody tr[data-depth]');
    expect(subRows.length).toBeGreaterThan(0);
    subRows.forEach(tr => {
      expect(tr.getAttribute('style')).toContain('--dt-row-indent: 20px');
    });

    // The shape invariant has to survive expansion too: on a sub-row the
    // grouping column renders through the placeholder branch.
    const headerCells = container.querySelectorAll('thead tr:last-of-type > *');
    container.querySelectorAll('tbody tr').forEach(tr => {
      expect(tr.children).toHaveLength(headerCells.length);
    });
  });

  test('the grouped-row indent rule ships in the stylesheet (sc-25312)', () => {
    // The indent moved from JS to CSS, so the only thing that can regress
    // silently is the rule not being emitted at all. It has to live somewhere
    // `styled` handles: the `css` prop needs Emotion's jsx factory, which this
    // repo installs through swc only - `babel.config.js` has no `importSource`
    // and there is no `@emotion/babel-preset-css-prop`, so under Jest the prop
    // is inert and the rule never reaches the document.
    render(
      ProviderWrapper({
        children: (
          <TableChart {...transformProps(testData.basic)} sticky={false} />
        ),
      }),
    );

    const cssText = [...document.querySelectorAll('style')]
      .flatMap(el => {
        try {
          return [...(el.sheet?.cssRules ?? [])].map(r => r.cssText);
        } catch {
          return [el.textContent ?? ''];
        }
      })
      .join('\n');

    expect(cssText).toMatch(/tr\[data-depth\][^{]*first-child/);
    expect(cssText).toMatch(/--dt-row-indent/);
  });
});
