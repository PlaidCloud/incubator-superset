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
  Children,
  cloneElement,
  useRef,
  useMemo,
  useLayoutEffect,
  useCallback,
  ReactNode,
  ReactElement,
  ComponentPropsWithRef,
  CSSProperties,
  UIEventHandler,
  useState,
} from 'react';
import getScrollBarSize from '../utils/getScrollBarSize';
import needScrollBar from '../utils/needScrollBar';
import useMountedMemo from '../utils/useMountedMemo';

type ReactElementWithChildren<
  T extends keyof JSX.IntrinsicElements,
  C extends ReactNode = ReactNode,
> = ReactElement<ComponentPropsWithRef<T> & { children: C }, T>;

type Th = ReactElementWithChildren<'th'>;
type Td = ReactElementWithChildren<'td'>;
type TrWithTh = ReactElementWithChildren<'tr', Th[]>;
type TrWithTd = ReactElementWithChildren<'tr', Td[]>;
type Thead = ReactElementWithChildren<'thead', TrWithTh>;
type Tbody = ReactElementWithChildren<'tbody', TrWithTd>;
type Tfoot = ReactElementWithChildren<'tfoot', TrWithTd>;
type Col = ReactElementWithChildren<'col', null>;
type ColGroup = ReactElementWithChildren<'colgroup', Col>;

export type Table = ReactElementWithChildren<
  'table',
  (Thead | Tbody | Tfoot | ColGroup)[]
>;
export type TableRenderer = () => Table;
export type GetTableSize = () => Partial<StickyState> | undefined;
export type SetStickyState = (size?: Partial<StickyState>) => void;

export type ColumnWidths = number[];

export interface StickyState {
  width?: number; // maximum full table width
  height?: number; // maximum full table height
  realHeight?: number; // actual table viewport height (header + scrollable area)
  bodyHeight?: number; // scrollable area height
  tableHeight?: number; // the full table height
  columnWidths?: ColumnWidths;
  hasHorizontalScroll?: boolean;
  hasVerticalScroll?: boolean;
  rendering?: boolean;
  setStickyState?: SetStickyState;
}

export interface UseStickyTableOptions {
  getTableSize?: GetTableSize;
}

const sum = (a: number, b: number) => a + b;
const mergeStyleProp = (
  node: ReactElement<{ style?: CSSProperties }>,
  style: CSSProperties,
) => ({
  style: {
    ...node.props.style,
    ...style,
  },
});
const fixedTableLayout: CSSProperties = { tableLayout: 'fixed' };

/**
 * An HOC for generating sticky header and fixed-height scrollable area
 */
function StickyWrap({
  sticky = {},
  width: maxWidth,
  height: maxHeight,
  children: table,
  setStickyState,
}: {
  width: number;
  height: number;
  setStickyState: SetStickyState;
  children: Table;
  sticky?: StickyState; // current sticky element sizes
}) {
  if (!table || table.type !== 'table') {
    throw new Error('<StickyWrap> must have only one <table> element as child');
  }
  let thead: Thead | undefined;
  let tbody: Tbody | undefined;
  let tfoot: Tfoot | undefined;

  Children.forEach(table.props.children, node => {
    if (!node) {
      return;
    }
    if (node.type === 'thead') {
      thead = node;
    } else if (node.type === 'tbody') {
      tbody = node;
    } else if (node.type === 'tfoot') {
      tfoot = node;
    }
  });
  if (!thead || !tbody) {
    throw new Error(
      '<table> in <StickyWrap> must contain both thead and tbody.',
    );
  }
  const columnCount = useMemo(() => {
    const headerRows = Children.toArray(
      thead?.props.children,
    ).pop() as TrWithTh;
    return headerRows.props.children.length;
  }, [thead]);

  const theadRef = useRef<HTMLTableSectionElement>(null); // original thead for layout computation
  const tfootRef = useRef<HTMLTableSectionElement>(null); // original tfoot for layout computation
  const scrollHeaderRef = useRef<HTMLDivElement>(null); // fixed header
  const scrollFooterRef = useRef<HTMLDivElement>(null); // fixed footer
  const scrollBodyRef = useRef<HTMLDivElement>(null); // main body

  const scrollBarSize = getScrollBarSize();
  const { bodyHeight, columnWidths } = sticky;
  const needSizer =
    !columnWidths ||
    sticky.width !== maxWidth ||
    sticky.height !== maxHeight ||
    sticky.setStickyState !== setStickyState;

  // update scrollable area and header column sizes when mounted
  useLayoutEffect(() => {
    if (!theadRef.current) {
      return;
    }
    const bodyThead = theadRef.current;
    const theadHeight = bodyThead.clientHeight;
    const tfootHeight = tfootRef.current ? tfootRef.current.clientHeight : 0;
    if (!theadHeight) {
      return;
    }
    const fullTableHeight = (bodyThead.parentNode as HTMLTableElement)
      .clientHeight;
    // instead of always using the first tr, we use the last one to support
    // multi-level headers assuming the last one is the more detailed one
    const ths = bodyThead.childNodes?.[bodyThead.childNodes?.length - 1 || 0]
      .childNodes as NodeListOf<HTMLTableHeaderCellElement>;
    const widths = Array.from(ths).map(
      th => th.getBoundingClientRect()?.width || th.clientWidth,
    );
    const [hasVerticalScroll, hasHorizontalScroll] = needScrollBar({
      width: maxWidth,
      height: maxHeight - theadHeight - tfootHeight,
      innerHeight: fullTableHeight,
      innerWidth: widths.reduce(sum),
      scrollBarSize,
    });
    // real container height, include table header, footer and space for
    // horizontal scroll bar
    const realHeight = Math.min(
      maxHeight,
      hasHorizontalScroll ? fullTableHeight + scrollBarSize : fullTableHeight,
    );
    setStickyState({
      hasVerticalScroll,
      hasHorizontalScroll,
      setStickyState,
      width: maxWidth,
      height: maxHeight,
      realHeight,
      tableHeight: fullTableHeight,
      bodyHeight: realHeight - theadHeight - tfootHeight,
      columnWidths: widths,
    });
  }, [maxWidth, maxHeight, setStickyState, scrollBarSize]);

  let sizerTable: ReactElement | undefined;
  let headerTable: ReactElement | undefined;
  let footerTable: ReactElement | undefined;
  let bodyTable: ReactElement | undefined;

  if (needSizer) {
    const theadWithRef = cloneElement(thead, { ref: theadRef });
    const tfootWithRef = tfoot && cloneElement(tfoot, { ref: tfootRef });
    sizerTable = (
      <div
        key="sizer"
        style={{
          height: maxHeight,
          overflow: 'auto',
          visibility: 'hidden',
          scrollbarGutter: 'stable',
        }}
        role="presentation"
      >
        {cloneElement(
          table,
          { role: 'presentation' },
          theadWithRef,
          tbody,
          tfootWithRef,
        )}
      </div>
    );
  }

  // reuse previously column widths, will be updated by `useLayoutEffect` above
  const colWidths = columnWidths?.slice(0, columnCount);

  if (colWidths && bodyHeight) {
    const colgroup = (
      <colgroup>
        {colWidths.map((w, i) => (
          // eslint-disable-next-line react/no-array-index-key
          <col key={i} width={w} />
        ))}
      </colgroup>
    );

    headerTable = (
      <div
        key="header"
        ref={scrollHeaderRef}
        style={{
          overflow: 'hidden',
          scrollbarGutter: 'stable',
        }}
        role="presentation"
      >
        {cloneElement(
          cloneElement(table, { role: 'presentation' }),
          mergeStyleProp(table, fixedTableLayout),
          colgroup,
          thead,
        )}
      </div>
    );

    footerTable = tfoot && (
      <div
        key="footer"
        ref={scrollFooterRef}
        style={{
          overflow: 'hidden',
          scrollbarGutter: 'stable',
        }}
        role="presentation"
      >
        {cloneElement(
          cloneElement(table, { role: 'presentation' }),
          mergeStyleProp(table, fixedTableLayout),
          colgroup,
          tfoot,
        )}
      </div>
    );

    const onScroll: UIEventHandler<HTMLDivElement> = e => {
      if (scrollHeaderRef.current) {
        scrollHeaderRef.current.scrollLeft = e.currentTarget.scrollLeft;
      }
      if (scrollFooterRef.current) {
        scrollFooterRef.current.scrollLeft = e.currentTarget.scrollLeft;
      }
    };
    bodyTable = (
      <div
        key="body"
        ref={scrollBodyRef}
        style={{
          height: bodyHeight,
          overflow: 'auto',
          scrollbarGutter: 'stable',
        }}
        onScroll={sticky.hasHorizontalScroll ? onScroll : undefined}
        role="presentation"
      >
        {cloneElement(
          cloneElement(table, { role: 'presentation' }),
          mergeStyleProp(table, fixedTableLayout),
          colgroup,
          tbody,
        )}
      </div>
    );
  }

  return (
    <div
      style={{
        width: maxWidth,
        height: sticky.realHeight || maxHeight,
        overflow: 'hidden',
      }}
      role="table"
    >
      {headerTable}
      {bodyTable}
      {footerTable}
      {sizerTable}
    </div>
  );
}

/**
 * Hook to manage sticky table state for TanStack Table v8
 * Returns a wrapper function and state setter for use with table rendering
 */
export function useSticky(getTableSize?: GetTableSize): {
  sticky: StickyState;
  setStickyState: SetStickyState;
  useStickyTable: (renderer: TableRenderer) => ReactNode;
} {
  const [sticky, setStickyStateInternal] = useState<StickyState>({});

  const setStickyState = useCallback((size?: Partial<StickyState>) => {
    setStickyStateInternal(prevState => ({
      ...prevState,
      ...size,
    }));
  }, []);

  const tableSizeFromHook = useMountedMemo(
    getTableSize ? () => getTableSize() : () => undefined,
    [getTableSize],
  );

  const useStickyTable = (renderer: TableRenderer) => {
    const { width, height }: { width?: number; height?: number } =
      tableSizeFromHook || sticky;
    const table = useMemo(renderer, [renderer]);

    useLayoutEffect(() => {
      if (!width || !height) {
        setStickyState();
      }
    }, [width, height]);

    if (!width || !height) {
      return null;
    }
    return (
      <StickyWrap
        width={width}
        height={height}
        sticky={sticky}
        setStickyState={setStickyState}
      >
        {table}
      </StickyWrap>
    );
  };

  return {
    sticky,
    setStickyState,
    useStickyTable,
  };
}

export default useSticky;
