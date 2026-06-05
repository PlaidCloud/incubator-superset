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
import { utils, writeFile } from 'xlsx';

/**
 * Export displayed table data (as shown on screen) to CSV format
 * Reads the table elements one by one to capture the displayed data
 * Handles both single-table and virtualized multi-table layouts
 */
export function exportTableAsCSV(
  tableSelector: string,
  fileName: string,
) {
  const container = document.querySelector(tableSelector);
  if (!container) {
    console.warn(`Table not found with selector: ${tableSelector}`);
    return;
  }

  // Extract headers from the first table or from thead
  const headers: string[] = [];
  let headerCells = container.querySelectorAll('thead th, .ant-table-thead th');
  
  // If no thead found, try first table's th elements
  if (headerCells.length === 0) {
    const tables = container.querySelectorAll('table');
    if (tables.length > 0) {
      headerCells = tables[0].querySelectorAll('th');
    }
  }
  
  headerCells.forEach((cell) => {
    // Try to get text from span first (for superset tables), then fallback to textContent
    const span = cell.querySelector('span');
    const headerText = span?.textContent?.trim() || cell.textContent?.trim() || '';
    headers.push(headerText);
  });

  // Extract rows from all tbody elements (handles virtualized tables)
  const rows: (string | number)[][] = [];

  // Get all tables and extract tbody rows from each
  const allTables = container.querySelectorAll('table');

  allTables.forEach((table) => {
    const tbody = table.querySelector('tbody');
    if (tbody) {
      const bodyRows = tbody.querySelectorAll('tr');
      bodyRows.forEach((row) => {
        const rowData: (string | number)[] = [];
        const cells = row.querySelectorAll('td');
        cells.forEach((cell, cellIndex) => {
          // For the first column (metric), preserve indentation
          if (cellIndex === 0) {
            // Check if cell has expand/collapse icon - if so, skip padding
            const hasExpandCollapseIcon = cell.querySelector('span[aria-label="minus-square"], span[aria-label="plus-square"]');
            
            let numSpaces = 0;
            if (!hasExpandCollapseIcon) {
                // Get padding-left from computed style (applied via CSS class)
                const cellElement = cell as HTMLElement;
                const computedStyle = window.getComputedStyle(cellElement);
                const paddingLeft = parseInt(computedStyle.paddingLeft || '0', 10);
                
                // Get default padding from a non-first column cell (no !important override)
                const secondCell = cells[1] as HTMLElement | undefined;
                const defaultPadding = secondCell 
                ? parseInt(window.getComputedStyle(secondCell).paddingLeft || '0', 10)
                : 0;
                
                // Only use the additional padding (the !important override)
                const additionalPadding = paddingLeft - defaultPadding;
                // Convert pixels to spaces (roughly 10px per space for readability)
                numSpaces = additionalPadding > 0 ? Math.round(additionalPadding / 10) : 0;
            }

            // Get text content, excluding SVG icon content
            let cellText = '';
            const walker = document.createTreeWalker(
              cell,
              NodeFilter.SHOW_TEXT,
              null,
            );
            let node: Node | null;
            while ((node = walker.nextNode())) {
              // Skip text inside SVG elements
              let parent = node.parentElement;
              let isInsideSvg = false;
              while (parent && parent !== cell) {
                if (parent.tagName === 'svg' || parent.tagName === 'SVG') {
                  isInsideSvg = true;
                  break;
                }
                parent = parent.parentElement;
              }
              if (!isInsideSvg) {
                cellText += node.textContent || '';
              }
            }
            cellText = cellText.trim();

            // Add spaces prefix based on padding
            const indent = ' '.repeat(numSpaces);
            rowData.push(indent + cellText);
          } else {
            // For data cells, use displayed text content
            const cellText = cell.textContent?.trim() || '';
            rowData.push(cellText);
          }
        });
        if (rowData.length > 0) {
          rows.push(rowData);
        }
      });
    }
  });

  // Create CSV content
  const csvContent = [
    headers.map(h => `"${h.replace(/"/g, '""')}"`).join(','),
    ...rows.map(row => 
      row.map(cell => {
        if (typeof cell === 'number') {
          return cell;
        }
        return `"${String(cell).replace(/"/g, '""')}"`;
      }).join(',')
    ),
  ].join('\n');

  // Download CSV
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.setAttribute('href', url);
  link.setAttribute('download', `${fileName}.csv`);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

/**
 * Export displayed table data (as shown on screen) to Excel format
 * Uses xlsx library to preserve formatting
 * Handles both single-table and virtualized multi-table layouts
 */
export function exportTableAsExcel(
  tableSelector: string,
  fileName: string,
) {
  const container = document.querySelector(tableSelector);
  if (!container) {
    console.warn(`Table not found with selector: ${tableSelector}`);
    return;
  }

  // Extract headers from the first table or from thead
  const headers: string[] = [];
  let headerCells = container.querySelectorAll('thead th, .ant-table-thead th');

  // If no thead found, try first table's th elements
  if (headerCells.length === 0) {
    const tables = container.querySelectorAll('table');
    if (tables.length > 0) {
      headerCells = tables[0].querySelectorAll('th');
    }
  }

  headerCells.forEach((cell) => {
    const span = cell.querySelector('span');
    const headerText = span?.textContent?.trim() || cell.textContent?.trim() || '';
    headers.push(headerText);
  });

  // Extract rows from all tbody elements
  const rows: string[][] = [];
  const allTables = container.querySelectorAll('table');

  allTables.forEach((table) => {
    const tbody = table.querySelector('tbody');
    if (tbody) {
      const bodyRows = tbody.querySelectorAll('tr');
      bodyRows.forEach((row) => {
        const rowData: string[] = [];
        const cells = row.querySelectorAll('td');
        cells.forEach((cell, cellIndex) => {
          if (cellIndex === 0) {
            // Check if cell has expand/collapse icon - if so, skip padding
            const hasExpandCollapseIcon = cell.querySelector('span[aria-label="minus-square"], span[aria-label="plus-square"]');
            
            let numSpaces = 0;
            if (!hasExpandCollapseIcon) {
              // Get padding-left from computed style (applied via CSS class)
              const cellElement = cell as HTMLElement;
              const computedStyle = window.getComputedStyle(cellElement);
              const paddingLeft = parseInt(computedStyle.paddingLeft || '0', 10);
              
              // Get default padding from a non-first column cell (no !important override)
              const secondCell = cells[1] as HTMLElement | undefined;
              const defaultPadding = secondCell 
                ? parseInt(window.getComputedStyle(secondCell).paddingLeft || '0', 10)
                : 0;
              
              // Only use the additional padding (the !important override)
              const additionalPadding = paddingLeft - defaultPadding;
              // Convert pixels to spaces (roughly 10px per space for readability)
              numSpaces = additionalPadding > 0 ? Math.round(additionalPadding / 10) : 0;
            }

            // Get text content, excluding SVG icon content
            let cellText = '';
            const walker = document.createTreeWalker(
              cell,
              NodeFilter.SHOW_TEXT,
              null,
            );
            let node: Node | null;
            while ((node = walker.nextNode())) {
              let parent = node.parentElement;
              let isInsideSvg = false;
              while (parent && parent !== cell) {
                if (parent.tagName === 'svg' || parent.tagName === 'SVG') {
                  isInsideSvg = true;
                  break;
                }
                parent = parent.parentElement;
              }
              if (!isInsideSvg) {
                cellText += node.textContent || '';
              }
            }
            cellText = cellText.trim();

            // Add spaces prefix based on padding
            const indent = ' '.repeat(numSpaces);
            rowData.push(indent + cellText);
          } else {
            const cellText = cell.textContent?.trim() || '';
            rowData.push(cellText);
          }
        });
        if (rowData.length > 0) {
          rows.push(rowData);
        }
      });
    }
  });

  // Build worksheet from extracted data
  const wsData = [headers, ...rows];
  const worksheet = utils.aoa_to_sheet(wsData);
  const workbook = utils.book_new();
  utils.book_append_sheet(workbook, worksheet, 'Sheet1');
  writeFile(workbook, `${fileName}.xlsx`);
}