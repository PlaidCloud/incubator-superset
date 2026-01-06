/*
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

/**
 * Type extensions for TanStack Table v8
 */
import {
  ColumnDef,
  Header,
  Cell,
  Row,
} from '@tanstack/react-table';
import { DragEvent, CSSProperties } from 'react';

/**
 * Extended column definition for custom metadata and rendering props
 */
declare module '@tanstack/react-table' {
  interface ColumnMeta {
    sortDescFirst?: boolean;
    sortType?: 'datetime' | 'alphanumeric' | 'basic';
  }

  interface HeaderContext<TData, TValue> {
    onDragStart?: (e: DragEvent) => void;
    onDrop?: (e: DragEvent) => void;
    style?: CSSProperties;
  }

  interface CellContext<TData, TValue> {
    style?: CSSProperties;
  }
}

export {};
