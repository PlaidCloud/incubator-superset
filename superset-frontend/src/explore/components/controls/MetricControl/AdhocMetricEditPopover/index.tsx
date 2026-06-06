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
/* eslint-disable camelcase */
import React, { PureComponent, createRef, type ChangeEvent } from 'react';
import { isDefined, ensureIsArray, DatasourceType } from '@superset-ui/core';
import { t } from '@apache-superset/core/translation';
import type { editors } from '@apache-superset/core';
import { styled } from '@apache-superset/core/theme';
import Tabs from '@superset-ui/core/components/Tabs';
import {
  Button,
  Checkbox,
  type CheckboxChangeEvent,
  EmptyState,
  Form,
  FormItem,
  Icons,
  Input,
  Select,
  Tooltip,
} from '@superset-ui/core/components';
import sqlKeywords from 'src/SqlLab/utils/sqlKeywords';
import { noOp } from 'src/utils/common';
import {
  AGGREGATES_OPTIONS,
  POPOVER_INITIAL_HEIGHT,
  POPOVER_INITIAL_WIDTH,
} from 'src/explore/constants';
import AdhocMetric, {
  EXPRESSION_TYPES,
} from 'src/explore/components/controls/MetricControl/AdhocMetric';
import {
  StyledMetricOption,
  StyledColumnOption,
} from 'src/explore/components/optionRenderers';
import { getColumnKeywords } from 'src/explore/controlUtils/getColumnKeywords';
import SQLEditorWithValidation from 'src/components/SQLEditorWithValidation';
import type { RefObject } from 'react';

interface ColumnType {
  column_name: string;
  verbose_name?: string;
  [key: string]: unknown;
}

interface SavedMetricType {
  metric_name: string;
  verbose_name?: string;
  expression?: string;
  [key: string]: unknown;
}

interface DatasourceInfo {
  type?: DatasourceType | string;
  id?: number | string;
  extra?: string;
  [key: string]: unknown;
}

interface ExtraConfig {
  disallow_adhoc_metrics?: boolean;
  [key: string]: unknown;
}

type Metric = AdhocMetric | SavedMetricType;

interface AdhocMetricEditPopoverProps {
  onChange: (newMetric: Metric, oldMetric?: Metric) => void;
  onClose: () => void;
  onResize: () => void;
  getCurrentTab?: (tab: string) => void;
  getCurrentLabel?: (labels: {
    savedMetricLabel?: string;
    adhocMetricLabel?: string;
  }) => void;
  handleDatasetModal?: (open: boolean) => void;
  adhocMetric: AdhocMetric;
  columns?: ColumnType[];
  savedMetricsOptions?: SavedMetricType[];
  savedMetric?: SavedMetricType;
  datasource?: DatasourceInfo;
  isNewMetric?: boolean;
  isLabelModified?: boolean;
  allowEmptyRowHeading?: boolean;
}

interface AdhocMetricEditPopoverState {
  adhocMetric: AdhocMetric;
  savedMetric?: SavedMetricType;
  width: number;
  height: number;
}

const defaultProps = {
  columns: [],
  getCurrentTab: noOp,
  isNewMetric: false,
};

const StyledSelect = styled(Select)`
  .metric-option {
    & > svg {
      min-width: ${({ theme }) => `${theme.sizeUnit * 4}px`};
    }
    & > .option-label {
      overflow: hidden;
      text-overflow: ellipsis;
    }
  }
`;

export const SAVED_TAB_KEY = 'SAVED';
export const HEADING_TAB_KEY = 'HEADING';

const StyledMetricTabs = styled(Tabs)`
  && .ant-tabs-nav-wrap {
    padding: 0;
  }

  && .ant-tabs-nav-list {
    display: flex;
    column-gap: ${({ theme }) => theme.sizeUnit * 8}px;
    justify-content: flex-start;
    width: 100%;
  }

  && .ant-tabs-tab {
    flex: 0 0 auto;
    margin: 0 !important;
    min-width: max-content;
  }

  && .ant-tabs-tab-btn {
    overflow: visible;
    text-overflow: clip;
    white-space: nowrap;
  }
`;

export default class AdhocMetricEditPopover extends PureComponent<
  AdhocMetricEditPopoverProps,
  AdhocMetricEditPopoverState
> {
  // "Saved" is a default tab unless there are no saved metrics for dataset
  defaultActiveTabKey = this.getDefaultTab();

  editorRef: RefObject<editors.EditorHandle>;

  dragStartX = 0;

  dragStartY = 0;

  dragStartWidth = 0;

  dragStartHeight = 0;

  constructor(props: AdhocMetricEditPopoverProps) {
    super(props);
    this.onSave = this.onSave.bind(this);
    this.onResetStateAndClose = this.onResetStateAndClose.bind(this);
    this.onColumnChange = this.onColumnChange.bind(this);
    this.onAggregateChange = this.onAggregateChange.bind(this);
    this.onSavedMetricChange = this.onSavedMetricChange.bind(this);
    this.onSqlExpressionChange = this.onSqlExpressionChange.bind(this);
    this.onHeadingChange = this.onHeadingChange.bind(this);
    this.onDragDown = this.onDragDown.bind(this);
    this.onMouseMove = this.onMouseMove.bind(this);
    this.onMouseUp = this.onMouseUp.bind(this);
    this.onTabChange = this.onTabChange.bind(this);
    this.editorRef = createRef();
    this.refreshEditor = this.refreshEditor.bind(this);
    this.getDefaultTab = this.getDefaultTab.bind(this);
    this.onEmptyRowChange = this.onEmptyRowChange.bind(this);

    this.state = {
      adhocMetric: this.props.adhocMetric,
      savedMetric: this.props.savedMetric,
      width: POPOVER_INITIAL_WIDTH,
      height: POPOVER_INITIAL_HEIGHT,
    };
    document.addEventListener('mouseup', this.onMouseUp);
  }

  componentDidMount() {
    this.props.getCurrentTab?.(this.defaultActiveTabKey);
  }

  componentDidUpdate(
    _prevProps: AdhocMetricEditPopoverProps,
    prevState: AdhocMetricEditPopoverState,
  ) {
    if (
      prevState.adhocMetric?.sqlExpression !==
      this.state.adhocMetric?.sqlExpression ||
      prevState.adhocMetric?.aggregate !== this.state.adhocMetric?.aggregate ||
      prevState.adhocMetric?.column?.column_name !==
      this.state.adhocMetric?.column?.column_name ||
      prevState.savedMetric?.metric_name !== this.state.savedMetric?.metric_name ||
      prevState.adhocMetric?.emptyRowHeading !==
        this.state.adhocMetric?.emptyRowHeading ||
      prevState.adhocMetric?.emptyRowHeadingText !==
        this.state.adhocMetric?.emptyRowHeadingText ||
      prevState.adhocMetric?.isEmpty !== this.state.adhocMetric?.isEmpty
    ) {
      this.props.getCurrentLabel?.({
        savedMetricLabel:
          this.state.savedMetric?.verbose_name ||
          this.state.savedMetric?.metric_name,
        adhocMetricLabel: this.state.adhocMetric?.getDefaultLabel(),
      });
    }
  }

  componentWillUnmount() {
    document.removeEventListener('mouseup', this.onMouseUp);
    document.removeEventListener('mousemove', this.onMouseMove);
  }

  getDefaultTab() {
    const { adhocMetric, savedMetric, savedMetricsOptions, isNewMetric } =
      this.props;

    if (
      this.props.allowEmptyRowHeading &&
      (adhocMetric.emptyRowHeading || adhocMetric.isEmpty)
    ) {
      return HEADING_TAB_KEY;
    }

    if (isDefined(adhocMetric.column) || isDefined(adhocMetric.sqlExpression)) {
      return adhocMetric.expressionType;
    }
    if (
      (isNewMetric || savedMetric?.metric_name) &&
      Array.isArray(savedMetricsOptions) &&
      savedMetricsOptions.length > 0
    ) {
      return SAVED_TAB_KEY;
    }
    return adhocMetric.expressionType;
  }

  onSave() {
    const { adhocMetric, savedMetric } = this.state;

    const metric = savedMetric?.metric_name ? savedMetric : adhocMetric;
    const oldMetric = this.props.savedMetric?.metric_name
      ? this.props.savedMetric
      : this.props.adhocMetric;
    this.props.onChange(
      {
        ...metric,
      } as Metric,
      oldMetric as Metric,
    );
    this.props.onClose();
  }

  onResetStateAndClose() {
    this.setState(
      {
        adhocMetric: this.props.adhocMetric,
        savedMetric: this.props.savedMetric,
      },
      this.props.onClose,
    );
  }

  onColumnChange(columnName: string): void {
    const column = this.props.columns?.find(
      column => column.column_name === columnName,
    );
    this.setState(prevState => ({
      adhocMetric: prevState.adhocMetric.duplicateWith({
        column,
        expressionType: EXPRESSION_TYPES.SIMPLE,
        emptyRowHeading: false,
        emptyRowHeadingText: '',
        isEmpty: false,
      }),
      savedMetric: undefined,
    }));
  }

  onAggregateChange(aggregate: string | null): void {
    // we construct this object explicitly to overwrite the value in the case aggregate is null
    this.setState(prevState => ({
      adhocMetric: prevState.adhocMetric.duplicateWith({
        aggregate,
        expressionType: EXPRESSION_TYPES.SIMPLE,
        emptyRowHeading: false,
        emptyRowHeadingText: '',
        isEmpty: false,
      }),
      savedMetric: undefined,
    }));
  }

  onSavedMetricChange(savedMetricName: string): void {
    const savedMetric = this.props.savedMetricsOptions?.find(
      metric => metric.metric_name === savedMetricName,
    );
    this.setState(prevState => ({
      savedMetric,
      adhocMetric: prevState.adhocMetric.duplicateWith({
        column: undefined,
        aggregate: undefined,
        sqlExpression: undefined,
        expressionType: EXPRESSION_TYPES.SIMPLE,
        emptyRowHeading: false,
        emptyRowHeadingText: '',
        isEmpty: false,
      }),
    }));
  }

  onSqlExpressionChange(sqlExpression: string): void {
    this.setState(prevState => ({
      adhocMetric: prevState.adhocMetric.duplicateWith({
        sqlExpression,
        expressionType: EXPRESSION_TYPES.SQL,
        emptyRowHeading: false,
        emptyRowHeadingText: '',
        isEmpty: false,
      }),
      savedMetric: undefined,
    }));
  }

  onHeadingChange(event: ChangeEvent<HTMLInputElement>) {
    this.setState(prevState => ({
      adhocMetric: prevState.adhocMetric.duplicateWith({
        emptyRowHeading: true,
        emptyRowHeadingText: event.target.value,
        isEmpty: false,
        column: undefined,
        aggregate: undefined,
        sqlExpression: undefined,
        expressionType: undefined,
      }),
      savedMetric: undefined,
    }));
  }

  onDragDown(e: React.MouseEvent): void {
    this.dragStartX = e.clientX;
    this.dragStartY = e.clientY;
    this.dragStartWidth = this.state.width;
    this.dragStartHeight = this.state.height;
    document.addEventListener('mousemove', this.onMouseMove);
  }

  onMouseMove(e: MouseEvent): void {
    this.props.onResize();
    this.setState({
      width: Math.max(
        this.dragStartWidth + (e.clientX - this.dragStartX),
        POPOVER_INITIAL_WIDTH,
      ),
      height: Math.max(
        this.dragStartHeight + (e.clientY - this.dragStartY),
        POPOVER_INITIAL_HEIGHT,
      ),
    });
  }

  onMouseUp(): void {
    document.removeEventListener('mousemove', this.onMouseMove);
  }

  onTabChange(tab: string): void {
    this.refreshEditor();
    this.props.getCurrentTab?.(tab);
  }

  refreshEditor(): void {
    setTimeout(() => {
      this.editorRef.current?.resize();
    }, 0);
  }

  renderColumnOption(option: ColumnType): React.ReactNode {
    const column = { ...option };
    if (
      (column as unknown as { metric_name?: string }).metric_name &&
      !column.verbose_name
    ) {
      column.verbose_name = (
        column as unknown as { metric_name: string }
      ).metric_name;
    }
    return <StyledColumnOption column={column} showType />;
  }

  renderMetricOption(savedMetric: SavedMetricType): React.ReactNode {
    return <StyledMetricOption metric={savedMetric} showType />;
  }

  onEmptyRowChange(event: CheckboxChangeEvent) {
    const isEmpty = event.target.checked;
    this.setState(prevState => ({
      adhocMetric: prevState.adhocMetric.duplicateWith({
        emptyRowHeading: isEmpty || !!prevState.adhocMetric.emptyRowHeadingText,
        isEmpty: isEmpty,
        emptyRowHeadingText: isEmpty ? '' : prevState.adhocMetric.emptyRowHeadingText,
        column: undefined,
        aggregate: undefined,
        sqlExpression: undefined,
        expressionType: undefined,
      }),
      savedMetric: undefined,
    }));
  }

  render() {
    const {
      adhocMetric: propsAdhocMetric,
      savedMetric: propsSavedMetric,
      columns,
      savedMetricsOptions,
      onChange,
      onClose,
      onResize,
      datasource,
      isNewMetric,
      isLabelModified,
      allowEmptyRowHeading,
      ...popoverProps
    } = this.props;
    const { adhocMetric, savedMetric } = this.state;
    const columnsArray = columns ?? [];
    const keywords = sqlKeywords.concat(
      getColumnKeywords(
        columnsArray as Parameters<typeof getColumnKeywords>[0],
      ),
    );

    const columnValue =
      (adhocMetric.column && adhocMetric.column.column_name) ||
      adhocMetric.inferSqlExpressionColumn();

    // autofocus on column if there's no value in column; otherwise autofocus on aggregate
    const columnSelectProps = {
      ariaLabel: t('Select column'),
      placeholder: t('%s column(s)', columnsArray.length),
      value: columnValue,
      onChange: this.onColumnChange,
      allowClear: true,
      autoFocus: !columnValue,
    };

    const aggregateSelectProps = {
      ariaLabel: t('Select aggregate options'),
      placeholder: t('%s aggregates(s)', AGGREGATES_OPTIONS.length),
      value:
        adhocMetric.aggregate ??
        adhocMetric.inferSqlExpressionAggregate() ??
        undefined,
      onChange: this.onAggregateChange as (value: unknown) => void,
      allowClear: true,
      autoFocus: !!columnValue,
    };

    const savedSelectProps = {
      ariaLabel: t('Select saved metrics'),
      placeholder: t('%s saved metric(s)', savedMetricsOptions?.length ?? 0),
      value: savedMetric?.metric_name,
      onChange: this.onSavedMetricChange,
      allowClear: true,
      autoFocus: true,
    };

    const stateIsValid = Boolean(
      adhocMetric.isValid() ||
        savedMetric?.metric_name ||
        (allowEmptyRowHeading &&
          adhocMetric.emptyRowHeading &&
          (adhocMetric.emptyRowHeadingText || adhocMetric.isEmpty)),
    );

    let adhocMetricContentChanged = !adhocMetric.equals(propsAdhocMetric);
    // If propsAdhocMetric exists and both are headings, explicitly check text change
    if (
      propsAdhocMetric &&
      (propsAdhocMetric.emptyRowHeading || propsAdhocMetric.isEmpty) &&
      (adhocMetric.emptyRowHeading || adhocMetric.isEmpty)
    ) {
      if (
        adhocMetric.emptyRowHeadingText !==
          propsAdhocMetric.emptyRowHeadingText ||
        adhocMetric.isEmpty !== propsAdhocMetric.isEmpty
      ) {
        adhocMetricContentChanged = true;
      }
    }

    const savedMetricContentChanged =
      (!(
        typeof savedMetric?.metric_name === 'undefined' &&
        typeof propsSavedMetric?.metric_name === 'undefined'
      ) &&
        savedMetric?.metric_name !== propsSavedMetric?.metric_name);

    const hasUnsavedChanges =
      isLabelModified ||
      isNewMetric ||
      adhocMetricContentChanged ||
      savedMetricContentChanged;

    let extra: ExtraConfig = {};
    if (datasource?.extra && typeof datasource.extra === 'string') {
      try {
        extra = JSON.parse(datasource.extra) as ExtraConfig;
      } catch {} // eslint-disable-line no-empty
    }

    const tabItems = [
      {
        key: SAVED_TAB_KEY,
        label: t('Saved'),
        children:
          ensureIsArray(savedMetricsOptions).length > 0 ? (
            <FormItem label={t('Saved metric')}>
              <StyledSelect
                options={ensureIsArray(savedMetricsOptions).map(savedMetric => ({
                  value: savedMetric.metric_name,
                  label: this.renderMetricOption(savedMetric),
                  key: savedMetric.id,
                  metric_name: savedMetric.metric_name,
                  verbose_name: savedMetric.verbose_name ?? '',
                }))}
                optionFilterProps={['metric_name', 'verbose_name']}
                {...savedSelectProps}
              />
            </FormItem>
          ) : datasource?.type === DatasourceType.Table ? (
            <EmptyState
              image="empty.svg"
              size="small"
              title={t('No saved metrics found')}
              description={t(
                'Add metrics to dataset in "Edit datasource" modal',
              )}
            />
          ) : (
            <EmptyState
              image="empty.svg"
              size="small"
              title={t('No saved metrics found')}
              description={
                <>
                  <span
                    tabIndex={0}
                    role="button"
                    onClick={() => {
                      this.props.handleDatasetModal?.(true);
                      this.props.onClose();
                    }}
                  >
                    {t('Create a dataset')}
                  </span>
                  {t(' to add metrics')}
                </>
              }
            />
          ),
      },
      {
        key: EXPRESSION_TYPES.SIMPLE,
        label: extra.disallow_adhoc_metrics ? (
          <Tooltip
            title={t('Simple ad-hoc metrics are not enabled for this dataset')}
          >
            {t('Simple')}
          </Tooltip>
        ) : (
          t('Simple')
        ),
        disabled: extra.disallow_adhoc_metrics,
        children: (
          <>
            <FormItem label={t('column')}>
              <Select
                options={columnsArray.map(column => ({
                  value: column.column_name,
                  key: (column as { id?: unknown }).id,
                  label: this.renderColumnOption(column),
                  column_name: column.column_name,
                  verbose_name: column.verbose_name ?? '',
                }))}
                optionFilterProps={['column_name', 'verbose_name']}
                {...columnSelectProps}
              />
            </FormItem>
            <FormItem label={t('aggregate')}>
              <Select
                options={AGGREGATES_OPTIONS.map(option => ({
                  value: option,
                  label: option,
                  key: option,
                }))}
                {...aggregateSelectProps}
              />
            </FormItem>
          </>
        ),
      },
      {
        key: EXPRESSION_TYPES.SQL,
        label: extra.disallow_adhoc_metrics ? (
          <Tooltip
            title={t('Custom SQL ad-hoc metrics are not enabled for this dataset')}
          >
            {t('Custom SQL')}
          </Tooltip>
        ) : (
          t('Custom SQL')
        ),
        disabled: extra.disallow_adhoc_metrics,
        children: (
          <SQLEditorWithValidation
            data-test="sql-editor"
            ref={this.editorRef}
            keywords={keywords}
            height={`${this.state.height - 120}px`}
            onChange={this.onSqlExpressionChange}
            width="100%"
            lineNumbers={false}
            value={
              adhocMetric.sqlExpression ||
              adhocMetric.translateToSql({ transformCountDistinct: true })
            }
            wordWrap
            showValidation
            expressionType="metric"
            datasourceId={datasource?.id}
            datasourceType={datasource?.type}
          />
        ),
      },
      ...(allowEmptyRowHeading
        ? [
            {
              key: HEADING_TAB_KEY,
              label: t('Row Heading'),
              children: (
                <div>
                  <FormItem label={t('Section Heading')}>
                    <Input
                      placeholder={t('Enter heading text')}
                      value={adhocMetric.emptyRowHeadingText || ''}
                      onChange={this.onHeadingChange}
                      autoFocus
                      data-test="heading-input"
                    />
                  </FormItem>
                  <FormItem>
                    <Checkbox
                      checked={adhocMetric.isEmpty || false}
                      onChange={this.onEmptyRowChange}
                      data-test="empty-row-checkbox"
                    >
                      {t('Empty row')}
                    </Checkbox>
                  </FormItem>
                </div>
              ),
            },
          ]
        : []),
    ];

    return (
      <Form
        layout="vertical"
        id="metrics-edit-popover"
        data-test="metrics-edit-popover"
        {...popoverProps}
      >
        <StyledMetricTabs
          id="adhoc-metric-edit-tabs"
          data-test="adhoc-metric-edit-tabs"
          defaultActiveKey={this.defaultActiveTabKey}
          className="adhoc-metric-edit-tabs"
          style={{ height: this.state.height, width: this.state.width }}
          onChange={this.onTabChange}
          allowOverflow
          items={tabItems}
        />
        <div>
          <Button
            buttonSize="small"
            buttonStyle="secondary"
            onClick={this.onResetStateAndClose}
            data-test="AdhocMetricEdit#cancel"
            cta
          >
            {t('Close')}
          </Button>
          <Button
            disabled={!stateIsValid || !hasUnsavedChanges}
            buttonStyle="primary"
            buttonSize="small"
            data-test="AdhocMetricEdit#save"
            onClick={this.onSave}
            cta
          >
            {t('Save')}
          </Button>
          <Icons.ArrowsAltOutlined
            role="button"
            aria-label={t('Resize')}
            tabIndex={0}
            onMouseDown={this.onDragDown}
            className="edit-popover-resize"
          />
        </div>
      </Form>
    );
  }
}
// @ts-expect-error - defaultProps for backward compatibility
AdhocMetricEditPopover.defaultProps = defaultProps;
