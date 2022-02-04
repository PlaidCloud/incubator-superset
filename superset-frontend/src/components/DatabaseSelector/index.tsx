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
import React, { ReactNode, useState, useMemo, useEffect } from 'react';
import { styled, SupersetClient, t } from '@superset-ui/core';
import rison from 'rison';
import { Select } from 'src/components';
import Label from 'src/components/Label';
import { FormLabel } from 'src/components/Form';
import RefreshLabel from 'src/components/RefreshLabel';
import { useToasts } from 'src/components/MessageToasts/withToasts';
import SupersetAsyncSelect from 'src/components/AsyncSelect';

const DatabaseSelectorWrapper = styled.div`
  ${({ theme }) => `
    .refresh {
      display: flex;
      align-items: center;
      width: 30px;
      margin-left: ${theme.gridUnit}px;
      margin-top: ${theme.gridUnit * 5}px;
    }

    .section {
      display: flex;
      flex-direction: row;
      align-items: center;
    }

    .select {
      width: calc(100% - 30px - ${theme.gridUnit}px);
      flex: 1;
    }

    & > div {
      margin-bottom: ${theme.gridUnit * 4}px;
    }
  `}
`;

const LabelStyle = styled.div`
  display: flex;
  flex-direction: row;
  align-items: center;
  margin-left: ${({ theme }) => theme.gridUnit - 2}px;

  .backend {
    overflow: visible;
  }

  .name {
    overflow: hidden;
    text-overflow: ellipsis;
  }
`;

type DatabaseValue = {
  label: React.ReactNode;
  value: number;
  id: number;
  database_name: string;
  backend: string;
  allow_multi_schema_metadata_fetch: boolean;
};

export type DatabaseObject = {
  id: number;
  database_name: string;
  backend: string;
  allow_multi_schema_metadata_fetch: boolean;
};

type SchemaValue = { label: string; value: string };

const DatabaseOption = styled.span`
  display: inline-flex;
  align-items: center;
`;

interface DatabaseSelectorProps {
  db?: DatabaseObject;
  formMode?: boolean;
  getDbList?: (arg0: any) => {};
  handleError: (msg: string) => void;
  isDatabaseSelectEnabled?: boolean;
  onDbChange?: (db: DatabaseObject) => void;
  onSchemaChange?: (schema?: string) => void;
  onSchemasLoad?: (schemas: Array<object>) => void;
  readOnly?: boolean;
  schema?: string;
  sqlLabMode?: boolean;
}

const SelectLabel = ({
  backend,
  databaseName,
}: {
  backend: string;
  databaseName: string;
}) => (
  <LabelStyle>
    <Label className="backend">{backend}</Label>
    <span className="name" title={databaseName}>
      {databaseName}
    </span>
  </LabelStyle>
);

export default function DatabaseSelector({
  db,
  formMode = false,
  getDbList,
  handleError,
  isDatabaseSelectEnabled = true,
  onDbChange,
  onSchemaChange,
  onSchemasLoad,
  readOnly = false,
  schema,
  sqlLabMode = false,
}: DatabaseSelectorProps) {
  const [loadingSchemas, setLoadingSchemas] = useState(false);
  const [schemaOptions, setSchemaOptions] = useState<SchemaValue[]>([]);
  const [currentDb, setCurrentDb] = useState<DatabaseValue | undefined>(
    db
      ? {
          label: (
            <SelectLabel backend={db.backend} databaseName={db.database_name} />
          ),
          value: db.id,
          ...db,
        }
      : undefined,
  );
  const [currentSchema, setCurrentSchema] = useState<SchemaValue | undefined>(
    schema ? { label: schema, value: schema } : undefined,
  );
  const [refresh, setRefresh] = useState(0);
  const { addSuccessToast } = useToasts();
  /*
  const loadDatabases = useMemo(
    () =>
      async (
        search: string,
        page: number,
        pageSize: number,
      ): Promise<{
        data: DatabaseValue[];
        totalCount: number;
      }> => {
        const queryParams = rison.encode({
          order_columns: 'database_name',
          order_direction: 'asc',
          page,
          page_size: pageSize,
          ...(formMode || !sqlLabMode
            ? { filters: [{ col: 'database_name', opr: 'ct', value: search }] }
            : {
                filters: [
                  { col: 'database_name', opr: 'ct', value: search },
                  {
                    col: 'expose_in_sqllab',
                    opr: 'eq',
                    value: true,
                  },
                ],
              }),
        });
        const endpoint = `/api/v1/database/?q=${queryParams}`;
        return SupersetClient.get({ endpoint }).then(({ json }) => {
          const { result } = json;
          if (getDbList) {
            getDbList(result);
          }
          if (result.length === 0) {
            handleError(t("It seems you don't have access to any database"));
          }
          const options = result.map((row: DatabaseObject) => ({
            label: (
              <SelectLabel
                backend={row.backend}
                databaseName={row.database_name}
              />
            ),
            value: row.id,
            id: row.id,
            database_name: row.database_name,
            backend: row.backend,
            allow_multi_schema_metadata_fetch:
              row.allow_multi_schema_metadata_fetch,
          }));
          return {
            data: options,
            totalCount: options.length,
          };
        });
      },
    [formMode, getDbList, handleError, sqlLabMode],
  );
  */

  useEffect(() => {
    if (currentDb) {
      setLoadingSchemas(true);
      const queryParams = rison.encode({ force: refresh > 0 });
      const endpoint = `/api/v1/database/${currentDb.value}/schemas/?q=${queryParams}`;

      // TODO: Would be nice to add pagination in a follow-up. Needs endpoint changes.
      SupersetClient.get({ endpoint })
        .then(({ json }) => {
          const options = json.result.map((s: string) => ({
            value: s,
            label: s,
            title: s,
          }));
          if (onSchemasLoad) {
            onSchemasLoad(options);
          }
          setSchemaOptions(options);
          setLoadingSchemas(false);
          if (refresh > 0) addSuccessToast('List refreshed');
        })
        .catch(() => {
          setLoadingSchemas(false);
          handleError(t('There was an error loading the schemas'));
        });
    }
  }, [currentDb, onSchemasLoad, refresh]);

  function dbMutator(data: any) {
    if (getDbList) {
      getDbList(data.result);
    }
    if (data.result.length === 0) {
      handleError(t("It seems you don't have access to any database"));
    }
    return data.result.map((row: DatabaseObject) => ({
      ...row,
      // label is used for the typeahead
      // ADT2022: I think row should maybe actually be a database value?
      // Actually, maybe this should match the other place where we map across a list of DatabaseObjects
      label: `${row.backend} ${row.database_name}`,
    }));
  }

  function changeDataBase(
    value: { label: string; value: number },
    database: DatabaseValue,
  ) {
    setCurrentDb(database);
    setCurrentSchema(undefined);
    if (onDbChange) {
      onDbChange(database);
    }
    if (onSchemaChange) {
      onSchemaChange(undefined);
    }
  }

  function changeSchema(schema: SchemaValue) {
    setCurrentSchema(schema);
    if (onSchemaChange) {
      onSchemaChange(schema.value);
    }
  }

  function renderDatabaseOption(db: DatabaseValue) {
    return (
      <DatabaseOption title={db.database_name}>
        <Label type="default">{db.backend}</Label> {db.database_name}
      </DatabaseOption>
    );
  }

  function renderSelectRow(select: ReactNode, refreshBtn: ReactNode) {
    return (
      <div className="section">
        <span className="select">{select}</span>
        <span className="refresh">{refreshBtn}</span>
      </div>
    );
  }

  function renderDatabaseSelect() {
    const queryParams = rison.encode({
      order_columns: 'database_name',
      order_direction: 'asc',
      page: 0,
      page_size: -1,
      ...(formMode || !sqlLabMode
        ? {}
        : {
            filters: [
              {
                col: 'expose_in_sqllab',
                opr: 'eq',
                value: true,
              },
            ],
          }),
    });

    return renderSelectRow(
      <SupersetAsyncSelect
        ariaLabel={t('Select database or type database name')}
        optionFilterProps={['database_name', 'value']}
        data-test="select-database"
        dataEndpoint={`/api/v1/database/?q=${queryParams}`}
        onChange={changeDataBase}
        onAsyncError={() =>
          handleError(t('Error while fetching database list'))
        }
        clearable={false}
        value={currentDb}
        valueKey="id"
        valueRenderer={(db: DatabaseValue) => (
          <div>
            <span className="text-muted m-r-5">{t('Project:')}</span>
            {renderDatabaseOption(db)}
          </div>
        )}
        optionRenderer={renderDatabaseOption}
        mutator={dbMutator}
        header={<FormLabel>{t('Database')}</FormLabel>}
        lazyLoading={false}
        placeholder={t('Select database or type database name')}
        disabled={!isDatabaseSelectEnabled || readOnly}
        // options={loadDatabases}
      />,
      null,
    );
  }

  function renderSchemaSelect() {
    const refreshIcon = !formMode && !readOnly && (
      <RefreshLabel
        onClick={() => setRefresh(refresh + 1)}
        tooltipContent={t('Force refresh schema list')}
      />
    );

    return renderSelectRow(
      <Select
        ariaLabel={t('Select schema or type schema name')}
        disabled={readOnly}
        header={<FormLabel>{t('Schema')}</FormLabel>}
        labelInValue
        lazyLoading={false}
        loading={loadingSchemas}
        name="select-schema"
        placeholder={t('Select schema or type schema name')}
        onChange={item => changeSchema(item as SchemaValue)}
        options={schemaOptions}
        showSearch
        value={currentSchema}
      />,
      refreshIcon,
    );
  }

  return (
    <DatabaseSelectorWrapper data-test="DatabaseSelector">
      {renderDatabaseSelect()}
      {renderSchemaSelect()}
    </DatabaseSelectorWrapper>
  );
}
