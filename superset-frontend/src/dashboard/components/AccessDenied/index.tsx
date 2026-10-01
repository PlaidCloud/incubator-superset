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
import { useEffect, useState } from 'react';
import { SupersetClient } from '@superset-ui/core';
import { t } from '@apache-superset/core/translation';
import { styled } from '@apache-superset/core/theme';
import { Button, EmptyState, Input } from '@superset-ui/core/components';

export const MAX_NOTE_LENGTH = 500;

type Props = { idOrSlug: string | number };
type Context = { title?: string; owners?: string[] };

const Form = styled.div`
  ${({ theme }) => `
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: ${theme.sizeUnit * 3}px;
    width: min(100%, ${theme.sizeUnit * 90}px);
    color: ${theme.colorText};
  `}
`;

const ErrorText = styled.span`
  color: ${({ theme }) => theme.colorError};
`;

const Heading = styled.span`
  ${({ theme }) => `
    color: ${theme.colorText};
    font-weight: ${theme.fontWeightStrong};
  `}
`;

/**
 * Shown on PlaidCloud for any dashboard that can't be opened. The generic page is
 * the same for a dashboard that doesn't exist, a Draft and a restricted one. PlaidCloud
 * returns a title and owners only to eligible project members. The request itself is
 * only made when the user clicks.
 */
export default function AccessDenied({ idOrSlug }: Props) {
  const [note, setNote] = useState('');
  const [context, setContext] = useState<Context>({});
  const [status, setStatus] = useState<'idle' | 'sending' | 'sent' | 'failed'>(
    'idle',
  );
  const dashboardId = /^\d+$/.test(String(idOrSlug))
    ? Number(idOrSlug)
    : String(idOrSlug);

  useEffect(() => {
    let cancelled = false;
    SupersetClient.post({
      endpoint: '/api/v1/dashboard/access_context',
      jsonPayload: { dashboard_id: dashboardId },
    })
      .then(({ json }) => {
        if (!cancelled) setContext(json?.result ?? {});
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [dashboardId]);

  const requestAccess = () => {
    setStatus('sending');
    SupersetClient.post({
      endpoint: '/api/v1/dashboard/access_request',
      jsonPayload: { dashboard_id: dashboardId, note },
    })
      .then(() => setStatus('sent'))
      .catch(() => setStatus('failed'));
  };

  const detailed = Boolean(context.title);
  const owners = context.owners ?? [];

  return (
    <EmptyState
      size="large"
      title={
        <Heading>
          {detailed
            ? t("You don't have access to %s.", context.title)
            : t("This dashboard doesn't exist or you don't have access.")}
        </Heading>
      }
      description={
        status === 'sent'
          ? t('Your request was sent')
          : (detailed && owners.length > 0 && (
              <>{t('Owners: %s', owners.join(', '))}</>
            )) ||
            t('If you think you should have access, you can ask its owners.')
      }
    >
      <Form>
        {status !== 'sent' && (
          <>
            <Input.TextArea
              aria-label={t('Note to the owners (optional)')}
              placeholder={t('Note to the owners (optional)')}
              maxLength={MAX_NOTE_LENGTH}
              rows={3}
              value={note}
              onChange={e => setNote(e.target.value)}
            />
            {status === 'failed' && (
              <ErrorText role="alert">
                {t("Your request couldn't be sent. Please try again.")}
              </ErrorText>
            )}
            <Button
              buttonStyle="primary"
              loading={status === 'sending'}
              onClick={requestAccess}
            >
              {t('Request access')}
            </Button>
          </>
        )}
        <a href="/dashboard/list/">{t('Back to Dashboards')}</a>
      </Form>
    </EmptyState>
  );
}
